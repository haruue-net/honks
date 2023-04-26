// SPDX-License-Identifier: MIT
/* (c) 2021 Toby
 * (c) 2022 Haruue Icymoon <i@haruue.moe>
 */

// most codes here is copied from hysteria project.
// https://github.com/HyNetwork/hysteria/blob/ab2ad4aa6d44785bb8a8caea1a22c9a8bb534a37/pkg/socks5/server.go
// modified by haruue to remove dependency of hysteria client.

package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"strconv"
)

import (
	"github.com/txthinking/socks5"
	"net"
	"time"
)

const udpBufferSize = 65535

var (
	ErrUnsupportedCmd = errors.New("unsupported command")
	ErrUserPassAuth   = errors.New("invalid username or password")
)

type Server struct {
	AuthFunc   func(username, password string) bool
	Method     byte
	TCPAddr    *net.TCPAddr
	TCPTimeout time.Duration
	DisableUDP bool

	TCPRequestFunc   func(addr net.Addr, reqAddr string)
	TCPErrorFunc     func(addr net.Addr, reqAddr string, err error)
	UDPAssociateFunc func(addr net.Addr)
	UDPErrorFunc     func(addr net.Addr, err error)

	tcpListener *net.TCPListener
}

func NewServer(addr string, authFunc func(username string, password string) bool, tcpTimeout time.Duration, disableUDP bool, tcpReqFunc func(addr net.Addr, reqAddr string), tcpErrorFunc func(addr net.Addr, reqAddr string, err error), udpAssocFunc func(addr net.Addr), udpErrorFunc func(addr net.Addr, err error)) (*Server, error) {
	tAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	m := socks5.MethodNone
	if authFunc != nil {
		m = socks5.MethodUsernamePassword
	}
	s := &Server{
		AuthFunc:         authFunc,
		Method:           m,
		TCPAddr:          tAddr,
		TCPTimeout:       tcpTimeout,
		DisableUDP:       disableUDP,
		TCPRequestFunc:   tcpReqFunc,
		TCPErrorFunc:     tcpErrorFunc,
		UDPAssociateFunc: udpAssocFunc,
		UDPErrorFunc:     udpErrorFunc,
	}
	return s, nil
}

func (s *Server) negotiate(c *net.TCPConn) error {
	rq, err := socks5.NewNegotiationRequestFrom(c)
	if err != nil {
		return err
	}
	var got bool
	var m byte
	for _, m = range rq.Methods {
		if m == s.Method {
			got = true
		}
	}
	if !got {
		rp := socks5.NewNegotiationReply(socks5.MethodUnsupportAll)
		if _, err := rp.WriteTo(c); err != nil {
			return err
		}
	}
	rp := socks5.NewNegotiationReply(s.Method)
	if _, err := rp.WriteTo(c); err != nil {
		return err
	}

	if s.Method == socks5.MethodUsernamePassword {
		urq, err := socks5.NewUserPassNegotiationRequestFrom(c)
		if err != nil {
			return err
		}
		if !s.AuthFunc(string(urq.Uname), string(urq.Passwd)) {
			urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
			if _, err := urp.WriteTo(c); err != nil {
				return err
			}
			return ErrUserPassAuth
		}
		urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
		if _, err := urp.WriteTo(c); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) ListenAndServe() error {
	var err error
	s.tcpListener, err = net.ListenTCP("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer s.tcpListener.Close()
	for {
		c, err := s.tcpListener.AcceptTCP()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if s.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(s.TCPTimeout)); err != nil {
					return
				}
			}
			if err := s.negotiate(c); err != nil {
				return
			}
			r, err := socks5.NewRequestFrom(c)
			if err != nil {
				return
			}
			_ = s.handle(c, r)
		}()
	}
}

func (s *Server) handle(c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		// TCP
		return s.handleTCP(c, r)
	} else if r.Cmd == socks5.CmdUDP {
		// UDP
		if !s.DisableUDP {
			return s.handleUDP(c, r)
		} else {
			_ = sendReply(c, socks5.RepCommandNotSupported)
			return ErrUnsupportedCmd
		}
	} else {
		_ = sendReply(c, socks5.RepCommandNotSupported)
		return ErrUnsupportedCmd
	}
}

func (s *Server) handleTCP(c *net.TCPConn, r *socks5.Request) error {
	host, port, addr := parseRequestAddress(r)
	var ipAddr *net.IPAddr
	var resErr error
	ipAddr, resErr = net.ResolveIPAddr("ip", host)
	s.TCPRequestFunc(c.RemoteAddr(), addr)
	var closeErr error
	defer func() {
		s.TCPErrorFunc(c.RemoteAddr(), addr, closeErr)
	}()

	if resErr != nil {
		_ = sendReply(c, socks5.RepHostUnreachable)
		closeErr = resErr
		return resErr
	}
	rc, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   ipAddr.IP,
		Port: int(port),
		Zone: ipAddr.Zone,
	})
	if err != nil {
		_ = sendReply(c, socks5.RepHostUnreachable)
		closeErr = err
		return err
	}
	defer rc.Close()
	_ = sendReply(c, socks5.RepSuccess)
	closeErr = pipePairWithTimeout(c, rc, s.TCPTimeout)
	return nil
}

func (s *Server) handleUDP(c *net.TCPConn, r *socks5.Request) error {
	s.UDPAssociateFunc(c.RemoteAddr())
	var closeErr error
	defer func() {
		s.UDPErrorFunc(c.RemoteAddr(), closeErr)
	}()
	// Start local UDP server
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   s.TCPAddr.IP,
		Zone: s.TCPAddr.Zone,
	})
	if err != nil {
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = err
		return err
	}
	defer udpConn.Close()
	// Local UDP relay conn for ACL Direct
	var localRelayConn *net.UDPConn
	localRelayConn, err = net.ListenUDP("udp", nil)
	if err != nil {
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = err
		return err
	}
	defer localRelayConn.Close()
	// Send UDP server addr to the client
	// Same IP as TCP but a different port
	tcpLocalAddr := c.LocalAddr().(*net.TCPAddr)
	var atyp byte
	var addr, port []byte
	if ip4 := tcpLocalAddr.IP.To4(); ip4 != nil {
		atyp = socks5.ATYPIPv4
		addr = ip4
	} else if ip6 := tcpLocalAddr.IP.To16(); ip6 != nil {
		atyp = socks5.ATYPIPv6
		addr = ip6
	} else {
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = errors.New("invalid local addr")
		return closeErr
	}
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(udpConn.LocalAddr().(*net.UDPAddr).Port))
	_, _ = socks5.NewReply(socks5.RepSuccess, atyp, addr, port).WriteTo(c)
	// Let UDP server do its job, we hold the TCP connection here
	go s.udpServer(udpConn, localRelayConn)
	if s.TCPTimeout != 0 {
		// Disable TCP timeout for UDP holder
		_ = c.SetDeadline(time.Time{})
	}
	buf := make([]byte, 1024)
	for {
		_, err := c.Read(buf)
		if err != nil {
			closeErr = err
			break
		}
	}
	// As the TCP connection closes, so does the UDP server & HyClient session
	return nil
}

func (s *Server) udpServer(clientConn *net.UDPConn, localRelayConn *net.UDPConn) {
	var clientAddr *net.UDPAddr
	buf := make([]byte, udpBufferSize)
	// Local to remote
	for {
		n, cAddr, err := clientConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || d.Frag != 0 {
			// Ignore bad packets
			continue
		}
		if clientAddr == nil {
			// Whoever sends the first valid packet is our client
			clientAddr = cAddr
			// Start remote to local
			go func() {
				buf := make([]byte, udpBufferSize)
				for {
					n, from, err := localRelayConn.ReadFrom(buf)
					if n > 0 {
						atyp, addr, port, err := socks5.ParseAddress(from.String())
						if err != nil {
							continue
						}
						d := socks5.NewDatagram(atyp, addr, port, buf[:n])
						_, _ = clientConn.WriteToUDP(d.Bytes(), clientAddr)
					}
					if err != nil {
						break
					}
				}
			}()
		} else if cAddr.String() != clientAddr.String() {
			// Not our client, bye
			continue
		}
		host, port, _ := parseDatagramRequestAddress(d)
		var ipAddr *net.IPAddr
		var resErr error
		ipAddr, resErr = net.ResolveIPAddr("ip", host)
		if resErr != nil {
			return
		}
		_, _ = localRelayConn.WriteToUDP(d.Data, &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: int(port),
			Zone: ipAddr.Zone,
		})
	}
}

func sendReply(conn *net.TCPConn, rep byte) error {
	p := socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	_, err := p.WriteTo(conn)
	return err
}

func parseRequestAddress(r *socks5.Request) (host string, port uint16, addr string) {
	p := binary.BigEndian.Uint16(r.DstPort)
	if r.Atyp == socks5.ATYPDomain {
		d := string(r.DstAddr[1:])
		return d, p, net.JoinHostPort(d, strconv.Itoa(int(p)))
	} else {
		ipStr := net.IP(r.DstAddr).String()
		return ipStr, p, net.JoinHostPort(ipStr, strconv.Itoa(int(p)))
	}
}

func parseDatagramRequestAddress(r *socks5.Datagram) (host string, port uint16, addr string) {
	p := binary.BigEndian.Uint16(r.DstPort)
	if r.Atyp == socks5.ATYPDomain {
		d := string(r.DstAddr[1:])
		return d, p, net.JoinHostPort(d, strconv.Itoa(int(p)))
	} else {
		ipStr := net.IP(r.DstAddr).String()
		return ipStr, p, net.JoinHostPort(ipStr, strconv.Itoa(int(p)))
	}
}

const kPipeBufferSize = 65535

func pipePairWithTimeout(conn net.Conn, stream io.ReadWriteCloser, timeout time.Duration) error {
	errChan := make(chan error, 2)
	// TCP to stream
	go func() {
		buf := make([]byte, kPipeBufferSize)
		for {
			if timeout != 0 {
				_ = conn.SetDeadline(time.Now().Add(timeout))
			}
			rn, err := conn.Read(buf)
			if rn > 0 {
				_, err := stream.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	// Stream to TCP
	go func() {
		buf := make([]byte, kPipeBufferSize)
		for {
			rn, err := stream.Read(buf)
			if rn > 0 {
				_, err := conn.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
				if timeout != 0 {
					_ = conn.SetDeadline(time.Now().Add(timeout))
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	return <-errChan
}
