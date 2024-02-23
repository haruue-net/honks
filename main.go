package main

import (
	"fmt"
	"github.com/flynn/json5"
	"github.com/haruue-net/honks/socks5"
	"io"
	"net"
	"os"
)

const (
	udpPacketBufferSize = 65535
)

func showUsage(writer io.Writer) {
	fmt.Fprintf(writer, "Usage: %s config.json\n", os.Args[0])
}

var config Config

func main() {
	if len(os.Args) != 2 {
		showUsage(os.Stderr)
		os.Exit(22)
	}

	switch os.Args[1] {
	case "-h":
		fallthrough
	case "--help":
		showUsage(os.Stdout)
		os.Exit(0)
	default:
		configFilePath := os.Args[1]
		err := readConfig(configFilePath)
		if err != nil {
			logFatal("cannot parse config from %s: %s\n", configFilePath, err)
			os.Exit(1)
		}
	}

	if len(config.Listen) == 0 {
		logFatal("no listen address specified\n")
	}

	authFunc := config.Users.AuthFunc
	if !config.Users.AuthEnabled() {
		authFunc = nil
	}

	mlis := NewMultipleListener()
	defer mlis.Close()
	for _, listenAddr := range config.Listen {
		logInfo("listen on %s\n", listenAddr)
		lis, err := net.Listen("tcp", listenAddr)
		if err != nil {
			logFatal("cannot listen on %s: %s\n", listenAddr, err)
		}
		mlis.Add(lis)
	}

	server := socks5.Server{
		HyClient:    localOutbound{},
		AuthFunc:    authFunc,
		DisableUDP:  config.DisableUDP,
		EventLogger: eventLogger{},
	}

	logFatal("server exit: %v\n", server.Serve(mlis))
}

func readConfig(path string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	err = json5.NewDecoder(file).Decode(&config)
	if err != nil {
		return
	}

	return
}

type eventLogger struct{}

func (eventLogger) TCPRequest(addr net.Addr, reqAddr string) {
	logVerbose("tcp request: %s => %s\n", addr, reqAddr)
}

func (eventLogger) TCPError(addr net.Addr, reqAddr string, err error) {
	if err != nil {
		logVerbose("tcp error: %s => %s: %s\n", addr, reqAddr, err)
	}
	logVerbose("tcp done: %s => %s\n", addr, reqAddr)
}

func (eventLogger) UDPRequest(addr net.Addr) {
	logVerbose("udp request from %s\n", addr)
}

func (eventLogger) UDPError(addr net.Addr, err error) {
	if err != nil {
		logVerbose("udp error from %s: %s\n", addr, err)
	}
	logVerbose("udp done from %s\n", addr)
}

type localOutbound struct{}

func (localOutbound) TCP(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (localOutbound) UDP() (socks5.FakeHyUDPConn, error) {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &localUDPConn{UDPConn: udpConn}, nil
}

func (localOutbound) Close() error {
	return nil
}

type localUDPConn struct {
	*net.UDPConn
}

func (c *localUDPConn) Receive() (b []byte, addr string, err error) {
	bs := make([]byte, udpPacketBufferSize)
	n, udpAddr, err := c.UDPConn.ReadFromUDP(bs)
	if err != nil {
		return
	}
	addr = udpAddr.String()
	b = make([]byte, n)
	copy(b, bs[:n])
	return
}

func (c *localUDPConn) Send(b []byte, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	_, err = c.UDPConn.WriteToUDP(b, udpAddr)
	return err
}
