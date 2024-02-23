package socks5

import "net"

type FakeHyClient interface {
	TCP(addr string) (net.Conn, error)
	UDP() (FakeHyUDPConn, error)
	Close() error
}

type FakeHyUDPConn interface {
	Receive() (b []byte, addr string, err error)
	Send(b []byte, addr string) error
	Close() error
}

type Accepter interface {
	Accept() (net.Conn, error)
}
