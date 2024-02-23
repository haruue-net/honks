package main

import (
	"net"
)

type MultipleListener struct {
	closeChan chan struct{}
	connChan  chan net.Conn
	errChan   chan error
}

func NewMultipleListener() *MultipleListener {
	return &MultipleListener{
		closeChan: make(chan struct{}),
		connChan:  make(chan net.Conn),
		errChan:   make(chan error),
	}
}

func (l *MultipleListener) Add(listener net.Listener) {
	go func() {
		defer listener.Close()

		for {
			select {
			case <-l.closeChan:
				return
			default:
			}
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-l.closeChan:
					return
				case l.errChan <- err:
				}
				return
			}
			select {
			case <-l.closeChan:
			case l.connChan <- conn:
			}
		}
	}()
}

func (l *MultipleListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connChan:
		return conn, nil
	case err := <-l.errChan:
		return nil, err
	case <-l.closeChan:
		return nil, net.ErrClosed
	}
}

func (l *MultipleListener) Close() error {
	close(l.closeChan)
	return nil
}
