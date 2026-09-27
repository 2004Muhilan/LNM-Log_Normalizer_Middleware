//go:build !linux

package frame

import (
	"errors"
	"net"
)

var errNoReusePort = errors.New("SO_REUSEPORT scale-out is supported on Linux only (the runtime container)")

func listenTCP(addr string, reusePort bool) (net.Listener, error) {
	if reusePort {
		return nil, errNoReusePort
	}
	return net.Listen("tcp", addr)
}

func listenUDP(addr string, reusePort bool) (*net.UDPConn, error) {
	if reusePort {
		return nil, errNoReusePort
	}
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", a)
}
