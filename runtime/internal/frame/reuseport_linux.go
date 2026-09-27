//go:build linux

package frame

import (
	"context"
	"net"
	"syscall"
)

// Scale-out across processes (laptop branch, 2026-09-27): several runtimes open the SAME listening address with
// SO_REUSEPORT and the kernel spreads incoming connections (TCP, HTTP) and datagrams (UDP) over them by its default
// hash of the flow's source and destination address and port. One flow — a TCP connection, a UDP sender's source
// port — therefore always reaches the same process, so per-source state (drift, propagation, sequence gaps, source
// binding) stays in one place. No random or eBPF distribution: that would break per-sender ordering. The kernel hashes
// the FLOW, not the sender's address: a sender that opens a new connection (a reconnect, a new HTTP connection) may land
// on another process and starts there with fresh per-source state.
func listenConfig(reusePort bool) net.ListenConfig {
	if !reusePort {
		return net.ListenConfig{}
	}
	return net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
}

func listenTCP(addr string, reusePort bool) (net.Listener, error) {
	lc := listenConfig(reusePort)
	return lc.Listen(context.Background(), "tcp", addr)
}

func listenUDP(addr string, reusePort bool) (*net.UDPConn, error) {
	lc := listenConfig(reusePort)
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// soReusePort is SO_REUSEPORT on Linux (asm-generic/socket.h; the same value on amd64 and arm64). The frozen syscall
// package does not export it and golang.org/x/sys is not a dependency of this module.
const soReusePort = 0xf
