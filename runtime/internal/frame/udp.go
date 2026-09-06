package frame

import (
	"context"
	"net"
)

// UDP receives syslog datagrams: one datagram is one frame, its bytes are the raw event exactly as
// received (framing method udp_datagram, no prefix or suffix stripped — a datagram has no delimiter).
// Bounded by construction: a datagram larger than MaxEventBytes is truncated by the socket read and
// flagged, never buffered. Stops when ctx is done or after MaxFrames (0 = unlimited).
type UDP struct {
	Addr          string
	MaxEventBytes int
	MaxFrames     int
}

func (u UDP) Listen() (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", u.Addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", addr)
}

// Serve reads datagrams from conn and calls emit for each until ctx is done or MaxFrames is reached.
func (u UDP) Serve(ctx context.Context, conn *net.UDPConn, emit func(Frame) error) error {
	max := u.MaxEventBytes
	if max <= 0 {
		max = 65536
	}
	buf := make([]byte, max+1)
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	n := 0
	for {
		got, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		status := "none"
		if got > max {
			got, status = max, "truncated"
		}
		raw := make([]byte, got)
		copy(raw, buf[:got])
		fr := Frame{Raw: raw, Framing: Framing{Method: "udp_datagram", RawPrefix: []byte{}, RawSuffix: []byte{}, FragmentCount: 1,
			OriginalMessageLength: got, TruncationStatus: status, FramingConfidence: "high"}}
		if from != nil {
			fr.Peer = from.String() // P7: continuity is kept per sender
		}
		if err := emit(fr); err != nil {
			return err
		}
		n++
		if u.MaxFrames > 0 && n >= u.MaxFrames {
			return nil
		}
	}
}
