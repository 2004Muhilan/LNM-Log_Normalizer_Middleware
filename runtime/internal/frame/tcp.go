package frame

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TCP is the syslog-over-TCP listener (plan P7). Bounded by construction (invariant 7):
//   - at most MaxConns connections are served; a connection beyond that is accepted and closed at
//     once (counted in Refused) so the kernel backlog never grows unbounded either;
//   - per connection the only buffers are the framer's 64 KiB read buffer and one frame of at most
//     MaxEventBytes, so resident memory is ≤ MaxConns × (64 KiB + MaxEventBytes) whatever the peers do;
//   - a connection that sends nothing for IdleTimeout is closed; whatever partial frame it had is
//     emitted as a low-confidence frame (retained as evidence) and counted in PartialAtClose;
//   - a line or counted message longer than MaxEventBytes arrives as truncated/continuation pieces.
//
// Framing is "octet" (RFC 6587 octet counting with non-transparent fallback per frame) or "newline".
// Frames from every connection are delivered to emit one at a time, in arrival order per connection,
// each tagged with Peer = the remote address.
type TCP struct {
	Addr          string
	MaxEventBytes int
	MaxConns      int
	IdleTimeout   time.Duration
	Framing       string // octet | newline
	MaxFrames     int64  // stop after N frames in total (tests); 0 = until ctx is done
	Multiline     *Multiline
	// OnClose is called when a connection ends with a partial frame pending (peer, reason).
	OnClose func(peer, reason string)
	// ReusePort: scale-out — several processes on one address (SO_REUSEPORT); a connection stays with one process
	ReusePort bool

	Accepted       atomic.Int64
	Refused        atomic.Int64
	IdleClosed     atomic.Int64
	PartialAtClose atomic.Int64
	Frames         atomic.Int64
	Active         atomic.Int64
	PeakActive     atomic.Int64
}

func (t *TCP) Listen() (net.Listener, error) { return listenTCP(t.Addr, t.ReusePort) }

// idleReader applies the idle timeout before every read.
type idleReader struct {
	c net.Conn
	d time.Duration
}

func (r idleReader) Read(p []byte) (int, error) {
	if r.d > 0 {
		_ = r.c.SetReadDeadline(time.Now().Add(r.d))
	}
	return r.c.Read(p)
}

// Serve accepts connections until ctx is done (or MaxFrames is reached) and delivers frames to emit.
func (t *TCP) Serve(ctx context.Context, ln net.Listener, emit func(Frame) error) error {
	maxConns := t.MaxConns
	if maxConns <= 0 {
		maxConns = 256
	}
	maxBytes := t.MaxEventBytes
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var mu sync.Mutex // serialises emit across connections
	var wg sync.WaitGroup
	var emitErr error
	sem := make(chan struct{}, maxConns)
	deliver := func(peer string, fr Frame) error {
		mu.Lock()
		defer mu.Unlock()
		if emitErr != nil {
			return emitErr
		}
		fr.Peer = peer
		if err := emit(fr); err != nil {
			emitErr = err
			cancel()
			return err
		}
		if n := t.Frames.Add(1); t.MaxFrames > 0 && n >= t.MaxFrames {
			cancel()
		}
		return nil
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			break
		}
		select {
		case sem <- struct{}{}:
		default:
			t.Refused.Add(1)
			c.Close()
			continue
		}
		t.Accepted.Add(1)
		if a := t.Active.Add(1); a > t.PeakActive.Load() {
			t.PeakActive.Store(a)
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem; t.Active.Add(-1) }()
			defer c.Close()
			peer := c.RemoteAddr().String()
			var partial bool
			var lastErr error
			em := func(fr Frame) error {
				if fr.Framing.FramingConfidence == "low" && fr.Framing.RawSuffix != nil && len(fr.Framing.RawSuffix) == 0 && fr.Framing.Method != "multiline" {
					partial = true // a frame without its terminator: the connection ended mid-frame
				}
				return deliver(peer, fr)
			}
			var scanErr error
			r := idleReader{c: c, d: t.IdleTimeout}
			if t.Multiline != nil {
				j := t.Multiline.Joiner(em)
				scanErr = t.scan(r, maxBytes, j.Feed)
				if ferr := j.Flush(); ferr != nil && scanErr == nil {
					scanErr = ferr
				}
			} else {
				scanErr = t.scan(r, maxBytes, em)
			}
			lastErr = scanErr
			var ne net.Error
			if errors.As(lastErr, &ne) && ne.Timeout() {
				t.IdleClosed.Add(1)
			}
			if partial {
				t.PartialAtClose.Add(1)
				if t.OnClose != nil {
					reason := "closed by peer"
					if errors.As(lastErr, &ne) && ne.Timeout() {
						reason = "idle timeout"
					} else if lastErr != nil && lastErr != io.EOF {
						reason = lastErr.Error()
					}
					mu.Lock()
					t.OnClose(peer, reason)
					mu.Unlock()
				}
			}
		}(c)
	}
	ln.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return emitErr
}

func (t *TCP) scan(r io.Reader, maxBytes int, emit func(Frame) error) error {
	if t.Framing == "newline" {
		return Newline{MaxEventBytes: maxBytes}.Scan(r, emit)
	}
	return OctetCount{MaxEventBytes: maxBytes}.Scan(r, emit)
}
