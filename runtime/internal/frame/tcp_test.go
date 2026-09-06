package frame

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Load sizes come from the environment so scripts/p7-check.sh can size them to the machine it runs on
// (the demo laptop: 12 threads, ~6 GB free under a 7.7 GB WSL cap) and say so; the defaults keep the
// ordinary suite quick.
func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func heapInuse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func startTCP(t *testing.T, tc *TCP, emit func(Frame) error) (net.Listener, context.CancelFunc, *sync.WaitGroup) {
	t.Helper()
	ln, err := tc.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = tc.Serve(ctx, ln, emit) }()
	return ln, cancel, &wg
}

// Invariant 7, connection flood: many more connections than MaxConns arrive at once. At most MaxConns
// are served; the rest are accepted and closed (counted, not queued); the heap stays under a bound
// that is MaxConns × (64 KiB + MaxEventBytes) plus slack, whatever the peers do.
func TestTCPConnectionFloodHoldsMemoryCap(t *testing.T) {
	conns := envInt("ULPF_LOAD_CONNS", 600)
	maxConns := 64
	maxEvent := 64 << 10
	var mu sync.Mutex
	frames := 0
	tc := &TCP{Addr: "127.0.0.1:0", MaxEventBytes: maxEvent, MaxConns: maxConns, IdleTimeout: 300 * time.Millisecond, Framing: "newline"}
	ln, cancel, wg := startTCP(t, tc, func(Frame) error { mu.Lock(); frames++; mu.Unlock(); return nil })
	before := heapInuse()
	var cs []net.Conn
	var cmu sync.Mutex
	var dial sync.WaitGroup
	for i := 0; i < conns; i++ {
		dial.Add(1)
		go func(i int) {
			defer dial.Done()
			c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				return
			}
			// half a line, then hold the connection open: the server must not wait forever nor buffer more
			fmt.Fprintf(c, "<13>Jan  5 04:05:06 h app: flood %d partial", i)
			cmu.Lock()
			cs = append(cs, c)
			cmu.Unlock()
		}(i)
	}
	dial.Wait()
	time.Sleep(150 * time.Millisecond)
	peak := heapInuse()
	if tc.PeakActive.Load() > int64(maxConns) {
		t.Fatalf("more than MaxConns served at once: %d", tc.PeakActive.Load())
	}
	bound := uint64(maxConns)*uint64(64<<10+maxEvent) + 24<<20
	if peak-before > bound {
		t.Fatalf("heap grew by %d MiB under a flood of %d connections; bound %d MiB", (peak-before)>>20, conns, bound>>20)
	}
	// idle timeout closes what was served; their partial lines are retained as low-confidence frames
	time.Sleep(600 * time.Millisecond)
	cancel()
	wg.Wait()
	for _, c := range cs {
		c.Close()
	}
	if tc.Accepted.Load()+tc.Refused.Load() < int64(conns)*9/10 {
		t.Fatalf("accounting: accepted %d refused %d of %d", tc.Accepted.Load(), tc.Refused.Load(), conns)
	}
	if tc.Refused.Load() == 0 {
		t.Fatalf("a flood of %d connections against MaxConns=%d must refuse some", conns, maxConns)
	}
	if tc.PartialAtClose.Load() == 0 || frames == 0 {
		t.Fatalf("partial lines must be retained: partial_at_close=%d frames=%d", tc.PartialAtClose.Load(), frames)
	}
	t.Logf("flood: conns=%d accepted=%d refused=%d peak_active=%d idle_closed=%d partial_retained=%d heap_growth=%d MiB (bound %d MiB)",
		conns, tc.Accepted.Load(), tc.Refused.Load(), tc.PeakActive.Load(), tc.IdleClosed.Load(), tc.PartialAtClose.Load(), (peak-before)>>20, bound>>20)
}

// Invariant 7, oversized message: a single counted message and a single line far larger than
// MaxEventBytes arrive as bounded truncated/continuation pieces; every byte is retained (a streaming
// hash of prefix+raw+suffix over the pieces equals the hash of what was sent) and the server's heap
// growth is bounded by the frame cap, not by the message size — the test keeps no piece, so what it
// measures is the framer's own buffering.
func TestTCPOversizedMessageIsBoundedAndRetained(t *testing.T) {
	mb := envInt("ULPF_LOAD_MB", 4)
	maxEvent := 64 << 10
	big := bytes.Repeat([]byte("y"), mb<<20)
	for _, mode := range []string{"octet", "newline"} {
		var in []byte
		if mode == "octet" {
			in = append([]byte(strconv.Itoa(len(big))+" "), big...)
		} else {
			in = append(append([]byte{}, big...), '\n')
		}
		want := sha256.Sum256(in)
		var mu sync.Mutex
		h := sha256.New()
		pieces, flagged, over := 0, 0, 0
		first := ""
		tc := &TCP{Addr: "127.0.0.1:0", MaxEventBytes: maxEvent, MaxConns: 4, IdleTimeout: 2 * time.Second, Framing: mode}
		ln, cancel, wg := startTCP(t, tc, func(fr Frame) error {
			mu.Lock()
			defer mu.Unlock()
			h.Write(fr.Framing.RawPrefix)
			h.Write(fr.Raw)
			h.Write(fr.Framing.RawSuffix)
			if pieces == 0 {
				first = fr.Framing.TruncationStatus
			}
			pieces++
			if fr.Framing.TruncationStatus != "none" {
				flagged++
			}
			if len(fr.Raw) > maxEvent {
				over++
			}
			return nil
		})
		before := heapInuse()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { c.Write(in); c.Close(); close(done) }()
		peak := before
		deadline := time.Now().Add(30 * time.Second)
		for {
			mu.Lock()
			n := pieces
			mu.Unlock()
			if p := heapInuse(); p > peak {
				peak = p
			}
			if n >= (mb<<20)/maxEvent || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		<-done
		time.Sleep(100 * time.Millisecond)
		cancel()
		wg.Wait()
		mu.Lock()
		got := h.Sum(nil)
		np, nf, no, f0 := pieces, flagged, over, first
		mu.Unlock()
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("%s: the pieces do not rebuild the message (%d pieces)", mode, np)
		}
		if f0 != "truncated" || nf != np || no != 0 {
			t.Fatalf("%s: pieces must all be flagged and within the cap: first=%s flagged=%d/%d over=%d", mode, f0, nf, np, no)
		}
		growth := uint64(0)
		if peak > before {
			growth = peak - before
		}
		if growth > 16<<20 {
			t.Fatalf("%s: heap grew by %d MiB while framing a %d MiB message — the framer buffered more than the cap", mode, growth>>20, mb)
		}
		t.Logf("%s: %d MiB message -> %d bounded pieces (cap %d KiB), peak heap growth %d MiB", mode, mb, np, maxEvent>>10, growth>>20)
	}
}

// Invariant 7, idle connections: peers that go quiet mid-line are closed at the idle timeout; their
// partial frames are retained (low confidence) and OnClose is told, once per connection.
func TestTCPIdleConnectionsAreClosedAndPartialsRetained(t *testing.T) {
	n := envInt("ULPF_LOAD_IDLE", 50)
	var mu sync.Mutex
	var got []Frame
	var closed []string
	tc := &TCP{Addr: "127.0.0.1:0", MaxEventBytes: 4096, MaxConns: n + 8, IdleTimeout: 200 * time.Millisecond, Framing: "octet",
		OnClose: func(peer, reason string) { closed = append(closed, peer+" "+reason) }}
	ln, cancel, wg := startTCP(t, tc, func(fr Frame) error { mu.Lock(); got = append(got, fr); mu.Unlock(); return nil })
	var cs []net.Conn
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "40 <13>Jan  5 04:05:06 h app: idle %03d", i) // declares 40 bytes, sends fewer
		cs = append(cs, c)
	}
	time.Sleep(900 * time.Millisecond)
	cancel()
	wg.Wait()
	for _, c := range cs {
		c.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if tc.IdleClosed.Load() != int64(n) || tc.PartialAtClose.Load() != int64(n) || len(closed) != n {
		t.Fatalf("idle: closed=%d partial=%d onclose=%d of %d", tc.IdleClosed.Load(), tc.PartialAtClose.Load(), len(closed), n)
	}
	if len(got) != n {
		t.Fatalf("every partial must be a frame: %d", len(got))
	}
	for _, f := range got {
		if f.Framing.FramingConfidence != "low" || f.Framing.TruncationStatus != "truncated" || !strings.HasPrefix(string(f.Raw), "<13>Jan") {
			t.Fatalf("partial frame: %+v", f)
		}
	}
	if !strings.HasSuffix(closed[0], "idle timeout") {
		t.Fatalf("reason: %s", closed[0])
	}
}

// Ordinary traffic over TCP: octet-counted and newline frames from several connections all arrive,
// each tagged with its peer, none interleaved within a frame.
func TestTCPFramesCarryPeer(t *testing.T) {
	var mu sync.Mutex
	var got []Frame
	tc := &TCP{Addr: "127.0.0.1:0", MaxEventBytes: 4096, MaxConns: 8, IdleTimeout: time.Second, Framing: "octet", MaxFrames: 6}
	ln, cancel, wg := startTCP(t, tc, func(fr Frame) error { mu.Lock(); got = append(got, fr); mu.Unlock(); return nil })
	defer cancel()
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		msg := fmt.Sprintf("<13>Jan  5 04:05:06 h app: conn %d", i)
		fmt.Fprintf(c, "%d %s", len(msg), msg)
		fmt.Fprintf(c, "%s line\n", msg)
		c.Close()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 6 {
		t.Fatalf("frames: %d", len(got))
	}
	peers := map[string]int{}
	for _, f := range got {
		if f.Peer == "" {
			t.Fatal("peer missing")
		}
		peers[f.Peer]++
	}
	if len(peers) != 3 {
		t.Fatalf("peers: %v", peers)
	}
}
