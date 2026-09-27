//go:build linux

package frame

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Scale-out: N listeners share one TCP address (SO_REUSEPORT); the kernel spreads connections over them, and every
// frame of one connection is received by exactly one listener (the flow's hash picks it).
func TestReusePortTCPKeepsEachConnectionOnOneProcess(t *testing.T) {
	const procs, senders, frames = 3, 24, 20
	first := &TCP{Addr: "127.0.0.1:0", MaxEventBytes: 4096, ReusePort: true}
	ln0, err := first.Listen()
	if err != nil {
		t.Fatal(err)
	}
	addr := ln0.Addr().String()
	var mu sync.Mutex
	owner := map[string]map[int]int{} // peer -> listener -> frames
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	serve := func(i int, tc *TCP, ln net.Listener) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tc.Serve(ctx, ln, func(fr Frame) error {
				mu.Lock()
				defer mu.Unlock()
				if owner[fr.Peer] == nil {
					owner[fr.Peer] = map[int]int{}
				}
				owner[fr.Peer][i]++
				return nil
			})
		}()
	}
	serve(0, first, ln0)
	for i := 1; i < procs; i++ {
		tc := &TCP{Addr: addr, MaxEventBytes: 4096, ReusePort: true}
		ln, err := tc.Listen()
		if err != nil {
			t.Fatalf("listener %d on the same address: %v", i, err)
		}
		serve(i, tc, ln)
	}
	for s := 0; s < senders; s++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		for f := 0; f < frames; f++ {
			m := fmt.Sprintf("<13>1 2026-09-27T00:00:00Z h app - - - sender %d frame %d", s, f)
			fmt.Fprintf(c, "%d %s", len(m), m)
		}
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := 0
		for _, m := range owner {
			for _, k := range m {
				n += k
			}
		}
		mu.Unlock()
		if n == senders*frames || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	used := map[int]bool{}
	for peer, m := range owner {
		if len(m) != 1 {
			t.Fatalf("connection %s was split across listeners: %v", peer, m)
		}
		for i, k := range m {
			used[i] = true
			if k != frames {
				t.Fatalf("connection %s: %d of %d frames", peer, k, frames)
			}
		}
	}
	if len(owner) != senders {
		t.Fatalf("%d of %d connections seen", len(owner), senders)
	}
	if len(used) < 2 {
		t.Fatalf("the kernel should have spread %d connections over %d listeners, used %v", senders, procs, used)
	}
}

// UDP: every datagram of one sender (one source port) reaches the same listener.
func TestReusePortUDPKeepsEachSenderOnOneProcess(t *testing.T) {
	const procs, senders, frames = 3, 16, 10
	u0 := UDP{Addr: "127.0.0.1:0", MaxEventBytes: 4096, ReusePort: true}
	c0, err := u0.Listen()
	if err != nil {
		t.Fatal(err)
	}
	addr := c0.LocalAddr().String()
	conns := []*net.UDPConn{c0}
	for i := 1; i < procs; i++ {
		c, err := UDP{Addr: addr, ReusePort: true}.Listen()
		if err != nil {
			t.Fatalf("udp listener %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	var mu sync.Mutex
	owner := map[string]map[int]int{}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c *net.UDPConn) {
			defer wg.Done()
			_ = UDP{MaxEventBytes: 4096}.Serve(ctx, c, func(fr Frame) error {
				mu.Lock()
				defer mu.Unlock()
				if owner[fr.Peer] == nil {
					owner[fr.Peer] = map[int]int{}
				}
				owner[fr.Peer][i]++
				return nil
			})
		}(i, c)
	}
	for s := 0; s < senders; s++ {
		c, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		for f := 0; f < frames; f++ {
			fmt.Fprintf(c, "<13>sender %d datagram %d", s, f)
			time.Sleep(time.Millisecond)
		}
		c.Close()
	}
	time.Sleep(300 * time.Millisecond)
	cancel()
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
	for peer, m := range owner {
		if len(m) != 1 {
			t.Fatalf("sender %s split across listeners: %v", peer, m)
		}
	}
	if len(owner) < senders*9/10 {
		t.Fatalf("only %d of %d senders seen", len(owner), senders)
	}
}

// Directory pull: two processes on one drop directory take disjoint shares; every file of one source goes to one.
func TestPullShardsPartitionBySource(t *testing.T) {
	dir := t.TempDir()
	for _, src := range []string{"fw01", "fw02", "proxy7", "dns3", "vpn9"} {
		for k := 0; k < 3; k++ {
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s_%d.log", src, k)), []byte(src+" line\n"), 0o644)
		}
	}
	bySource := map[string]map[int]bool{}
	total := 0
	for shard := 0; shard < 2; shard++ {
		p := &Pull{Dir: dir, Once: true, Shard: shard, Shards: 2}
		if err := p.Serve(context.Background(), func(fr Frame) error {
			src := fr.Peer[:len(fr.Peer)-len("_0.log")]
			if bySource[src] == nil {
				bySource[src] = map[int]bool{}
			}
			bySource[src][shard] = true
			total++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if total != 15 {
		t.Fatalf("every file exactly once across the shards: %d of 15", total)
	}
	for src, m := range bySource {
		if len(m) != 1 {
			t.Fatalf("source %s split across shards: %v", src, m)
		}
	}
}
