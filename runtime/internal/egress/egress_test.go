package egress

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func event(i int, pad int) string {
	return fmt.Sprintf(`{"class_uid":4001,"time":1734567890123,"n":%d,"pad":"%s","_lineage":{"event_id":"ev_%026d","raw_hash":"sha256:%064d"}}`, i, strings.Repeat("x", pad), i, i)
}

func spool(t *testing.T, n, pad int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "out.jsonl")
	var b strings.Builder
	for i := 1; i <= n; i++ {
		b.WriteString(event(i, pad) + "\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// collector is a syslog/TCP receiver that parses RFC 6587 octet-counted frames and records the event numbers.
type collector struct {
	ln    net.Listener
	mu    sync.Mutex
	seen  []int
	byCon map[net.Conn][]int // per connection, in arrival order
	conns []net.Conn
	read  atomic.Bool // when false, connections are accepted and never read (a sink that stopped accepting)
}

func newCollector(t *testing.T, addr string) *collector {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{ln: ln, byCon: map[net.Conn][]int{}}
	c.read.Store(true)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.conns = append(c.conns, conn)
			c.mu.Unlock()
			go c.serve(conn)
		}
	}()
	return c
}

func (c *collector) serve(conn net.Conn) {
	for !c.read.Load() {
		time.Sleep(20 * time.Millisecond)
	}
	r := bufio.NewReader(conn)
	for {
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(r, msg); err != nil {
			return
		}
		i := strings.Index(string(msg), "] {")
		var ev struct {
			N int `json:"n"`
		}
		if i < 0 || json.Unmarshal(msg[i+2:], &ev) != nil || !strings.HasPrefix(string(msg), "<134>1 ") || !strings.Contains(string(msg), `[ulpf@32473 event_id="ev_`) {
			panic("malformed frame: " + string(msg[:min(len(msg), 120)]))
		}
		c.mu.Lock()
		c.seen = append(c.seen, ev.N)
		c.byCon[conn] = append(c.byCon[conn], ev.N)
		c.mu.Unlock()
	}
}

func (c *collector) kill() { // the SIEM goes away: listener and every connection
	c.ln.Close()
	c.mu.Lock()
	for _, x := range c.conns {
		x.Close()
	}
	c.mu.Unlock()
}

func (c *collector) numbers() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.seen...)
}

// every event 1..n arrived at least once, and first arrivals are in order (duplicates are allowed: at-least-once)
func assertAllInOrder(t *testing.T, seen []int, n int) (dups int) {
	t.Helper()
	first := map[int]int{}
	last := 0
	for pos, v := range seen {
		if _, ok := first[v]; ok {
			dups++
			continue
		}
		first[v] = pos
		if v != last+1 {
			t.Fatalf("first arrival of %d follows %d: an event was skipped or reordered", v, last)
		}
		last = v
	}
	if len(first) != n {
		t.Fatalf("%d of %d events arrived: events were DROPPED", len(first), n)
	}
	return dups
}

// What at-least-once over RECONNECTING TCP actually guarantees: every event arrives; WITHIN a connection events are
// in order (re-sent batches may repeat earlier numbers, never skip forward past an undelivered one). ACROSS
// connections a receiver may interleave the old connection's buffered tail with the new connection's resend, so a
// global order is not promised — receivers order by event time / event_id, as they must for any multi-path feed.
func assertNoneDroppedOrderedPerConnection(t *testing.T, c *collector, n int) (dups int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	got := map[int]int{}
	for _, seq := range c.byCon {
		high := 0
		for _, v := range seq {
			got[v]++
			if high > 0 && v > high+1 { // a connection may START anywhere (a resend after reconnect); it may never skip forward
				t.Fatalf("within one connection %d follows %d: an event was skipped", v, high)
			}
			if v > high {
				high = v
			}
		}
	}
	for i := 1; i <= n; i++ {
		if got[i] == 0 {
			t.Fatalf("event %d never arrived: DROPPED (%d of %d distinct arrived)", i, len(got), n)
		}
		dups += got[i] - 1
	}
	return dups
}

func TestSyslogForwardDeliversEveryEventFramedAndInOrder(t *testing.T) {
	c := newCollector(t, "127.0.0.1:0")
	defer c.kill()
	sp := spool(t, 250, 40)
	f := &Forwarder{Spool: sp, CursorPath: sp + ".cursor", Sink: &SyslogTCP{Addr: c.ln.Addr().String(), Timeout: 2 * time.Second, Hostname: "ulpf-test"}, Poll: 10 * time.Millisecond}
	if err := f.Start(true); err != nil {
		t.Fatal(err)
	}
	st := f.Drain(10 * time.Second)
	time.Sleep(100 * time.Millisecond)
	if st.Delivered != 250 || st.Undelivered != 0 || st.Stalls != 0 {
		t.Fatalf("stats: %+v", st)
	}
	if d := assertAllInOrder(t, c.numbers(), 250); d != 0 {
		t.Fatalf("%d duplicates on a healthy connection", d)
	}
	// the cursor survives: a second forwarder over the same spool sends nothing again
	f2 := &Forwarder{Spool: sp, CursorPath: sp + ".cursor", Sink: &SyslogTCP{Addr: c.ln.Addr().String(), Timeout: 2 * time.Second}, Poll: 10 * time.Millisecond}
	if err := f2.Start(false); err != nil {
		t.Fatal(err)
	}
	f2.Drain(5 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if n := len(c.numbers()); n != 250 {
		t.Fatalf("a restarted forwarder re-sent delivered events: %d frames", n)
	}
}

// The requirement this package exists for: a SIEM that goes away must not cost a single event, and the
// interruption must be REPORTED (OnStall -> the pipeline's egress_stalled gap record), then its end (OnResume).
func TestSinkOutageDropsNothingAndIsReported(t *testing.T) {
	c := newCollector(t, "127.0.0.1:0")
	addr := c.ln.Addr().String()
	sp := spool(t, 100, 40)
	var mu sync.Mutex
	var stalls, resumes []Stall
	f := &Forwarder{Spool: sp, CursorPath: sp + ".cursor", Sink: &SyslogTCP{Addr: addr, Timeout: time.Second}, BatchLines: 20, Poll: 10 * time.Millisecond,
		StallAfter: 300 * time.Millisecond, MaxBackoff: 100 * time.Millisecond,
		OnStall:  func(s Stall) { mu.Lock(); stalls = append(stalls, s); mu.Unlock() },
		OnResume: func(s Stall) { mu.Lock(); resumes = append(resumes, s); mu.Unlock() }}
	if err := f.Start(true); err != nil {
		t.Fatal(err)
	}
	for len(c.numbers()) < 100 {
		time.Sleep(time.Millisecond)
	}
	c.kill() // the SIEM goes away ... and ingestion carries on: 300 more events reach the spool while it is down
	fh, err := os.OpenFile(sp, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 101; i <= 400; i++ {
		fh.WriteString(event(i, 40) + "\n")
	}
	fh.Close()
	before := c.numbers()
	time.Sleep(800 * time.Millisecond) // long enough for StallAfter
	mu.Lock()
	if len(stalls) != 1 || stalls[0].LastEventID == "" || stalls[0].Err == "" {
		mu.Unlock()
		t.Fatalf("the outage must be reported once, naming the last acknowledged event: %+v", stalls)
	}
	mu.Unlock()
	if b, err := os.ReadFile(sp + ".cursor"); err != nil || !strings.Contains(string(b), `"sink": "syslog+tcp://`) {
		t.Fatalf("cursor not persisted: %v %s", err, b)
	}
	// the SIEM comes back on the same address
	c2 := newCollector(t, addr)
	defer c2.kill()
	st := f.Drain(20 * time.Second)
	time.Sleep(100 * time.Millisecond)
	all := append(before, c2.numbers()...)
	dups := assertAllInOrder(t, all, 400)
	mu.Lock()
	defer mu.Unlock()
	if st.Delivered != 400 || st.Undelivered != 0 || st.Retries == 0 || len(resumes) != 1 || resumes[0].LagEvents == 0 {
		t.Fatalf("after recovery: stats %+v resumes %+v", st, resumes)
	}
	t.Logf("outage: %d events before, %d after, %d duplicate(s) (at-least-once), %d retries, stall reported after %v, %d events delivered late",
		len(before), len(c2.numbers()), dups, st.Retries, stalls[0].Duration.Round(time.Millisecond), resumes[0].LagEvents)
}

// A sink that ACCEPTS the connection and stops READING: the TCP window fills, the write must time out (not hang),
// the stall must be reported, nothing may be dropped, and delivery completes when the sink reads again.
func TestSinkThatStopsReadingIsAStallNotAHang(t *testing.T) {
	c := newCollector(t, "127.0.0.1:0")
	defer c.kill()
	c.read.Store(false)
	const n = 6000
	sp := spool(t, n, 4000) // ~24 MiB: far beyond loopback socket buffers
	var stalled atomic.Int32
	f := &Forwarder{Spool: sp, CursorPath: sp + ".cursor", Sink: &SyslogTCP{Addr: c.ln.Addr().String(), Timeout: 300 * time.Millisecond}, Poll: 10 * time.Millisecond,
		StallAfter: 400 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, OnStall: func(Stall) { stalled.Add(1) }}
	if err := f.Start(true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for stalled.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if stalled.Load() == 0 {
		t.Fatal("a sink that stopped reading was never reported as stalled: the forwarder is hanging in a write or silently dropping")
	}
	c.read.Store(true)
	st := f.Drain(60 * time.Second)
	time.Sleep(200 * time.Millisecond)
	dups := assertNoneDroppedOrderedPerConnection(t, c, n)
	if st.Undelivered != 0 || st.Delivered != n {
		t.Fatalf("stats: %+v", st)
	}
	t.Logf("stopped-reading sink: stalled, then %d events delivered, %d duplicate(s), %d retries", n, dups, st.Retries)
}

func TestHTTPPostRetriesUntilAcknowledged(t *testing.T) {
	var mu sync.Mutex
	var got []int
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 3 { // the collector refuses the first three batches
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Content-Type") != "application/x-ndjson" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		sc := bufio.NewScanner(r.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		mu.Lock()
		for sc.Scan() {
			var ev struct {
				N int `json:"n"`
			}
			if json.Unmarshal(sc.Bytes(), &ev) == nil {
				got = append(got, ev.N)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	sp := spool(t, 130, 10)
	sink, err := Open(srv.URL, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f := &Forwarder{Spool: sp, CursorPath: sp + ".cursor", Sink: sink, BatchLines: 50, Poll: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}
	if err := f.Start(true); err != nil {
		t.Fatal(err)
	}
	st := f.Drain(10 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	if d := assertAllInOrder(t, got, 130); d != 0 || st.Retries != 3 || st.Delivered != 130 {
		t.Fatalf("http: %d duplicates (a refused batch must not be partly accepted), stats %+v", d, st)
	}
}

func TestPartialLastLineIsNotSentAndReplacedSpoolIsRefused(t *testing.T) {
	c := newCollector(t, "127.0.0.1:0")
	defer c.kill()
	sp := spool(t, 3, 5)
	fh, _ := os.OpenFile(sp, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"n":4,"_lineage":{"event_id":"ev_half`) // the writer is mid-line
	fh.Close()
	f := &Forwarder{Spool: sp, CursorPath: sp + ".cursor", Sink: &SyslogTCP{Addr: c.ln.Addr().String(), Timeout: time.Second}, Poll: 10 * time.Millisecond}
	if err := f.Start(true); err != nil {
		t.Fatal(err)
	}
	st := f.Drain(300 * time.Millisecond)
	if st.Delivered != 3 || st.Undelivered == 0 {
		t.Fatalf("a half-written line must stay undelivered, not be sent: %+v", st)
	}
	// the spool is replaced by a shorter file: the old cursor must not be trusted
	os.WriteFile(sp, []byte(event(1, 1)+"\n"), 0o644)
	f2 := &Forwarder{Spool: sp, CursorPath: sp + ".cursor", Sink: &SyslogTCP{Addr: c.ln.Addr().String(), Timeout: time.Second}}
	if err := f2.Start(false); err == nil || !strings.Contains(err.Error(), "spool was replaced") {
		t.Fatalf("a cursor beyond the spool must be refused: %v", err)
	}
	if _, err := Open("syslog+udp://127.0.0.1:514", time.Second); err == nil || !strings.Contains(err.Error(), "not offered") {
		t.Fatalf("UDP forwarding must be refused with the reason: %v", err)
	}
}
