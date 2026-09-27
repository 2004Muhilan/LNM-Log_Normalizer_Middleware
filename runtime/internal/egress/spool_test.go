package egress

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func ev(i int) []byte {
	return []byte(fmt.Sprintf(`{"class_uid":4001,"_lineage":{"event_id":"ev_%05d"}}`+"\n", i))
}

// A reopened spool continues where it ended; a half-written tail is cut back and reported; a spool with segments but
// no SPOOL_ID is refused; --spool-fresh discards segments and cursors.
func TestSpoolResumesAndCutsAHalfWrittenTail(t *testing.T) {
	dir := t.TempDir()
	s, tr, err := OpenSpool(dir, 200, false)
	if err != nil || tr != nil {
		t.Fatal(err, tr)
	}
	for i := 0; i < 10; i++ {
		if err := s.Append(ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	head, id := s.Head(), s.ID
	s.Close()
	segs := ListSegments(dir)
	if len(segs) < 2 || segs[len(segs)-1].End() != head {
		t.Fatalf("segments %+v head %d", segs, head)
	}
	for i := 1; i < len(segs); i++ {
		if segs[i].Base != segs[i-1].End() {
			t.Fatalf("segments must be contiguous in the global offset: %+v", segs)
		}
	}
	f, _ := os.OpenFile(segs[len(segs)-1].Path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"class_uid":4001,"_lin`) // a crash mid-write
	f.Close()
	s2, tr, err := OpenSpool(dir, 200, false)
	if err != nil || tr == nil || tr.Bytes != 23 || tr.At != head || s2.ID != id || s2.Head() != head {
		t.Fatalf("reopen: %v %+v id %s head %d", err, tr, s2.ID, s2.Head())
	}
	s2.Append(ev(10))
	batch, _, _, _ := readSpool(dir, head, 10, 1<<20)
	if len(batch) != 1 || !strings.Contains(string(batch[0]), "ev_00010") {
		t.Fatalf("the next append must follow the cut, not glue onto the fragment: %q", batch)
	}
	s2.Close()
	os.Remove(filepath.Join(dir, "SPOOL_ID"))
	if _, _, err := OpenSpool(dir, 200, false); err == nil {
		t.Fatal("segments without a SPOOL_ID must be refused")
	}
	os.WriteFile(filepath.Join(dir, "cursor-x.json"), []byte("{}"), 0o644)
	s3, _, err := OpenSpool(dir, 200, true)
	if err != nil || s3.Head() != 0 || s3.ID == id {
		t.Fatalf("fresh: %v head %d", err, s3.Head())
	}
	if _, err := os.Stat(filepath.Join(dir, "cursor-x.json")); !os.IsNotExist(err) {
		t.Fatal("a fresh spool discards the cursors")
	}
}

type httpFake struct {
	mu   sync.Mutex
	got  []string
	hdr  []http.Header
	down bool
}

func (h *httpFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down {
		w.WriteHeader(503)
		return
	}
	b, _ := io.ReadAll(r.Body)
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		h.got = append(h.got, l)
	}
	h.hdr = append(h.hdr, r.Header.Clone())
	w.WriteHeader(204)
}

func (h *httpFake) n() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.got) }

// Each destination has its own cursor in the segmented spool: a dead one delivers nothing and delays nothing; the
// live one gets every event, in order, each batch carrying its exact spool range; cursors are keyed by the
// destination's name and survive a restart of the forwarder.
func TestSegmentedSpoolDestinationsAreIndependentAndResume(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := OpenSpool(dir, 300, false)
	fake := &httpFake{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	live, _ := Open(srv.URL, time.Second)
	gone, _ := Open("syslog+tcp://"+dead, 100*time.Millisecond)
	fl := &Forwarder{Seg: s, Sink: live, Poll: 5 * time.Millisecond, BatchLines: 7}
	fd := &Forwarder{Seg: s, Sink: gone, Poll: 5 * time.Millisecond, StallAfter: 50 * time.Millisecond}
	fl.Start(false)
	fd.Start(false)
	for i := 0; i < 60; i++ {
		s.Append(ev(i))
	}
	for t0 := time.Now(); fake.n() < 60 && time.Since(t0) < 5*time.Second; {
		time.Sleep(5 * time.Millisecond)
	}
	sl, sd := fl.Drain(time.Second), fd.Drain(100*time.Millisecond)
	if sl.Delivered != 60 || sd.Delivered != 0 || sd.Undelivered != s.Head() {
		t.Fatalf("live %+v dead %+v", sl, sd)
	}
	for i, l := range fake.got {
		if !strings.Contains(l, fmt.Sprintf("ev_%05d", i)) {
			t.Fatalf("order: %d %s", i, l)
		}
	}
	var prevEnd int64
	for _, h := range fake.hdr {
		var a, b int64
		fmt.Sscan(h.Get("X-ULPF-Spool-Start"), &a)
		fmt.Sscan(h.Get("X-ULPF-Spool-End"), &b)
		if h.Get("X-ULPF-Spool-Id") != s.ID || a != prevEnd || b <= a {
			t.Fatalf("spool range headers must tile the spool: %v", h)
		}
		prevEnd = b
	}
	if prevEnd != s.Head() {
		t.Fatalf("ranges end at %d, spool at %d", prevEnd, s.Head())
	}
	if _, err := os.Stat(s.CursorPath(live.Name())); err != nil {
		t.Fatal("cursor keyed by destination name:", err)
	}
	// restart: the live destination resumes at the head, nothing is sent twice
	for i := 60; i < 65; i++ {
		s.Append(ev(i))
	}
	live2, _ := Open(srv.URL, time.Second)
	f2 := &Forwarder{Seg: s, Sink: live2, Poll: 5 * time.Millisecond}
	f2.Start(false)
	for t0 := time.Now(); fake.n() < 65 && time.Since(t0) < 5*time.Second; {
		time.Sleep(5 * time.Millisecond)
	}
	f2.Drain(time.Second)
	if fake.n() != 65 || !strings.Contains(fake.got[60], "ev_00060") {
		t.Fatalf("after the restart: %d lines, got[60]=%s", fake.n(), fake.got[60])
	}
}

// Syslog has no acknowledgement: after a restart, the last batch the previous run believed delivered is sent again
// (at most a redelivery, never a loss).
func TestSyslogDestinationGetsTheLastBatchAgainAfterARestart(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := OpenSpool(dir, 1<<20, false)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				b, _ := io.ReadAll(c)
				mu.Lock()
				got = append(got, string(b))
				mu.Unlock()
			}()
		}
	}()
	defer ln.Close()
	for i := 0; i < 4; i++ {
		s.Append(ev(i))
	}
	sink, _ := Open("syslog+tcp://"+ln.Addr().String(), time.Second)
	f := &Forwarder{Seg: s, Sink: sink, Poll: 5 * time.Millisecond, BatchLines: 2}
	f.Start(false)
	time.Sleep(200 * time.Millisecond)
	f.Drain(time.Second)
	s.Append(ev(4))
	sink2, _ := Open("syslog+tcp://"+ln.Addr().String(), time.Second)
	f2 := &Forwarder{Seg: s, Sink: sink2, Poll: 5 * time.Millisecond, BatchLines: 2}
	f2.Start(false)
	time.Sleep(200 * time.Millisecond)
	st := f2.Drain(time.Second)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	all := strings.Join(got, "")
	mu.Unlock()
	c := func(id string) int { return strings.Count(all, `"event_id":"`+id+`"`) } // the JSON body; the frame's structured data names it again
	if c("ev_00002") != 2 || c("ev_00003") != 2 || c("ev_00001") != 1 || c("ev_00004") != 1 || st.Resent != 2 {
		t.Fatalf("expected the last batch (ev 2,3) twice, everything else once; resent %d:\n%s", st.Resent, all)
	}
}

// Skipping moves only the slow destination, names the exact range, and never goes backwards.
func TestRequestSkipNamesTheExactRangeForThatDestinationOnly(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := OpenSpool(dir, 1<<20, false)
	for i := 0; i < 10; i++ {
		s.Append(ev(i))
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	gone, _ := Open("syslog+tcp://"+dead, 50*time.Millisecond)
	var skips []Skip
	var mu sync.Mutex
	f := &Forwarder{Seg: s, Sink: gone, Poll: 5 * time.Millisecond, MaxBackoff: 10 * time.Second, OnSkip: func(k Skip) { mu.Lock(); skips = append(skips, k); mu.Unlock() }}
	f.Start(false)
	time.Sleep(1500 * time.Millisecond) // deep into backoff: the request must wake it
	to := int64(len(ev(0))) * 6
	t0 := time.Now()
	f.RequestSkip(to)
	for f.Offset() != to && time.Since(t0) < 2*time.Second {
		time.Sleep(5 * time.Millisecond)
	}
	f.RequestSkip(to / 2) // never backwards
	time.Sleep(50 * time.Millisecond)
	st := f.Drain(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(skips) != 1 || skips[0].Count != 6 || skips[0].FirstID != "ev_00000" || skips[0].LastID != "ev_00005" || skips[0].From != 0 || skips[0].To != to || st.Skipped != 6 || time.Since(t0) > 1500*time.Millisecond {
		t.Fatalf("skips %+v stats %+v after %v", skips, st, time.Since(t0))
	}
}
