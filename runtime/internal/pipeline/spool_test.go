package pipeline

import (
	"bytes"
	"encoding/json"
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

	"ulpf/runtime/internal/egress"
	"ulpf/runtime/internal/gap"
)

// countingHTTP acknowledges every batch and remembers the event ids, in arrival order.
type countingHTTP struct {
	mu  sync.Mutex
	ids []string
}

func (c *countingHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e struct {
			L struct {
				ID string `json:"event_id"`
			} `json:"_lineage"`
		}
		json.Unmarshal(l, &e)
		c.ids = append(c.ids, e.L.ID)
	}
	w.WriteHeader(204)
}

// pacedReader hands out one line per `every`, like a live source.
type pacedReader struct {
	lines [][]byte
	every time.Duration
	cur   []byte
}

func (r *pacedReader) Read(b []byte) (int, error) {
	if len(r.cur) == 0 {
		if len(r.lines) == 0 {
			return 0, io.EOF
		}
		time.Sleep(r.every)
		r.cur, r.lines = r.lines[0], r.lines[1:]
	}
	n := copy(b, r.cur)
	r.cur = r.cur[n:]
	return n, nil
}

func squidLines(t *testing.T, n int) []byte {
	t.Helper()
	p := loadGoldenPack(t)
	in, err := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Repeat(in, n)
}

func spoolOpts(t *testing.T, ev, spool string, urls ...string) Options {
	o := Options{Pack: loadGoldenPack(t), EvidenceDir: ev, Collector: "col-01", Channel: "file:test", Out: io.Discard, Quarantine: io.Discard,
		SpoolDir: spool, SpoolSegment: 32 << 10, SpoolCap: 96 << 10, SpoolTick: 10 * time.Millisecond,
		EgressStallAfter: 50 * time.Millisecond, EgressDrain: 1500 * time.Millisecond, EgressTimeout: 100 * time.Millisecond}
	for _, u := range urls {
		o.Egress = append(o.Egress, EgressSink{URL: u})
	}
	return o
}

func deadAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

func kinds(g []gap.Record) map[string][]gap.Record {
	m := map[string][]gap.Record{}
	for _, r := range g {
		m[r.Kind] = append(m[r.Kind], r)
	}
	return m
}

// The cap: a dead destination falls behind; first ONE egress_lagging record, then one egress_skipped record per
// segment it is moved past, each naming the destination and the exact range; the live destination receives
// everything; the spool on disk stays near the cap; the skipped count plus what is still spooled for the dead
// destination is every event — nothing vanishes without a record.
func TestSpoolCapSkipsOnlyTheSlowestDestinationAndRecordsEverySkip(t *testing.T) {
	live := &countingHTTP{}
	srv := httptest.NewServer(live)
	defer srv.Close()
	dead := "syslog+tcp://" + deadAddr(t)
	ev, sp := t.TempDir(), t.TempDir()
	// paced like a live stream (one line per 4 ms): a HEALTHY destination keeps up and is never more than the cap behind;
	// only the dead one falls past it. The forwarder polls every 200 ms, so a healthy destination can be ~50 events (~90 KB)
	// behind at this rate — under the 96 KB cap. (Before group commit an fsync per event paced this stream implicitly.
	// Fed all at once, even a healthy one can be momentarily past a tiny cap — and is then skipped too: the cap is a hard
	// bound on the disk, the approved policy.)
	st, err := Run(&pacedReader{lines: bytes.SplitAfter(squidLines(t, 60), []byte("\n")), every: 4 * time.Millisecond}, spoolOpts(t, ev, sp, srv.URL, dead))
	if err != nil {
		t.Fatal(err)
	}
	if st.Emitted != 360 || len(st.Egress) != 2 {
		t.Fatalf("stats %+v", st)
	}
	var liveSt, deadSt egress.Stats
	for _, e := range st.Egress {
		if e.Sink == dead {
			deadSt = e
		} else {
			liveSt = e
		}
	}
	if liveSt.Delivered != 360 || len(live.ids) != 360 || liveSt.Skipped != 0 {
		t.Fatalf("the live destination must get every event and skip none: %+v (%d received)", liveSt, len(live.ids))
	}
	g := kinds(gapRecords(t, ev))
	if len(g["egress_lagging"]) != 1 || g["egress_lagging"][0].Peer != dead || !strings.Contains(g["egress_lagging"][0].Detail, "nothing has been skipped yet") {
		t.Fatalf("one early warning for the dead destination only: %+v", g["egress_lagging"])
	}
	var skipped int64
	for _, r := range g["egress_skipped"] {
		if r.Peer != dead || r.LastEventID == "" || r.Missing <= 0 || r.Observed <= r.Expected || !strings.Contains(r.Detail, "evidence log") || !strings.Contains(r.Detail, "this destination only") {
			t.Fatalf("skip record must name the destination and the exact range: %+v", r)
		}
		skipped += r.Missing
	}
	if len(g["egress_skipped"]) < 3 || skipped != deadSt.Skipped {
		t.Fatalf("%d skip records for %d events; stats %+v", len(g["egress_skipped"]), skipped, deadSt)
	}
	var spooled int64
	var bytesOnDisk int64
	cf, _ := filepath.Glob(filepath.Join(sp, "cursor-syslog*.json"))
	if len(cf) != 1 {
		t.Fatalf("one cursor per destination, keyed by name: %v", cf)
	}
	cur, _ := os.ReadFile(cf[0])
	var c egress.Cursor
	json.Unmarshal(cur, &c)
	for _, s := range egress.ListSegments(sp) {
		bytesOnDisk += s.Size
		b, _ := os.ReadFile(s.Path)
		for i, l := range bytes.Split(b, []byte("\n")) {
			_ = i
			if len(l) > 0 && s.Base+int64(bytes.Index(b, l)) >= c.Offset {
				spooled++
			}
		}
	}
	if skipped+spooled != 360 || skipped == 0 {
		t.Fatalf("skipped %d + still spooled for the dead destination %d must be every event (360); cursor %+v", skipped, spooled, c)
	}
	if bytesOnDisk > (96<<10)+2*(32<<10) {
		t.Fatalf("spool on disk %d bytes: the cap is 96 KiB (+ at most a segment or two in flight)", bytesOnDisk)
	}
	if len(g["egress_rejected"]) != 0 || len(g["spool_truncated"]) != 0 {
		t.Fatal("no other egress records expected")
	}
}

// A restart resumes: the spool and the cursors survive; a half-written tail is cut and recorded; a destination that
// was down in the first run receives, in the second, what it missed plus what is new — each event once.
func TestRunResumesTheSpoolAndEveryCursorAfterARestart(t *testing.T) {
	ev, sp := t.TempDir(), t.TempDir()
	live := &countingHTTP{}
	var down sync.Mutex
	isDown := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		down.Lock()
		d := isDown
		down.Unlock()
		if d {
			w.WriteHeader(503)
			return
		}
		live.ServeHTTP(w, r)
	}))
	defer srv.Close()
	url := srv.URL + "/ingest"
	o := spoolOpts(t, ev, sp, url)
	o.SpoolCap, o.EgressDrain = 64<<20, 200*time.Millisecond
	st1, err := Run(bytes.NewReader(squidLines(t, 2)), o)
	if err != nil || st1.Emitted != 12 || st1.Egress[0].Delivered != 0 {
		t.Fatalf("run 1: %v %+v", err, st1)
	}
	segs := egress.ListSegments(sp)
	f, _ := os.OpenFile(segs[len(segs)-1].Path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"class_uid":4002,"_line`) // the crash
	f.Close()
	down.Lock()
	isDown = false
	down.Unlock()
	o2 := spoolOpts(t, ev, sp, url)
	o2.SpoolCap, o2.EgressDrain = 64<<20, 2*time.Second
	st2, err := Run(bytes.NewReader(squidLines(t, 1)), o2)
	if err != nil || st2.Emitted != 6 {
		t.Fatalf("run 2: %v %+v", err, st2)
	}
	seen := map[string]int{}
	for _, id := range live.ids {
		seen[id]++
	}
	if len(live.ids) != 18 || len(seen) != 18 || st2.Egress[0].Delivered != 18 {
		t.Fatalf("after the restart the destination must get run 1's 12 and run 2's 6, each once: %d ids, %d distinct, %+v", len(live.ids), len(seen), st2.Egress)
	}
	g := kinds(gapRecords(t, ev))
	if len(g["spool_truncated"]) != 1 || g["spool_truncated"][0].Missing != 24 || !strings.Contains(g["spool_truncated"][0].Detail, "evidence log") {
		t.Fatalf("the cut tail must be recorded: %+v", g["spool_truncated"])
	}
	o3 := spoolOpts(t, ev, sp, url)
	o3.SpoolFresh, o3.EgressDrain = true, time.Second
	st3, _ := Run(bytes.NewReader(squidLines(t, 1)), o3)
	if st3.Egress[0].Delivered != 6 || len(live.ids) != 24 {
		t.Fatalf("--spool-fresh starts over: %+v, %d ids", st3.Egress, len(live.ids))
	}
}

// A document the destination refuses permanently is an egress_rejected record naming the event, the destination and
// the error; the destination moves past it; every other event is stored.
func TestARejectedDocumentIsAnEvidenceRecordAndDeliveryContinues(t *testing.T) {
	var mu sync.Mutex
	stored := map[string]bool{}
	var victim string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		ls := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
		var items []string
		errs := false
		for i := 0; i+1 < len(ls); i += 2 {
			var a struct {
				Index struct {
					ID string `json:"_id"`
				} `json:"index"`
			}
			json.Unmarshal(ls[i], &a)
			id := a.Index.ID
			if victim == "" {
				victim = id
			}
			if id == victim {
				errs = true
				items = append(items, fmt.Sprintf(`{"index":{"_id":%q,"status":400,"error":{"type":"mapper_parsing_exception","reason":"failed to parse field [time]"}}}`, id))
				continue
			}
			stored[id] = true
			items = append(items, fmt.Sprintf(`{"index":{"_id":%q,"status":201}}`, id))
		}
		fmt.Fprintf(w, `{"took":1,"errors":%v,"items":[%s]}`, errs, strings.Join(items, ","))
	}))
	defer srv.Close()
	ev, sp := t.TempDir(), t.TempDir()
	st, err := Run(bytes.NewReader(squidLines(t, 2)), spoolOpts(t, ev, sp, "bulk+"+srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	g := kinds(gapRecords(t, ev))
	if len(g["egress_rejected"]) != 1 || g["egress_rejected"][0].LastEventID != victim || !strings.Contains(g["egress_rejected"][0].Detail, "mapper_parsing_exception") || g["egress_rejected"][0].Peer != "bulk+"+srv.URL {
		t.Fatalf("rejection record: %+v", g["egress_rejected"])
	}
	if len(stored) != 11 || st.Egress[0].Rejected != 1 || st.Egress[0].Delivered != 12 || st.Egress[0].Undelivered != 0 {
		t.Fatalf("stored %d, stats %+v", len(stored), st.Egress)
	}
}
