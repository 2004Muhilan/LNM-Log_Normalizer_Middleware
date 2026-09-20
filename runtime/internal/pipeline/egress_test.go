package pipeline

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ulpf/runtime/internal/egress"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/gap"
)

// siem is a minimal syslog/TCP receiver: RFC 6587 octet-counted frames, the MSG part (the JSON) kept per frame.
type siem struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs [][]byte
}

func newSIEM(t *testing.T, addr string) *siem {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &siem{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				r := bufio.NewReader(c)
				for {
					ls, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(ls))
					if err != nil {
						return
					}
					m := make([]byte, n)
					if _, err := io.ReadFull(r, m); err != nil {
						return
					}
					s.mu.Lock()
					s.msgs = append(s.msgs, m)
					s.mu.Unlock()
				}
			}()
		}
	}()
	return s
}

func (s *siem) payloads() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, m := range s.msgs {
		i := bytes.Index(m, []byte("] {"))
		out = append(out, m[i+2:])
	}
	return out
}

func gapRecords(t *testing.T, evDir string) []gap.Record {
	t.Helper()
	var out []gap.Record
	for _, seg := range evidence.Segments(evDir) {
		recs, err := evidence.ReadIndex(evDir, seg)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(filepath.Join(evDir, seg+".raw"))
		for _, r := range recs {
			if r.Framing.Method != evidence.MethodGapRecord {
				continue
			}
			var g gap.Record
			if err := json.Unmarshal(raw[r.Offset:r.Offset+int64(r.Length)], &g); err != nil {
				t.Fatal(err)
			}
			out = append(out, g)
		}
	}
	return out
}

func egressRun(t *testing.T, sinkURL string) (Stats, Options, string) {
	t.Helper()
	p := loadGoldenPack(t)
	in, err := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(t.TempDir(), "out.jsonl")
	fh, err := os.Create(spool)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var q bytes.Buffer
	o := fixedOpts(t, p, nil, &q)
	o.Out, o.SpoolPath = fh, spool
	o.Egress = []EgressSink{{URL: sinkURL, CursorPath: spool + ".cursor"}}
	o.EgressStallAfter, o.EgressDrain, o.EgressTimeout = 150*time.Millisecond, 900*time.Millisecond, 300*time.Millisecond
	st, err := Run(bytes.NewReader(in), o)
	if err != nil {
		t.Fatal(err)
	}
	return st, o, spool
}

// Egress touches no contract: what the SIEM receives inside each syslog frame is the normalized event byte for
// byte as the runtime emitted it; nothing is reordered; a healthy sink leaves no egress record in the evidence log.
func TestEgressForwardsTheEmittedBytesUnchanged(t *testing.T) {
	s := newSIEM(t, "127.0.0.1:0")
	defer s.ln.Close()
	st, o, spool := egressRun(t, "syslog+tcp://"+s.ln.Addr().String())
	time.Sleep(100 * time.Millisecond)
	if st.Emitted != 6 || len(st.Egress) != 1 || st.Egress[0].Delivered != 6 || st.Egress[0].Undelivered != 0 || st.Egress[0].Stalls != 0 {
		t.Fatalf("stats: emitted %d egress %+v", st.Emitted, st.Egress)
	}
	b, _ := os.ReadFile(spool)
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	got := s.payloads()
	if len(got) != 6 || len(lines) != 6 {
		t.Fatalf("frames %d, spool lines %d", len(got), len(lines))
	}
	for i := range lines {
		if !bytes.Equal(got[i], lines[i]) {
			t.Fatalf("frame %d is not the emitted event byte for byte:\n%s\n%s", i, got[i], lines[i])
		}
	}
	if !bytes.HasPrefix(s.msgs[0], []byte("<134>1 2024-12-19T")) || !bytes.Contains(s.msgs[0], []byte(`[ulpf@32473 event_id="ev_`)) {
		t.Fatalf("frame header: %s", s.msgs[0][:120])
	}
	if g := gapRecords(t, o.EvidenceDir); len(g) != 0 {
		t.Fatalf("a healthy sink must leave no gap record: %+v", g)
	}
}

// A SIEM that is not accepting costs no event and is NOT silent: ingestion completes (evidence written, events
// normalized and spooled), the interruption is an `egress_stalled` record IN THE EVIDENCE LOG — a leaf like any
// event — the run reports the undelivered bytes, and a later forwarder delivers all six from the persisted cursor.
func TestEgressOutageIsAnEvidenceLeafAndNothingIsDropped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // reserve an address, then close it: nobody is listening
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	st, o, spool := egressRun(t, "syslog+tcp://"+addr)
	if st.Emitted != 6 || st.Quarantined != 0 {
		t.Fatalf("ingestion must not depend on the sink: %+v", st)
	}
	if len(st.Egress) != 1 || st.Egress[0].Delivered != 0 || st.Egress[0].Undelivered == 0 || st.Egress[0].Stalls != 1 {
		t.Fatalf("egress stats: %+v", st.Egress)
	}
	g := gapRecords(t, o.EvidenceDir)
	if len(g) != 1 || g[0].Kind != "egress_stalled" || g[0].Peer != "syslog+tcp://"+addr || !strings.Contains(g[0].Detail, "none dropped") || st.GapKinds["egress_stalled"] != 1 {
		t.Fatalf("the outage must be one egress_stalled record in the evidence log: %+v (stats %v)", g, st.GapKinds)
	}
	// the SIEM comes back; the standalone forwarder resumes from the cursor the run persisted (offset 0: nothing was acknowledged)
	s := newSIEM(t, addr)
	defer s.ln.Close()
	sink, err := egress.Open("syslog+tcp://"+addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f := &egress.Forwarder{Spool: spool, CursorPath: spool + ".cursor", Sink: sink, Poll: 10 * time.Millisecond}
	if err := f.Start(false); err != nil {
		t.Fatal(err)
	}
	es := f.Drain(5 * time.Second)
	time.Sleep(100 * time.Millisecond)
	if es.Delivered != 6 || es.Undelivered != 0 || len(s.payloads()) != 6 {
		t.Fatalf("after the sink returned: %+v, %d frames", es, len(s.payloads()))
	}
}
