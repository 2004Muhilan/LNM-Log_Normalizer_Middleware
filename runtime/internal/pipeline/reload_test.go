package pipeline

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/pack"
)

// Hot reload: the set of loaded packs is swapped BETWEEN two frames, without a restart, and the change is an
// evidence-log record — from that leaf on, events are interpreted under a different pack, provable from the log
// alone. A reload that changes nothing writes nothing; a reload that cannot build a router changes nothing; a frame
// on a second ingress connector carries ITS channel into the evidence record.
func TestReloadSwapsPacksBetweenFramesAndIsAnEvidenceRecord(t *testing.T) {
	p := loadGoldenPack(t)
	in, _ := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	lines := bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n"))
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	var pipe *Pipeline
	st, err := RunFramesWith(func(emit func(frame.Frame) error) error {
		fr := func(l []byte, ch string) frame.Frame {
			return frame.Frame{Raw: l, Channel: ch, Framing: frame.Framing{Method: "newline", FragmentCount: 1, OriginalMessageLength: len(l), TruncationStatus: "none", FramingConfidence: "high"}}
		}
		if err := emit(fr(lines[0], "")); err != nil {
			return err
		}
		if err := pipe.Reload([]*pack.Pack{p}, "same set"); err != nil { // nothing changed: no record
			t.Fatal(err)
		}
		if err := pipe.Reload(nil, "empty set"); err == nil { // a router cannot be built from nothing: refused, the old one stays
			t.Fatal("a reload to no packs must be refused")
		}
		if err := emit(fr(lines[1], "http:127.0.0.1:8514")); err != nil {
			return err
		}
		newer := *p
		newer.PackVersion, newer.FileSHA256 = "1.1", "sha256:"+strings.Repeat("ab", 32)
		if err := pipe.Reload([]*pack.Pack{&newer}, "test: a corrected pack"); err != nil {
			t.Fatal(err)
		}
		return emit(fr(lines[2], ""))
	}, o, func(pl *Pipeline) { pipe = pl })
	if err != nil {
		t.Fatal(err)
	}
	if st.Emitted != 3 || st.Quarantined != 0 {
		t.Fatalf("all three lines must parse across the reload: %+v", st)
	}
	recs, err := evidence.ReadIndex(o.EvidenceDir, "seg_00000")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 { // event, event, pack_activated, event — in that order
		t.Fatalf("want 3 events and exactly ONE activation record, got %d records", len(recs))
	}
	raw, _ := os.ReadFile(filepath.Join(o.EvidenceDir, "seg_00000.raw"))
	act := string(raw[recs[2].Offset : recs[2].Offset+int64(recs[2].Length)])
	for _, want := range []string{`"kind":"pack_activated"`, "squid-native v1.1 sha256:abab", "was: v1.0 sha256:", "test: a corrected pack"} {
		if !strings.Contains(act, want) {
			t.Fatalf("activation record lacks %q: %s", want, act)
		}
	}
	if recs[0].Channel != o.Channel || recs[1].Channel != "http:127.0.0.1:8514" {
		t.Fatalf("each frame's evidence record must name the connector it arrived on: %q, %q", recs[0].Channel, recs[1].Channel)
	}
}
