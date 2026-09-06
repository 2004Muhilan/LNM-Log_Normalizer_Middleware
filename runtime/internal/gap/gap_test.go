package gap

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSequenceIDFromStructuredData(t *testing.T) {
	for sd, want := range map[string]int64{`[meta sequenceId="42"]`: 42, `[timeQuality tzKnown="1"][meta ip="1.2.3.4" sequenceId="7" sysUpTime="1"]`: 7} {
		if v, ok := SequenceID(sd); !ok || v != want {
			t.Fatalf("%q: %v %v", sd, v, ok)
		}
	}
	for _, sd := range []string{"-", "", `[meta ip="1.2.3.4"]`, `[other sequenceId="3"]`} {
		if _, ok := SequenceID(sd); ok {
			t.Fatalf("%q must carry no sequence", sd)
		}
	}
}

func TestTrackerDetectsGapsResetsSilence(t *testing.T) {
	t0 := time.UnixMilli(1734567890000).UTC()
	tr := New(500 * time.Millisecond)
	seq := func(n int64) *int64 { return &n }
	if r := tr.Observe("a", "src", "ch", "ev1", seq(1), t0); len(r) != 0 {
		t.Fatalf("first message: %+v", r)
	}
	if r := tr.Observe("a", "src", "ch", "ev2", seq(2), t0.Add(10*time.Millisecond)); len(r) != 0 {
		t.Fatalf("consecutive: %+v", r)
	}
	r := tr.Observe("a", "src", "ch", "ev3", seq(6), t0.Add(20*time.Millisecond))
	if len(r) != 1 || r[0].Kind != "sequence_gap" || r[0].Expected != 3 || r[0].Observed != 6 || r[0].Missing != 3 || r[0].LastEventID != "ev2" || r[0].Peer != "a" {
		t.Fatalf("gap: %+v", r)
	}
	r = tr.Observe("a", "src", "ch", "ev4", seq(1), t0.Add(30*time.Millisecond))
	if len(r) != 1 || r[0].Kind != "sequence_reset" {
		t.Fatalf("reset: %+v", r)
	}
	// no sequence: no claim
	if r := tr.Observe("b", "src", "ch", "ev5", nil, t0.Add(40*time.Millisecond)); len(r) != 0 {
		t.Fatalf("no sequence: %+v", r)
	}
	// silence: b stops, a keeps talking
	if r := tr.Sweep(t0.Add(400 * time.Millisecond)); len(r) != 0 {
		t.Fatalf("not yet silent: %+v", r)
	}
	tr.Observe("a", "src", "ch", "ev6", seq(2), t0.Add(500*time.Millisecond))
	r = tr.Sweep(t0.Add(600 * time.Millisecond))
	if len(r) != 1 || r[0].Kind != "silence" || r[0].Peer != "b" || r[0].SilenceMS != 560 || r[0].LastEventID != "ev5" {
		t.Fatalf("silence: %+v", r)
	}
	if r := tr.Sweep(t0.Add(700 * time.Millisecond)); len(r) != 0 {
		t.Fatalf("silence is recorded once: %+v", r)
	}
	r = tr.Observe("b", "src", "ch", "ev7", nil, t0.Add(900*time.Millisecond))
	if len(r) != 1 || r[0].Kind != "silence_end" || r[0].SilenceMS != 860 {
		t.Fatalf("silence end: %+v", r)
	}
	l := tr.Lost("a", "src", "ch", "closed by peer", t0.Add(time.Second))
	if l.Kind != "connection_lost" || l.LastEventID != "ev6" {
		t.Fatalf("lost: %+v", l)
	}
	if tr.Peers() != 2 {
		t.Fatal("peers")
	}
}

// Canonical bytes: sorted keys, no whitespace, no empty fields — the same detection hashes the same on
// any machine; parseable back.
func TestCanonicalIsDeterministicAndParses(t *testing.T) {
	r := Record{RecordVersion: RecordVersion, Kind: "silence", SourceID: "s", Channel: "c", Peer: "p", DetectedAt: 2, LastSeenAt: 1, SilenceMS: 1, Detail: "d"}
	b := Canonical(r)
	want := `{"channel":"c","detail":"d","detected_at":2,"kind":"silence","last_seen_at":1,"peer":"p","record_version":"gap-record 1.0.0","silence_ms":1,"source_id":"s"}`
	if string(b) != want {
		t.Fatalf("canonical:\n%s\n%s", b, want)
	}
	back, err := Parse(b)
	if err != nil || back != r {
		t.Fatalf("parse: %v %+v", err, back)
	}
	var generic map[string]any
	if json.Unmarshal(b, &generic) != nil {
		t.Fatal("valid json")
	}
}
