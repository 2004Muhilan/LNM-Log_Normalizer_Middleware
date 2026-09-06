package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ulpf/runtime/internal/frame"
)

func TestAppendSealReconstruct(t *testing.T) {
	dir := t.TempDir()
	now := time.UnixMilli(1734567890481).UTC()
	s, err := Open(dir, Options{Now: func() time.Time { return now }, Limits: Limits{MaxEvents: 2, MaxBytes: 1 << 20, MaxAge: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	lines := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	var want []byte
	var recs []Record
	for _, l := range lines {
		fr := frame.Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte("\r\n"), FragmentCount: 1, OriginalMessageLength: len(l), TruncationStatus: "none", FramingConfidence: "high"}
		r, err := s.Append(l, fr, "src", "col-01", "file:test")
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
		want = append(want, l...)
		want = append(want, "\r\n"...)
	}
	// MaxEvents=2 forces a rotation: the first segment must be sealed (immutable when this process holds
	// CAP_LINUX_IMMUTABLE on an inode-flag filesystem — the kernel decides, the store only reports), the
	// second open.
	sealedOrImmutable := func(st string) bool { return st == "sealed" || st == "immutable" }
	if !sealedOrImmutable(s.State(recs[0].SegmentID)) || s.State(recs[2].SegmentID) != "open" || recs[0].SegmentID == recs[2].SegmentID {
		t.Fatalf("lifecycle: %s=%s %s=%s", recs[0].SegmentID, s.State(recs[0].SegmentID), recs[2].SegmentID, s.State(recs[2].SegmentID))
	}
	if s.State(recs[0].SegmentID) == "sealed" {
		t.Logf("segment sealed but not immutable here: %s (expected without the capability)", s.ImmutabilityError(recs[0].SegmentID))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !sealedOrImmutable(s.State(recs[2].SegmentID)) {
		t.Fatal("close must seal the open segment")
	}
	// the on-disk view agrees with the in-memory one, and every sealed segment carries a manifest
	for _, seg := range Segments(dir) {
		if SegmentState(dir, seg) != s.State(seg) {
			t.Fatalf("state disagreement for %s: disk %s store %s", seg, SegmentState(dir, seg), s.State(seg))
		}
		if _, err := os.Stat(filepath.Join(dir, seg+".seal.json")); err != nil {
			t.Fatalf("no seal manifest for %s", seg)
		}
	}
	got, rs, err := Reconstruct(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || len(rs) != 3 {
		t.Fatalf("reconstruction differs: %q", got)
	}
	// Tamper: flip one byte in an immutable segment (as root would) and expect detection.
	p := filepath.Join(dir, recs[0].SegmentID+".raw")
	_ = os.Chmod(p, 0o644)
	b, _ := os.ReadFile(p)
	b[0] ^= 0xff
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Skipf("filesystem refused the tamper write (immutable attribute held): %v", err)
	}
	if _, _, err := Reconstruct(dir); err == nil {
		t.Fatal("tampered segment was not detected")
	}
}
