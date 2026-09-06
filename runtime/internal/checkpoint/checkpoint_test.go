package checkpoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/keys"
)

func fixtureStore(t *testing.T, dir string, n int, maxEvents int) []evidence.Record {
	now := time.UnixMilli(1734567890000).UTC()
	s, err := evidence.Open(dir, evidence.Options{Now: func() time.Time { return now }, Limits: evidence.Limits{MaxEvents: maxEvents, MaxBytes: 1 << 20, MaxAge: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	var recs []evidence.Record
	for i := 0; i < n; i++ {
		l := []byte(strings.Repeat("x", i+1) + " event")
		fr := frame.Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte("\n"), FragmentCount: 1, OriginalMessageLength: len(l), TruncationStatus: "none", FramingConfidence: "high"}
		r, err := s.Append(l, fr, "src", "col", "file:t")
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	return recs // the last segment stays OPEN on purpose: the store is not closed
}

// pretendImmutable treats every sealed segment as immutable — the flag cannot be set in an
// unprivileged test process; the kernel path is exercised by scripts/p5-boundary-test.sh.
func pretendImmutable(dir, seg string) string {
	st := evidence.SegmentState(dir, seg)
	if st == "sealed" {
		return "immutable"
	}
	return st
}

func trust(t *testing.T, k keys.Key) keys.TrustStore {
	td := t.TempDir()
	if err := k.PublicOnly().Save(filepath.Join(td, k.AuthorityID+".pub.json")); err != nil {
		t.Fatal(err)
	}
	return keys.TrustStore{Dir: td}
}

func TestOrderingRuleNeverCommitsAWritableSegment(t *testing.T) {
	dir := t.TempDir()
	recs := fixtureStore(t, dir, 5, 2) // seg_00000 (2), seg_00001 (2) sealed; seg_00002 (1) open
	key, _ := keys.Generate("ulpf-committer-test")
	// 1. with the kernel's real answer this process has no capability: nothing is immutable -> nothing committed
	rep, err := Commit(dir, "", key, KernelImmutability, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Committed) != 0 || rep.Checkpoint != nil {
		t.Fatalf("committed without immutability: %+v", rep)
	}
	for _, seg := range []string{"seg_00000", "seg_00001"} {
		if !strings.Contains(rep.Refused[seg], "not immutable") {
			t.Fatalf("%s refusal reason: %q", seg, rep.Refused[seg])
		}
	}
	if !strings.Contains(rep.Refused["seg_00002"], "open") {
		t.Fatalf("open segment refusal: %q", rep.Refused["seg_00002"])
	}
	// 2. with sealed segments treated as immutable: the two sealed ones are committed, the open one refused
	rep, err = Commit(dir, "", key, pretendImmutable, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Committed, ",") != "seg_00000,seg_00001" || rep.Checkpoint == nil || len(rep.Checkpoint.Segments) != 2 {
		t.Fatalf("commit: %+v", rep)
	}
	if !strings.Contains(rep.Refused["seg_00002"], "open") {
		t.Fatalf("the open segment must be refused by name: %+v", rep.Refused)
	}
	if _, err := os.Stat(filepath.Join(dir, "commit", "segments", "seg_00002.root.json")); err == nil {
		t.Fatal("a root was written for an open segment")
	}
	// 3. a second run commits nothing new and writes no checkpoint
	rep2, _ := Commit(dir, "", key, pretendImmutable, time.Now())
	if len(rep2.Committed) != 0 || rep2.Checkpoint != nil {
		t.Fatalf("recommitted: %+v", rep2)
	}
	_ = recs
	// 4. verification passes and the chain has one link
	f, n, err := VerifyAll(dir, "", trust(t, key))
	if err != nil || len(f) != 0 || n != 1 {
		t.Fatalf("verify: %v %v %d", f, err, n)
	}
}

func TestTamperIsDetectedAndNamed(t *testing.T) {
	dir := t.TempDir()
	recs := fixtureStore(t, dir, 4, 2)
	key, _ := keys.Generate("ulpf-committer-test")
	if _, err := Commit(dir, "", key, pretendImmutable, time.Now()); err != nil {
		t.Fatal(err)
	}
	// flip one byte of the second event in the first segment (as a privileged attacker would)
	p := filepath.Join(dir, "seg_00000.raw")
	_ = os.Chmod(p, 0o644)
	b, _ := os.ReadFile(p)
	b[recs[1].Offset] ^= 0x01
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Skip("filesystem held the immutable flag; the kernel path is exercised by the boundary test")
	}
	f, _, err := VerifyAll(dir, "", trust(t, key))
	if err != nil || len(f) == 0 {
		t.Fatalf("tamper not detected: %v %v", f, err)
	}
	where, _ := LocateTamper(dir, "seg_00000")
	if !strings.Contains(where, "leaf 1") || !strings.Contains(where, recs[1].EventID) {
		t.Fatalf("tamper not named: %q", where)
	}
	// the untouched segment still verifies on its own
	if w, _ := LocateTamper(dir, "seg_00001"); w != "" {
		t.Fatalf("false positive on the intact segment: %s", w)
	}
}

func TestSignatureChainAndDaily(t *testing.T) {
	dir := t.TempDir()
	fixtureStore(t, dir, 6, 2)
	key, _ := keys.Generate("ulpf-committer-test")
	t0 := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	// commit the first two sealed segments, then seal more and commit again -> two chained checkpoints
	rep1, _ := Commit(dir, "", key, pretendImmutable, t0)
	s, _ := evidence.Open(dir, evidence.Options{Now: func() time.Time { return t0 }, Limits: evidence.Limits{MaxEvents: 2, MaxBytes: 1 << 20, MaxAge: time.Hour}})
	s.Close() // Open marks the leftover open segment by disk state; nothing to seal, so seal a fresh one:
	s2, _ := evidence.Open(dir, evidence.Options{Now: func() time.Time { return t0 }, Limits: evidence.Limits{MaxEvents: 1, MaxBytes: 1 << 20, MaxAge: time.Hour}})
	s2.Append([]byte("late event"), frame.Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte("\n"), FragmentCount: 1, OriginalMessageLength: 10, TruncationStatus: "none", FramingConfidence: "high"}, "src", "col", "f")
	s2.Close()
	rep2, _ := Commit(dir, "", key, pretendImmutable, t0.Add(time.Minute))
	if rep1.Checkpoint == nil || rep2.Checkpoint == nil || rep2.Checkpoint.PrevHash == rep1.Checkpoint.PrevHash {
		t.Fatalf("two chained checkpoints expected: %+v %+v", rep1.Checkpoint, rep2.Checkpoint)
	}
	if _, path, err := Daily(dir, "", key, t0); err != nil || path == "" {
		t.Fatal(err)
	}
	tr := trust(t, key)
	if f, n, err := VerifyAll(dir, "", tr); err != nil || len(f) != 0 || n != 3 {
		t.Fatalf("verify: %v %d %v", f, n, err)
	}
	// forge: re-sign the first checkpoint with another key -> signature finding; edit its bytes -> chain finding
	other, _ := keys.Generate("ulpf-committer-test")
	cp := rep1.Path
	cb, _ := os.ReadFile(cp)
	sig, _ := other.Sign(cb)
	os.WriteFile(cp+".sig", []byte(sig+"\n"), 0o644) // checkpoint .sig files are bare hex; the authority is inside the signed checkpoint
	f, _, _ := VerifyAll(dir, "", tr)
	if len(f) == 0 || !strings.Contains(f[0].Detail, "signature") {
		t.Fatalf("forged signature not detected: %v", f)
	}
	os.WriteFile(cp, []byte(strings.Replace(string(cb), "\"minute\"", "\"minute \"", 1)), 0o644)
	f, _, _ = VerifyAll(dir, "", tr)
	found := false
	for _, x := range f {
		found = found || strings.Contains(x.Detail, "chain broken") || strings.Contains(x.Detail, "changed since the daily")
	}
	if !found {
		t.Fatalf("edited checkpoint not detected via chain/daily: %v", f)
	}
}

func TestExportBundleVerifiesWithOnlyTheTrustStore(t *testing.T) {
	dir := t.TempDir()
	recs := fixtureStore(t, dir, 5, 2)
	key, _ := keys.Generate("ulpf-committer-test")
	if _, err := Commit(dir, "", key, pretendImmutable, time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	Daily(dir, "", key, time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC))
	out := t.TempDir()
	b, err := Export(dir, "", recs[2].EventID, out)
	if err != nil {
		t.Fatal(err)
	}
	if b.LeafIndex != 0 || b.Record.SegmentID != "seg_00001" || b.DailyFile == "" {
		t.Fatalf("bundle: %+v", b)
	}
	if f, err := VerifyBundle(out, trust(t, key)); err != nil || f != nil {
		t.Fatalf("bundle should verify: %v %v", f, err)
	}
	// a bundle for the open segment's event cannot exist yet
	if _, err := Export(dir, "", recs[4].EventID, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not been committed") {
		t.Fatalf("export of an uncommitted event must fail: %v", err)
	}
	// tamper with the exported raw bytes -> refused, named
	raw, _ := os.ReadFile(filepath.Join(out, "event.raw"))
	raw[0] ^= 0xff
	os.WriteFile(filepath.Join(out, "event.raw"), raw, 0o644)
	f, err := VerifyBundle(out, trust(t, key))
	if err == nil || len(f) == 0 || f[0].Where != "event.raw" {
		t.Fatalf("tampered bundle accepted: %v %v", f, err)
	}
	// an untrusted authority -> refused
	if f, err := VerifyBundle(out, keys.TrustStore{Dir: t.TempDir()}); err == nil || len(f) == 0 {
		t.Fatal("bundle verified without a trusted key")
	}
}

// A development checkpoint cannot masquerade as a real one: the mode is in the signed artifact.
func TestCommitModeIsStampedAndSigned(t *testing.T) {
	dir := t.TempDir()
	fixtureStore(t, dir, 4, 2)
	key, _ := keys.Generate("ulpf-committer-test")
	rep, _ := Commit(dir, "", key, pretendImmutable, time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC))
	if rep.Checkpoint.CommitMode != ModeSealedOnlyDev {
		t.Fatalf("unprivileged commit must be stamped sealed_only_dev, got %q", rep.Checkpoint.CommitMode)
	}
	for _, s := range rep.Checkpoint.Segments {
		if s.ObservedState != "sealed" {
			t.Fatalf("observed_state must be the kernel's answer (sealed), got %q", s.ObservedState)
		}
	}
	dk, _, _ := Daily(dir, "", key, time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC))
	if dk.CommitMode != ModeSealedOnlyDev {
		t.Fatalf("daily root must carry the weakest mode, got %q", dk.CommitMode)
	}
	modes := Modes(dir, "")
	if modes[rep.Checkpoint.CheckpointID] != ModeSealedOnlyDev || modes[dk.CheckpointID] != ModeSealedOnlyDev {
		t.Fatalf("modes: %v", modes)
	}
	// editing the mode after signing is caught like any other edit
	cb, _ := os.ReadFile(rep.Path)
	os.WriteFile(rep.Path, []byte(strings.Replace(string(cb), ModeSealedOnlyDev, ModeKernelImmutable, 1)), 0o644)
	f, _, _ := VerifyAll(dir, "", trust(t, key))
	if len(f) == 0 {
		t.Fatal("a checkpoint whose mode was upgraded after signing must fail verification")
	}
}
