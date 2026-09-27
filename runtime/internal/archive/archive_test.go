package archive

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/keys"
)

type env struct {
	dir, cdir, arch string
	key             keys.Key
	trust           keys.TrustStore
	recs            []evidence.Record
	storeID         string
	now             time.Time
}

// three sealed segments of 10 events, committed (sealed treated as immutable: the kernel flag cannot be set in an
// unprivileged test; the kernel path is scripts/p5-boundary-test.sh) and, unless ship is false, shipped.
func setup(t *testing.T, ship bool) *env {
	t.Helper()
	e := &env{dir: t.TempDir(), arch: t.TempDir(), now: time.UnixMilli(1734567890000).UTC()}
	e.cdir = filepath.Join(t.TempDir(), "commit")
	s, err := evidence.Open(e.dir, evidence.Options{Now: func() time.Time { return e.now }, Limits: evidence.Limits{MaxEvents: 10, MaxBytes: 1 << 20, MaxAge: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		l := []byte(strings.Repeat("x", i+1) + " event")
		fr := frame.Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte("\n"), FragmentCount: 1, OriginalMessageLength: len(l), TruncationStatus: "none", FramingConfidence: "high"}
		r, err := s.Append(l, fr, "src", "col", "file:t")
		if err != nil {
			t.Fatal(err)
		}
		e.recs = append(e.recs, r)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	e.storeID = s.ID()
	e.key, _ = keys.Generate("ulpf-committer-test")
	td := t.TempDir()
	if err := e.key.PublicOnly().Save(filepath.Join(td, e.key.AuthorityID+".pub.json")); err != nil {
		t.Fatal(err)
	}
	e.trust = keys.TrustStore{Dir: td}
	pretend := func(dir, seg string) string {
		if st := evidence.SegmentState(dir, seg); st != "sealed" {
			return st
		}
		return "immutable"
	}
	if rep, err := checkpoint.Commit(e.dir, e.cdir, e.key, pretend, e.now); err != nil || len(rep.Committed) != 3 {
		t.Fatalf("commit: %+v %v", rep, err)
	}
	if ship {
		rep, err := Ship(e.dir, e.cdir, e.arch, e.now)
		if err != nil || len(rep.Shipped) != 3 || len(rep.Pending) != 0 {
			t.Fatalf("ship: %+v %v", rep, err)
		}
	}
	return e
}

func (e *env) buffer(grace time.Duration, later time.Duration) *Buffer {
	return &Buffer{Dir: e.dir, CommitDir: e.cdir, Archive: e.arch, Trust: e.trust, Grace: grace, Now: func() time.Time { return e.now.Add(later) }}
}

func localFiles(dir, seg string) int {
	n := 0
	for _, suf := range evidence.SegmentSuffixes {
		if _, err := os.Stat(filepath.Join(dir, seg+suf)); err == nil {
			n++
		}
	}
	return n
}

const seg0 = "seg_00000"

// A segment is never deleted while any deletion condition fails — each condition broken on its own, everything else
// holding; the sweep keeps the segment and says which condition held it.
func TestNeverDeletedWhileAnyConditionFails(t *testing.T) {
	cases := []struct {
		name   string
		cond   string
		break_ func(e *env, b *Buffer) (open string)
	}{
		{"the open segment", CondOpen, func(e *env, b *Buffer) string { return seg0 }},
		{"no signed checkpoint covers it (the trust store does not know the committer)", CondCheckpoint, func(e *env, b *Buffer) string {
			b.Trust = keys.TrustStore{Dir: t.TempDir()}
			return ""
		}},
		{"no receipt (not shipped)", CondReceipt, func(e *env, b *Buffer) string {
			os.Remove(ReceiptPath(e.arch, e.storeID, seg0))
			return ""
		}},
		{"the receipt does not match the seal record", CondReceipt, func(e *env, b *Buffer) string {
			r, _ := ReadReceipt(e.arch, e.storeID, seg0)
			r.Files[seg0+evidence.SuffixRaw] = "sha256:" + strings.Repeat("0", 64)
			bb, _ := json.Marshal(r)
			os.WriteFile(ReceiptPath(e.arch, e.storeID, seg0), bb, 0o644)
			return ""
		}},
		{"the archived bytes changed after the receipt", CondReceipt, func(e *env, b *Buffer) string {
			p := evidence.ArchiveSegmentPath(e.arch, e.storeID, seg0, evidence.SuffixRaw)
			bb, _ := os.ReadFile(p)
			bb[0] ^= 1
			os.WriteFile(p, bb, 0o644)
			return ""
		}},
		{"a covering checkpoint is not in the archive", CondShippedCk, func(e *env, b *Buffer) string {
			os.Remove(filepath.Join(StoreDir(e.arch, e.storeID), "commit", "checkpoints", "ckpt_000001.json.sig"))
			return ""
		}},
		{"the grace period has not passed", CondGrace, func(e *env, b *Buffer) string {
			b.Grace = time.Hour
			return ""
		}},
		{"a proof is reading it", CondLease, func(e *env, b *Buffer) string {
			evidence.TakeLease(e.dir, seg0, time.Hour)
			return ""
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t, true)
			b := e.buffer(time.Minute, 2*time.Minute) // everything holds: shipped two minutes ago, grace one minute
			open := c.break_(e, b)
			if got, why := b.Check(seg0, open); got != c.cond {
				t.Fatalf("condition %q expected, got %q (%s)", c.cond, got, why)
			}
			rep := b.Sweep(open)
			if localFiles(e.dir, seg0) != 3 || strings.Contains(strings.Join(rep.Deleted, ","), seg0) {
				t.Fatalf("%s was deleted while %q failed: %+v", seg0, c.cond, rep)
			}
			if !strings.HasPrefix(rep.Blocked[seg0], c.cond+":") {
				t.Fatalf("the sweep must say which condition held it: %q", rep.Blocked[seg0])
			}
		})
	}
	// never by age alone: an unshipped segment, however old, stays
	t.Run("unshipped, a year old", func(t *testing.T) {
		e := setup(t, false)
		b := e.buffer(0, 365*24*time.Hour)
		if rep := b.Sweep(""); len(rep.Deleted) != 0 || localFiles(e.dir, seg0) != 3 {
			t.Fatalf("an unshipped segment must never be deleted by age: %+v", rep)
		}
	})
	// and when every condition holds, it goes — its catalogue and the deletion log stay, the archive keeps the bytes
	t.Run("every condition holds", func(t *testing.T) {
		e := setup(t, true)
		b := e.buffer(time.Minute, 2*time.Minute)
		rep := b.Sweep("")
		if len(rep.Deleted) != 3 || localFiles(e.dir, seg0) != 0 || rep.LocalSegments != 0 {
			t.Fatalf("all three shipped segments must go: %+v", rep)
		}
		if evidence.CatalogLookup(e.dir, e.recs[3].EventID) != seg0 {
			t.Fatal("the local event-to-segment catalogue must name the deleted segment")
		}
		if _, err := os.Stat(filepath.Join(e.dir, "deleted.jsonl")); err != nil {
			t.Fatal("deletions are logged")
		}
		for _, suf := range evidence.SegmentSuffixes {
			if _, err := os.Stat(evidence.ArchiveSegmentPath(e.arch, e.storeID, seg0, suf)); err != nil {
				t.Fatalf("the archive must still hold %s%s", seg0, suf)
			}
		}
		// checkpoints stay local for the chain
		if cks, _ := filepath.Glob(filepath.Join(e.cdir, "checkpoints", "ckpt_*.json")); len(cks) != 1 {
			t.Fatal("local checkpoints are kept")
		}
		// a new store on the same directory never reuses a deleted segment's id
		if n := evidence.NextSegmentNumber(e.dir); n != 3 {
			t.Fatalf("numbering must continue past deleted segments: next %d", n)
		}
	})
}

// "Prove it" after the local copy is deleted: the export reads the archived copy (checked against its seal record)
// and the bundle verifies with the public key alone.
func TestProveItAfterLocalDeletion(t *testing.T) {
	e := setup(t, true)
	if rep := e.buffer(0, time.Second).Sweep(""); len(rep.Deleted) != 3 {
		t.Fatalf("setup: %+v", rep)
	}
	target := e.recs[14] // in seg_00001, deleted locally
	if _, err := checkpoint.Export(e.dir, e.cdir, target.EventID, filepath.Join(t.TempDir(), "b0")); err == nil {
		t.Fatal("without the archive, a deleted segment cannot be proven")
	}
	out := filepath.Join(t.TempDir(), "bundle")
	b, err := checkpoint.ExportFrom(evidence.NewLocator(e.dir, e.arch), e.cdir, target.EventID, out)
	if err != nil {
		t.Fatal(err)
	}
	if b.EvidenceSource != "archive" || b.Record.SegmentID != "seg_00001" || b.StoreID != e.storeID {
		t.Fatalf("bundle: %+v", b)
	}
	if f, err := checkpoint.VerifyBundle(out, e.trust); err != nil {
		t.Fatalf("the bundle from the archive must verify: %v %+v", err, f)
	}
	if raw, _ := os.ReadFile(filepath.Join(out, "event.raw")); string(raw) != strings.Repeat("x", 15)+" event" {
		t.Fatalf("raw bytes: %q", raw)
	}
	// the whole verifier over local + archive: every committed segment verifies
	if f, n, err := checkpoint.VerifyAllFrom(evidence.NewLocator(e.dir, e.arch), e.cdir, e.trust); err != nil || len(f) != 0 || n != 1 {
		t.Fatalf("verify: %+v %d %v", f, n, err)
	}
}

// Tampering with an archived segment is detected and names the exact event.
func TestArchivedTamperNamesTheEvent(t *testing.T) {
	e := setup(t, true)
	e.buffer(0, time.Second).Sweep("")
	victim := e.recs[17] // seg_00001
	p := evidence.ArchiveSegmentPath(e.arch, e.storeID, victim.SegmentID, evidence.SuffixRaw)
	bb, _ := os.ReadFile(p)
	bb[victim.Offset+2] ^= 0x20
	if err := os.WriteFile(p, bb, 0o644); err != nil {
		t.Fatal(err)
	}
	loc := evidence.NewLocator(e.dir, e.arch)
	f, _, err := checkpoint.VerifyAllFrom(loc, e.cdir, e.trust)
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, x := range f {
		if x.Where == victim.SegmentID && strings.Contains(x.Detail, victim.EventID) && strings.Contains(x.Detail, "archived copy") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the verifier must name %s in the archived copy of %s: %+v", victim.EventID, victim.SegmentID, f)
	}
	if where, _ := checkpoint.LocateTamperFrom(loc, victim.SegmentID); !strings.Contains(where, victim.EventID) {
		t.Fatalf("locate: %q", where)
	}
	if _, err := checkpoint.ExportFrom(loc, e.cdir, victim.EventID, filepath.Join(t.TempDir(), "b")); err == nil {
		t.Fatal("an altered archived copy must not be exported as proof")
	}
}

// A restart mid-shipment resumes without duplicating or losing a segment: the shipper dies after the first file of the
// first segment lands; the next pass finds it, checks it, ships the rest and receipts every segment exactly once.
func TestShipResumesAfterACrash(t *testing.T) {
	e := setup(t, false)
	crash := errors.New("killed mid-shipment")
	landed := 0
	testHookAfterPut = func(dst string) error {
		if strings.Contains(dst, "/segments/seg_") && !strings.Contains(dst, "/commit/") {
			landed++
			if landed == 1 {
				return crash
			}
		}
		return nil
	}
	rep, _ := Ship(e.dir, e.cdir, e.arch, e.now)
	testHookAfterPut = nil
	if _, err := os.Stat(ReceiptPath(e.arch, e.storeID, seg0)); err == nil {
		t.Fatal("no receipt may exist for a segment whose shipment was interrupted")
	}
	if !strings.Contains(rep.Pending[seg0], "killed mid-shipment") {
		t.Fatalf("the interrupted segment is pending: %+v", rep)
	}
	rep2, err := Ship(e.dir, e.cdir, e.arch, e.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	receipted := map[string]bool{}
	for _, s := range append(rep.Shipped, rep2.Shipped...) {
		if receipted[s] {
			t.Fatalf("%s receipted twice", s)
		}
		receipted[s] = true
	}
	if len(receipted) != 3 || len(rep2.Pending) != 0 {
		t.Fatalf("every segment exactly once: %v, pending %v", receipted, rep2.Pending)
	}
	files, _ := filepath.Glob(filepath.Join(StoreDir(e.arch, e.storeID), "segments", "*"))
	if len(files) != 9 {
		t.Fatalf("three segments x three files, no leftovers or duplicates: %v", files)
	}
	for _, f := range files {
		if strings.HasSuffix(f, ".part") {
			t.Fatalf("temporary file left behind: %s", f)
		}
	}
	for _, r := range e.recs {
		if err := evidence.NewLocator(e.dir, e.arch).CheckSeal(r.SegmentID); err != nil {
			t.Fatal(err)
		}
	}
	// a third pass ships nothing new
	if rep3, _ := Ship(e.dir, e.cdir, e.arch, e.now.Add(2*time.Minute)); len(rep3.Shipped) != 0 || rep3.CommitFiles != 0 {
		t.Fatalf("shipping is idempotent: %+v", rep3)
	}
	// and the archive is never overwritten: a different file under a segment's name is refused, not replaced
	e2 := setup(t, false)
	os.MkdirAll(filepath.Join(StoreDir(e2.arch, e2.storeID), "segments"), 0o755)
	os.WriteFile(evidence.ArchiveSegmentPath(e2.arch, e2.storeID, seg0, evidence.SuffixRaw), []byte("not the evidence"), 0o644)
	rep4, _ := Ship(e2.dir, e2.cdir, e2.arch, e2.now)
	if !strings.Contains(rep4.Pending[seg0], "never overwritten") {
		t.Fatalf("a conflicting archived file must be reported, never overwritten: %+v", rep4)
	}
	if b, _ := os.ReadFile(evidence.ArchiveSegmentPath(e2.arch, e2.storeID, seg0, evidence.SuffixRaw)); string(b) != "not the evidence" {
		t.Fatal("the archive was overwritten")
	}
}
