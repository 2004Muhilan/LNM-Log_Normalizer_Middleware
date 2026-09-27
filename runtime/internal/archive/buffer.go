package archive

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/keys"
)

// Buffer is the store's side of the archive: it decides, segment by segment, whether the local copy may go, and
// deletes it only when EVERY condition holds —
//
//  1. a signed checkpoint covers it: a minute checkpoint lists the segment, its signature verifies against the trust
//     store, and the root it lists carries the same raw and index hashes as the local seal record;
//  2. a receipt for it is in the archive, the receipt's hashes equal the local seal record's, and the archived files,
//     read now, still hash to them;
//  3. every checkpoint covering it is in the archive, byte-identical to the local one (with its signature);
//  4. the grace period since the receipt has passed (recent "Prove it" lookups stay local);
//  5. no proof is reading it (no unexpired lease).
//
// Never by age alone: an unshipped segment may be the only copy. The open segment is never considered.
type Buffer struct {
	Dir       string
	CommitDir string // the committer's commit tree (read here, never written)
	Archive   string
	Trust     keys.TrustStore
	Grace     time.Duration
	Now       func() time.Time

	mu      sync.Mutex
	sigOK   map[string]bool     // checkpoint file hash -> signature verified (a checkpoint never changes)
	cov     map[string][]string // during a sweep: segment -> covering checkpoints (read once per sweep)
	deleted int
}

// Condition names, one per deletion condition (tests break each on its own).
const (
	CondOpen       = "open"
	CondSealed     = "sealed"
	CondCheckpoint = "signed_checkpoint"
	CondReceipt    = "receipt"
	CondShippedCk  = "covering_checkpoints_shipped"
	CondGrace      = "grace_period"
	CondLease      = "no_proof_reading"
)

func (b *Buffer) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Buffer) cdir() string {
	if b.CommitDir != "" {
		return b.CommitDir
	}
	return filepath.Join(b.Dir, "commit")
}

// Check returns ("", "") when the segment may be deleted, else the failing condition and why.
func (b *Buffer) Check(segID, open string) (string, string) {
	if segID == open {
		return CondOpen, "the segment is still being written"
	}
	sealB, err := os.ReadFile(filepath.Join(b.Dir, segID+evidence.SuffixSeal))
	if err != nil {
		return CondSealed, "no seal record"
	}
	var man evidence.SealManifest
	if err := json.Unmarshal(sealB, &man); err != nil {
		return CondSealed, "unreadable seal record"
	}
	// 1. signed checkpoint coverage
	cov := b.cov
	if cov == nil {
		cov = CoveringCheckpoints(b.cdir())
	}
	cks := cov[segID]
	signed := []string{}
	for _, id := range cks {
		f := filepath.Join(b.cdir(), "checkpoints", id+".json")
		cb, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var ck checkpoint.Checkpoint
		if json.Unmarshal(cb, &ck) != nil {
			continue
		}
		if !b.verified(cb, f, ck.AuthorityID) {
			continue
		}
		for _, sr := range ck.Segments {
			if sr.SegmentID == segID && sr.RawSHA256 == man.RawSHA256 && sr.IdxSHA256 == man.IdxSHA256 {
				signed = append(signed, id)
			}
		}
	}
	if len(signed) == 0 {
		if len(cks) == 0 {
			return CondCheckpoint, "no checkpoint lists it"
		}
		return CondCheckpoint, "no checkpoint listing it has a signature that verifies against the trust store with matching hashes"
	}
	// 2a. the receipt names exactly the seal record's hashes
	storeID := evidence.ReadStoreID(b.Dir)
	r, err := ReadReceipt(b.Archive, storeID, segID)
	if err != nil {
		return CondReceipt, "not shipped: no receipt in the archive"
	}
	want := map[string]string{segID + evidence.SuffixRaw: man.RawSHA256, segID + evidence.SuffixIdx: man.IdxSHA256, segID + evidence.SuffixSeal: evidence.Hash(sealB)}
	for name, h := range want {
		if r.Files[name] != h {
			return CondReceipt, fmt.Sprintf("the receipt's hash for %s (%s) is not the seal record's (%s)", name, r.Files[name], h)
		}
	}
	// the cheap conditions before the archive is read again:
	// 4. grace
	if age := b.now().Sub(time.UnixMilli(r.ShippedAt)); age < b.Grace {
		return CondGrace, fmt.Sprintf("shipped %s ago; the grace period is %s", age.Round(time.Second), b.Grace)
	}
	// 5. no proof reading it
	if evidence.Leased(b.Dir, segID, b.now()) {
		return CondLease, "a proof is reading it"
	}
	// 3. covering checkpoints shipped, byte-identical
	for _, id := range cks {
		for _, suf := range []string{".json", ".json.sig"} {
			if ok, why := SameBytes(filepath.Join(b.cdir(), "checkpoints", id+suf), filepath.Join(StoreDir(b.Archive, storeID), "commit", "checkpoints", id+suf)); !ok {
				return CondShippedCk, "covering checkpoint " + id + suf + ": " + why
			}
		}
	}
	// 2b. the archived bytes themselves, read now, still hash to the seal record (the receipt is not taken on trust)
	for name, h := range want {
		ab, err := os.ReadFile(filepath.Join(StoreDir(b.Archive, storeID), "segments", name))
		if err != nil {
			return CondReceipt, "the archived " + name + " is missing"
		}
		if evidence.Hash(ab) != h {
			return CondReceipt, "the archived " + name + " no longer hashes to its seal record"
		}
	}
	return "", ""
}

func (b *Buffer) verified(cb []byte, f, authority string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sigOK == nil {
		b.sigOK = map[string]bool{}
	}
	h := evidence.Hash(cb)
	if ok, seen := b.sigOK[h]; seen {
		return ok
	}
	sig, err := os.ReadFile(f + ".sig")
	ok := err == nil && b.Trust.Dir != "" && b.Trust.Verify(authority, cb, strings.TrimSpace(string(sig))) == nil
	b.sigOK[h] = ok
	return ok
}

// Delete removes a segment's local copy: the catalogue of its event ids is written first (the local
// event-to-segment index), then the deletion is logged, then the kernel flag is cleared and the three files are
// removed. Call only after Check returned no failing condition.
func (b *Buffer) Delete(segID string) error {
	recs, err := evidence.ReadIndex(b.Dir, segID)
	if err != nil {
		return err
	}
	if err := evidence.WriteCatalog(b.Dir, segID, recs); err != nil {
		return err
	}
	storeID := evidence.ReadStoreID(b.Dir)
	r, _ := ReadReceipt(b.Archive, storeID, segID)
	line, _ := json.Marshal(map[string]any{"segment_id": segID, "deleted_at": b.now().UnixMilli(), "events": len(recs), "shipped_at": r.ShippedAt,
		"archive": StoreDir(b.Archive, storeID), "raw_sha256": r.Files[segID+evidence.SuffixRaw]})
	f, err := os.OpenFile(filepath.Join(b.Dir, "deleted.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		return err
	}
	for _, suf := range []string{evidence.SuffixIdx, evidence.SuffixRaw, evidence.SuffixSeal} {
		p := filepath.Join(b.Dir, segID+suf)
		if err := evidence.ClearImmutable(p); err != nil {
			return fmt.Errorf("%s: clearing the immutable flag: %w", p, err)
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if d, err := os.Open(b.Dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	b.mu.Lock()
	b.deleted++
	b.mu.Unlock()
	return nil
}

// SweepReport is one pass of the buffer.
type SweepReport struct {
	Deleted       []string          `json:"deleted"`
	Blocked       map[string]string `json:"blocked"` // segment -> "condition: why"
	LocalBytes    int64             `json:"local_bytes"`
	LocalSegments int               `json:"local_segments"`
}

// Sweep deletes every local segment all conditions allow and measures what stays.
func (b *Buffer) Sweep(open string) SweepReport {
	rep := SweepReport{Blocked: map[string]string{}}
	b.cov = CoveringCheckpoints(b.cdir())
	defer func() { b.cov = nil }()
	for _, seg := range evidence.Segments(b.Dir) {
		if cond, why := b.Check(seg, open); cond != "" {
			rep.Blocked[seg] = cond + ": " + why
			continue
		}
		if err := b.Delete(seg); err != nil {
			rep.Blocked[seg] = "delete: " + err.Error()
			continue
		}
		rep.Deleted = append(rep.Deleted, seg)
	}
	rep.LocalBytes, rep.LocalSegments = LocalUsage(b.Dir)
	return rep
}

// LocalUsage is the bytes and number of segments held in the local buffer (the three files of every segment).
func LocalUsage(dir string) (int64, int) {
	var n int64
	segs := evidence.Segments(dir)
	for _, seg := range segs {
		for _, suf := range evidence.SegmentSuffixes {
			if st, err := os.Stat(filepath.Join(dir, seg+suf)); err == nil {
				n += st.Size()
			}
		}
	}
	return n, len(segs)
}

// Status is what the demo's System page shows: shipped, pending, deleted, local usage.
type Status struct {
	StoreID          string `json:"store_id"`
	Archive          string `json:"archive"`
	LocalSegments    int    `json:"local_segments"`
	LocalBytes       int64  `json:"local_bytes"`
	ShippedSegments  int    `json:"shipped_segments"`  // receipts in the archive
	PendingSegments  int    `json:"pending_segments"`  // local segments without a receipt (open, uncommitted or not shipped yet)
	DeletedSegments  int    `json:"deleted_segments"`  // local copies removed after shipping (catalogue files)
	ArchivedBytes    int64  `json:"archived_bytes"`    // segment files in the archive
	CheckpointsLocal int    `json:"checkpoints_local"` // kept locally for the chain
}

// StatusOf reads the state from the directories alone (any process may call it).
func StatusOf(dir, cdir, archive string) Status {
	s := Status{StoreID: evidence.ReadStoreID(dir), Archive: archive}
	s.LocalBytes, s.LocalSegments = LocalUsage(dir)
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	cks, _ := filepath.Glob(filepath.Join(cdir, "checkpoints", "ckpt_*.json"))
	s.CheckpointsLocal = len(cks)
	cat, _ := filepath.Glob(filepath.Join(dir, "catalog", "seg_*.ids"))
	s.DeletedSegments = len(cat)
	if s.StoreID == "" || archive == "" {
		s.PendingSegments = s.LocalSegments
		return s
	}
	rec, _ := filepath.Glob(filepath.Join(StoreDir(archive, s.StoreID), "receipts", "seg_*.json"))
	s.ShippedSegments = len(rec)
	shipped := map[string]bool{}
	for _, r := range rec {
		shipped[strings.TrimSuffix(filepath.Base(r), ".json")] = true
	}
	for _, seg := range evidence.Segments(dir) {
		if !shipped[seg] {
			s.PendingSegments++
		}
	}
	files, _ := filepath.Glob(filepath.Join(StoreDir(archive, s.StoreID), "segments", "seg_*"))
	for _, f := range files {
		if st, err := os.Stat(f); err == nil && !strings.HasSuffix(f, ".part") {
			s.ArchivedBytes += st.Size()
		}
	}
	return s
}
