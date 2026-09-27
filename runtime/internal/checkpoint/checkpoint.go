// Package checkpoint is the committer's logic: Merkle roots over IMMUTABLE evidence segments, signed
// checkpoints chained by hash, and the verifier's recomputation of all of it.
//
// Ordering rule (plan P5 exit criterion): a root is computed only over a segment whose three files
// carry the kernel's immutable flag — never over a segment that can still be written. Open segments
// (no seal manifest) and sealed-but-not-immutable segments are refused by name; the committer reports
// them and commits nothing for them.
//
// Layout under <evidence>/commit/:  segments/<seg>.root.json      one per committed segment
//
//	checkpoints/ckpt_<n>.json     minute checkpoints, chained
//	checkpoints/ckpt_<n>.json.sig ed25519 over the exact file bytes
//	daily/day_<YYYY-MM-DD>.json   daily roots over the day's checkpoints, signed likewise
//
// The committer holds a signing key and no capability; the store holds the capability and no key.
package checkpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/merkle"
)

// 1.1.0 (P5 boundary): commit_mode on the checkpoint and observed_state per segment — a development
// checkpoint over merely SEALED files is distinguishable from one over kernel-locked evidence, in the
// signed artifact itself. 1.0.0 checkpoints are read with commit_mode "unknown".
const CheckpointVersion = "1.1.0"

const (
	ModeKernelImmutable = "kernel_immutable" // every committed segment carried FS_IMMUTABLE_FL when committed
	ModeSealedOnlyDev   = "sealed_only_dev"  // at least one segment was only SEALED (development seam) — attests to file hashes, not to kernel-locked evidence
)

type SegmentRoot struct {
	SegmentID     string `json:"segment_id"`
	Root          string `json:"root"`
	Leaves        int    `json:"leaves"`
	RawSHA256     string `json:"raw_sha256"`
	IdxSHA256     string `json:"idx_sha256"`
	SealedAt      int64  `json:"sealed_at"`
	ObservedState string `json:"observed_state,omitempty"` // 1.1.0: what the kernel said at commit time: immutable | sealed
}

type Checkpoint struct {
	Version          string        `json:"checkpoint_version"`
	CheckpointID     string        `json:"checkpoint_id"`
	Kind             string        `json:"kind"` // minute | daily
	CreatedAt        int64         `json:"created_at"`
	PrevHash         string        `json:"prev_checkpoint_hash"` // sha256 of the previous checkpoint file bytes; "sha256:0..0" for the first
	AuthorityID      string        `json:"authority_id"`
	Segments         []SegmentRoot `json:"segments,omitempty"`    // minute
	Checkpoints      []string      `json:"checkpoints,omitempty"` // daily: ids of the minute checkpoints covered
	CheckpointHashes []string      `json:"checkpoint_hashes,omitempty"`
	Root             string        `json:"root"`                  // merkle root over segment roots (minute) or checkpoint hashes (daily)
	CommitMode       string        `json:"commit_mode,omitempty"` // 1.1.0: kernel_immutable | sealed_only_dev (daily: the weakest of its checkpoints)
}

// Mode of a checkpoint read from disk; 1.0.0 files carry none.
func (c Checkpoint) Mode() string {
	if c.CommitMode == "" {
		return "unknown (checkpoint_version " + c.Version + ")"
	}
	return c.CommitMode
}

// Immutability decides whether a segment may be committed. The production check is the kernel flag
// on all three files; tests inject one, which is the only way to exercise the ordering rule on a
// filesystem where the flag cannot be set.
type Immutability func(dir, segID string) string

func KernelImmutability(dir, segID string) string { return evidence.SegmentState(dir, segID) }

var zeroHash = "sha256:" + strings.Repeat("0", 64)

// SegmentLeaves recomputes every leaf of a segment from its raw bytes and index, refusing any record
// whose raw bytes do not hash to the recorded raw_hash (a corrupt segment is never committed).
func SegmentLeaves(dir, segID string) ([]merkle.Hash, []evidence.Record, error) {
	return SegmentLeavesFrom(evidence.NewLocator(dir, ""), segID)
}

// SegmentLeavesFrom is SegmentLeaves over the local buffer or, for a segment deleted locally, its archived copy.
// A record whose bytes changed is named in the error: the exact event.
func SegmentLeavesFrom(l *evidence.Locator, segID string) ([]merkle.Hash, []evidence.Record, error) {
	recs, err := l.ReadIndex(segID)
	if err != nil {
		return nil, nil, err
	}
	raw, where, err := l.ReadFile(segID, evidence.SuffixRaw)
	if err != nil {
		return nil, nil, err
	}
	copyOf := ""
	if where == "archive" {
		copyOf = " (archived copy)"
	}
	leaves := make([]merkle.Hash, 0, len(recs))
	for _, r := range recs {
		if r.Offset < 0 || r.Offset+int64(r.Length) > int64(len(raw)) {
			return nil, nil, fmt.Errorf("%s%s: record %s exceeds the segment", segID, copyOf, r.EventID)
		}
		if evidence.Hash(raw[r.Offset:r.Offset+int64(r.Length)]) != r.RawHash {
			return nil, nil, fmt.Errorf("%s%s: raw bytes of %s (bytes %d..%d) do not match raw_hash", segID, copyOf, r.EventID, r.Offset, r.Offset+int64(r.Length))
		}
		h, err := merkle.Parse(r.RawHash)
		if err != nil {
			return nil, nil, err
		}
		leaves = append(leaves, merkle.Leaf(segID, r.Offset, r.Length, h))
	}
	return leaves, recs, nil
}

func readManifest(dir, segID string) (evidence.SealManifest, error) {
	var m evidence.SealManifest
	b, err := os.ReadFile(filepath.Join(dir, segID+".seal.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// Report is what a commit run did and refused.
type Report struct {
	Committed  []string          `json:"committed"`
	Refused    map[string]string `json:"refused"` // segment -> reason
	Checkpoint *Checkpoint       `json:"checkpoint,omitempty"`
	Path       string            `json:"checkpoint_path,omitempty"`
}

// Commit computes roots for every immutable, not-yet-committed segment and writes one signed minute
// checkpoint over them (none when there is nothing new).
func Commit(dir, cdir string, key keys.Key, imm Immutability, now time.Time) (Report, error) {
	rep := Report{Refused: map[string]string{}}
	if imm == nil {
		imm = KernelImmutability
	}
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	for _, d := range []string{filepath.Join(cdir, "segments"), filepath.Join(cdir, "checkpoints"), filepath.Join(cdir, "daily")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return rep, err
		}
	}
	var roots []SegmentRoot
	for _, seg := range evidence.Segments(dir) {
		if _, err := os.Stat(filepath.Join(cdir, "segments", seg+".root.json")); err == nil {
			continue // already committed
		}
		switch st := imm(dir, seg); st {
		case "immutable":
		case "open":
			rep.Refused[seg] = "open: no seal manifest; the segment can still be written"
			continue
		default:
			rep.Refused[seg] = "sealed but not immutable: the kernel flag is not set on every file; the segment could still be written by a privileged process"
			continue
		}
		man, err := readManifest(dir, seg)
		if err != nil {
			rep.Refused[seg] = "unreadable seal manifest: " + err.Error()
			continue
		}
		rawB, _ := os.ReadFile(filepath.Join(dir, seg+".raw"))
		idxB, _ := os.ReadFile(filepath.Join(dir, seg+".idx.jsonl"))
		if evidence.Hash(rawB) != man.RawSHA256 || evidence.Hash(idxB) != man.IdxSHA256 {
			rep.Refused[seg] = "segment content does not match its seal manifest"
			continue
		}
		leaves, _, err := SegmentLeaves(dir, seg)
		if err != nil {
			rep.Refused[seg] = err.Error()
			continue
		}
		// observed_state is the KERNEL's answer, recorded even when a development seam decided commitability
		sr := SegmentRoot{SegmentID: seg, Root: merkle.Root(leaves).String(), Leaves: len(leaves), RawSHA256: man.RawSHA256, IdxSHA256: man.IdxSHA256, SealedAt: man.SealedAt, ObservedState: evidence.SegmentState(dir, seg)}
		b, _ := json.MarshalIndent(sr, "", "  ")
		if err := os.WriteFile(filepath.Join(cdir, "segments", seg+".root.json"), append(b, '\n'), 0o644); err != nil {
			return rep, err
		}
		roots = append(roots, sr)
		rep.Committed = append(rep.Committed, seg)
	}
	if len(roots) == 0 {
		return rep, nil
	}
	prevHash, n, err := lastCheckpoint(cdir)
	if err != nil {
		return rep, err
	}
	var rh []merkle.Hash
	for _, r := range roots {
		h, _ := merkle.Parse(r.Root)
		rh = append(rh, h)
	}
	mode := ModeKernelImmutable
	for _, r := range roots {
		if r.ObservedState != "immutable" {
			mode = ModeSealedOnlyDev
		}
	}
	ck := Checkpoint{Version: CheckpointVersion, CheckpointID: fmt.Sprintf("ckpt_%06d", n+1), Kind: "minute", CreatedAt: now.UnixMilli(),
		PrevHash: prevHash, AuthorityID: key.AuthorityID, Segments: roots, Root: merkle.Root(rh).String(), CommitMode: mode}
	path, err := writeSigned(filepath.Join(cdir, "checkpoints", ck.CheckpointID+".json"), ck, key)
	if err != nil {
		return rep, err
	}
	rep.Checkpoint, rep.Path = &ck, path
	return rep, nil
}

// Daily writes one signed daily root over every minute checkpoint created on the given UTC day.
func Daily(dir, cdir string, key keys.Key, day time.Time) (*Checkpoint, string, error) {
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	files, _ := filepath.Glob(filepath.Join(cdir, "checkpoints", "ckpt_*.json"))
	sort.Strings(files)
	dayStr := day.UTC().Format("2006-01-02")
	var ids, hashes []string
	var hs []merkle.Hash
	mode := ModeKernelImmutable
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, "", err
		}
		var ck Checkpoint
		if err := json.Unmarshal(b, &ck); err != nil {
			return nil, "", err
		}
		if time.UnixMilli(ck.CreatedAt).UTC().Format("2006-01-02") != dayStr {
			continue
		}
		h := evidence.Hash(b)
		ids = append(ids, ck.CheckpointID)
		if ck.CommitMode != ModeKernelImmutable {
			mode = ModeSealedOnlyDev
		}
		hashes = append(hashes, h)
		mh, _ := merkle.Parse(h)
		hs = append(hs, mh)
	}
	if len(ids) == 0 {
		return nil, "", errors.New("no minute checkpoints on " + dayStr)
	}
	ck := Checkpoint{Version: CheckpointVersion, CheckpointID: "day_" + dayStr, Kind: "daily", CreatedAt: day.UnixMilli(), PrevHash: zeroHash,
		AuthorityID: key.AuthorityID, Checkpoints: ids, CheckpointHashes: hashes, Root: merkle.Root(hs).String(), CommitMode: mode}
	if err := os.MkdirAll(filepath.Join(cdir, "daily"), 0o755); err != nil {
		return nil, "", err
	}
	path, err := writeSigned(filepath.Join(cdir, "daily", ck.CheckpointID+".json"), ck, key)
	return &ck, path, err
}

func writeSigned(path string, ck Checkpoint, key keys.Key) (string, error) {
	b, _ := json.MarshalIndent(ck, "", "  ")
	b = append(b, '\n')
	sig, err := key.Sign(b)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(path+".sig", []byte(sig+"\n"), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func lastCheckpoint(cdir string) (string, int, error) {
	files, _ := filepath.Glob(filepath.Join(cdir, "checkpoints", "ckpt_*.json"))
	if len(files) == 0 {
		return zeroHash, 0, nil
	}
	sort.Strings(files)
	last := files[len(files)-1]
	b, err := os.ReadFile(last)
	if err != nil {
		return "", 0, err
	}
	var n int
	fmt.Sscanf(filepath.Base(last), "ckpt_%06d.json", &n)
	return evidence.Hash(b), n, nil
}

// ---------------------------------------------------------------- verification

type Finding struct {
	Where  string `json:"where"`
	Detail string `json:"detail"`
}

// VerifyAll recomputes every committed segment root from the raw evidence, checks each checkpoint's
// signature, chain and root, and reports every discrepancy by name (segment and event where possible).
// It needs the evidence directory and a trust store — no ULPF state, so it can run anywhere.
func VerifyAll(dir, cdir string, trust keys.TrustStore) ([]Finding, int, error) {
	return VerifyAllFrom(evidence.NewLocator(dir, ""), cdir, trust)
}

// VerifyAllFrom is VerifyAll over the local buffer and the archive: a segment deleted locally is verified from its
// archived copy; one held in neither place is a finding.
func VerifyAllFrom(l *evidence.Locator, cdir string, trust keys.TrustStore) ([]Finding, int, error) {
	var findings []Finding
	dir := l.Dir
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	files, _ := filepath.Glob(filepath.Join(cdir, "checkpoints", "ckpt_*.json"))
	sort.Strings(files)
	prev := zeroHash
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return findings, checked, err
		}
		sigB, err := os.ReadFile(f + ".sig")
		if err != nil {
			findings = append(findings, Finding{filepath.Base(f), "signature file missing"})
			continue
		}
		var ck Checkpoint
		if err := json.Unmarshal(b, &ck); err != nil {
			findings = append(findings, Finding{filepath.Base(f), "unparseable: " + err.Error()})
			continue
		}
		if err := trust.Verify(ck.AuthorityID, b, strings.TrimSpace(string(sigB))); err != nil {
			findings = append(findings, Finding{ck.CheckpointID, "signature: " + err.Error()})
		}
		if ck.PrevHash != prev {
			findings = append(findings, Finding{ck.CheckpointID, fmt.Sprintf("chain broken: prev_checkpoint_hash %s, previous file hashes to %s", ck.PrevHash, prev)})
		}
		prev = evidence.Hash(b)
		var rh []merkle.Hash
		for _, sr := range ck.Segments {
			h, _ := merkle.Parse(sr.Root)
			rh = append(rh, h)
			leaves, recs, err := SegmentLeavesFrom(l, sr.SegmentID)
			if err != nil {
				findings = append(findings, Finding{sr.SegmentID, err.Error()})
				continue
			}
			if got := merkle.Root(leaves).String(); got != sr.Root {
				// name the leaf: recompute per-record hashes against the stored raw hashes already done in
				// SegmentLeaves; a root mismatch with intact records means the index itself changed
				findings = append(findings, Finding{sr.SegmentID, fmt.Sprintf("segment root %s differs from committed %s over %d records", got, sr.Root, len(recs))})
			}
			if _, err := l.Manifest(sr.SegmentID); err == nil {
				if err := l.CheckSeal(sr.SegmentID); err != nil {
					findings = append(findings, Finding{sr.SegmentID, err.Error()})
				}
			}
		}
		if len(ck.Segments) > 0 && merkle.Root(rh).String() != ck.Root {
			findings = append(findings, Finding{ck.CheckpointID, "checkpoint root differs from the segment roots it lists"})
		}
		checked++
	}
	// daily roots
	days, _ := filepath.Glob(filepath.Join(cdir, "daily", "day_*.json"))
	for _, f := range days {
		b, _ := os.ReadFile(f)
		sigB, err := os.ReadFile(f + ".sig")
		var ck Checkpoint
		if err != nil || json.Unmarshal(b, &ck) != nil {
			findings = append(findings, Finding{filepath.Base(f), "daily root unreadable or unsigned"})
			continue
		}
		if err := trust.Verify(ck.AuthorityID, b, strings.TrimSpace(string(sigB))); err != nil {
			findings = append(findings, Finding{ck.CheckpointID, "signature: " + err.Error()})
		}
		var hs []merkle.Hash
		for i, id := range ck.Checkpoints {
			cb, err := os.ReadFile(filepath.Join(cdir, "checkpoints", id+".json"))
			if err != nil || evidence.Hash(cb) != ck.CheckpointHashes[i] {
				findings = append(findings, Finding{ck.CheckpointID, "minute checkpoint " + id + " missing or changed since the daily root was signed"})
			}
			h, _ := merkle.Parse(ck.CheckpointHashes[i])
			hs = append(hs, h)
		}
		if merkle.Root(hs).String() != ck.Root {
			findings = append(findings, Finding{ck.CheckpointID, "daily root differs from its checkpoint hashes"})
		}
		checked++
	}
	return findings, checked, nil
}

func merkleRootString(leaves []merkle.Hash) string { return merkle.Root(leaves).String() }

// LocateTamper names the first record whose raw bytes no longer match its raw_hash — the leaf the
// verifier points at when a segment root differs.
func LocateTamper(dir, segID string) (string, error) {
	return LocateTamperFrom(evidence.NewLocator(dir, ""), segID)
}

// LocateTamperFrom is LocateTamper on the local copy or, when deleted locally, the archived copy.
func LocateTamperFrom(l *evidence.Locator, segID string) (string, error) {
	recs, err := l.ReadIndex(segID)
	if err != nil {
		return "", err
	}
	raw, _, err := l.ReadFile(segID, evidence.SuffixRaw)
	if err != nil {
		return "", err
	}
	for i, r := range recs {
		if r.Offset+int64(r.Length) > int64(len(raw)) || evidence.Hash(raw[r.Offset:r.Offset+int64(r.Length)]) != r.RawHash {
			return fmt.Sprintf("leaf %d (event %s, bytes %d..%d)", i, r.EventID, r.Offset, r.Offset+int64(r.Length)), nil
		}
	}
	return "", nil
}

// Modes returns checkpoint id -> commit mode for every checkpoint and daily root in the commit tree.
func Modes(dir, cdir string) map[string]string {
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	out := map[string]string{}
	for _, pat := range []string{"checkpoints/ckpt_*.json", "daily/day_*.json"} {
		files, _ := filepath.Glob(filepath.Join(cdir, pat))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var ck Checkpoint
			if json.Unmarshal(b, &ck) == nil && ck.CheckpointID != "" {
				out[ck.CheckpointID] = ck.Mode()
			}
		}
	}
	return out
}
