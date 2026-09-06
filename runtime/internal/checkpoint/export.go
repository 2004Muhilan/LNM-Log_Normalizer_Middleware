package checkpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/merkle"
)

// Bundle is the one-command evidence export: the raw bytes of one event, its lineage record, the
// Merkle inclusion proof to its segment root, the checkpoint that committed that root (with its
// signature), and the daily root if one exists. Verifiable with nothing but a trust-store public key —
// the external-witness pattern (plan §4.5): a machine that has never run ULPF checks it.
type Bundle struct {
	BundleVersion  string          `json:"bundle_version"`
	EventID        string          `json:"event_id"`
	Record         evidence.Record `json:"record"`
	RawFile        string          `json:"raw_file"` // event.raw next to bundle.json
	Leaf           string          `json:"leaf"`
	LeafIndex      int             `json:"leaf_index"`
	Proof          []ProofStep     `json:"proof"`
	SegmentRoot    string          `json:"segment_root"`
	CheckpointID   string          `json:"checkpoint_id"`
	CheckpointFile string          `json:"checkpoint_file"` // checkpoint.json (+ .sig) next to bundle.json
	DailyFile      string          `json:"daily_file,omitempty"`
}

type ProofStep struct {
	Sibling string `json:"sibling"`
	Left    bool   `json:"left"`
}

// Export writes the bundle for eventID into outDir.
func Export(dir, cdir, eventID, outDir string) (Bundle, error) {
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	var b Bundle
	var rec *evidence.Record
	var idx int
	var segID string
	for _, seg := range evidence.Segments(dir) {
		recs, err := evidence.ReadIndex(dir, seg)
		if err != nil {
			return b, err
		}
		for i, r := range recs {
			if r.EventID == eventID {
				rr := r
				rec, idx, segID = &rr, i, seg
			}
		}
	}
	if rec == nil {
		return b, fmt.Errorf("event %s not found in %s", eventID, dir)
	}
	leaves, _, err := SegmentLeaves(dir, segID)
	if err != nil {
		return b, err
	}
	proof, err := merkle.Proof(leaves, idx)
	if err != nil {
		return b, err
	}
	// the checkpoint that committed this segment
	files, _ := filepath.Glob(filepath.Join(cdir, "checkpoints", "ckpt_*.json"))
	sort.Strings(files)
	var ckFile string
	var root string
	for _, f := range files {
		cb, _ := os.ReadFile(f)
		var ck Checkpoint
		if json.Unmarshal(cb, &ck) != nil {
			continue
		}
		for _, sr := range ck.Segments {
			if sr.SegmentID == segID {
				ckFile, root = f, sr.Root
			}
		}
	}
	if ckFile == "" {
		return b, fmt.Errorf("segment %s of event %s has not been committed yet (run the committer first)", segID, eventID)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return b, err
	}
	raw, _ := os.ReadFile(filepath.Join(dir, segID+".raw"))
	if err := os.WriteFile(filepath.Join(outDir, "event.raw"), raw[rec.Offset:rec.Offset+int64(rec.Length)], 0o644); err != nil {
		return b, err
	}
	for _, suffix := range []string{"", ".sig"} {
		cb, err := os.ReadFile(ckFile + suffix)
		if err != nil {
			return b, err
		}
		if err := os.WriteFile(filepath.Join(outDir, "checkpoint.json"+suffix), cb, 0o644); err != nil {
			return b, err
		}
	}
	b = Bundle{BundleVersion: "1.0.0", EventID: eventID, Record: *rec, RawFile: "event.raw", Leaf: leaves[idx].String(), LeafIndex: idx,
		SegmentRoot: root, CheckpointID: strings.TrimSuffix(filepath.Base(ckFile), ".json"), CheckpointFile: "checkpoint.json"}
	for _, s := range proof {
		b.Proof = append(b.Proof, ProofStep{Sibling: s.Sibling.String(), Left: s.Left})
	}
	// daily root covering that checkpoint, if any
	days, _ := filepath.Glob(filepath.Join(cdir, "daily", "day_*.json"))
	for _, d := range days {
		db, _ := os.ReadFile(d)
		var dk Checkpoint
		if json.Unmarshal(db, &dk) != nil {
			continue
		}
		for _, id := range dk.Checkpoints {
			if id == b.CheckpointID {
				for _, suffix := range []string{"", ".sig"} {
					x, _ := os.ReadFile(d + suffix)
					_ = os.WriteFile(filepath.Join(outDir, "daily.json"+suffix), x, 0o644)
				}
				b.DailyFile = "daily.json"
			}
		}
	}
	bb, _ := json.MarshalIndent(b, "", "  ")
	return b, os.WriteFile(filepath.Join(outDir, "bundle.json"), append(bb, '\n'), 0o644)
}

// VerifyBundle checks a bundle with only a trust store: raw bytes hash to the record's raw_hash; the
// leaf is the canonical leaf of that record; the proof reaches the segment root; the checkpoint lists
// that root, hashes consistently and is signed by a trusted authority; the daily root, when present,
// covers the checkpoint and is signed. Returns every discrepancy.
func VerifyBundle(bundleDir string, trust keys.TrustStore) ([]Finding, error) {
	var findings []Finding
	bb, err := os.ReadFile(filepath.Join(bundleDir, "bundle.json"))
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(bb, &b); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(bundleDir, b.RawFile))
	if err != nil {
		return nil, err
	}
	if evidence.Hash(raw) != b.Record.RawHash {
		findings = append(findings, Finding{"event.raw", fmt.Sprintf("raw bytes hash to %s, record says %s", evidence.Hash(raw), b.Record.RawHash)})
	}
	if len(raw) != b.Record.Length {
		findings = append(findings, Finding{"event.raw", "length differs from the record"})
	}
	rh, err := merkle.Parse(b.Record.RawHash)
	if err != nil {
		return findings, err
	}
	leaf := merkle.Leaf(b.Record.SegmentID, b.Record.Offset, b.Record.Length, rh)
	if leaf.String() != b.Leaf {
		findings = append(findings, Finding{"leaf", "leaf hash is not the canonical leaf of the record"})
	}
	var steps []merkle.Step
	for _, s := range b.Proof {
		h, err := merkle.Parse(s.Sibling)
		if err != nil {
			return findings, err
		}
		steps = append(steps, merkle.Step{Sibling: h, Left: s.Left})
	}
	root, err := merkle.Parse(b.SegmentRoot)
	if err != nil {
		return findings, err
	}
	if !merkle.Verify(leaf, steps, root) {
		findings = append(findings, Finding{"proof", "inclusion proof does not reach the segment root"})
	}
	cb, err := os.ReadFile(filepath.Join(bundleDir, b.CheckpointFile))
	if err != nil {
		return findings, err
	}
	sig, err := os.ReadFile(filepath.Join(bundleDir, b.CheckpointFile+".sig"))
	if err != nil {
		return append(findings, Finding{"checkpoint", "signature file missing"}), nil
	}
	var ck Checkpoint
	if err := json.Unmarshal(cb, &ck); err != nil {
		return findings, err
	}
	if err := trust.Verify(ck.AuthorityID, cb, strings.TrimSpace(string(sig))); err != nil {
		findings = append(findings, Finding{"checkpoint", "signature: " + err.Error()})
	}
	listed := false
	var rh2 []merkle.Hash
	for _, sr := range ck.Segments {
		h, _ := merkle.Parse(sr.Root)
		rh2 = append(rh2, h)
		if sr.SegmentID == b.Record.SegmentID && sr.Root == b.SegmentRoot {
			listed = true
		}
	}
	if !listed {
		findings = append(findings, Finding{"checkpoint", "does not list this segment root"})
	}
	if merkle.Root(rh2).String() != ck.Root {
		findings = append(findings, Finding{"checkpoint", "root differs from its listed segment roots"})
	}
	if b.DailyFile != "" {
		db, err := os.ReadFile(filepath.Join(bundleDir, b.DailyFile))
		dsig, err2 := os.ReadFile(filepath.Join(bundleDir, b.DailyFile+".sig"))
		if err != nil || err2 != nil {
			return append(findings, Finding{"daily", "daily root or its signature missing"}), nil
		}
		var dk Checkpoint
		if json.Unmarshal(db, &dk) != nil {
			return append(findings, Finding{"daily", "unparseable"}), nil
		}
		if err := trust.Verify(dk.AuthorityID, db, strings.TrimSpace(string(dsig))); err != nil {
			findings = append(findings, Finding{"daily", "signature: " + err.Error()})
		}
		covered := false
		for i, id := range dk.Checkpoints {
			if id == ck.CheckpointID && dk.CheckpointHashes[i] == evidence.Hash(cb) {
				covered = true
			}
		}
		if !covered {
			findings = append(findings, Finding{"daily", "daily root does not cover this checkpoint's exact bytes"})
		}
	}
	if len(findings) == 0 {
		return nil, nil
	}
	return findings, errors.New("bundle does not verify")
}
