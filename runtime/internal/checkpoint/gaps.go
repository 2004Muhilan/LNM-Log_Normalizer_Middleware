package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/gap"
	"ulpf/runtime/internal/keys"
)

// GapEntry is one gap record as the verifier displays it (P7): the record, where it sits, and what
// the commit tree says about it — the leaf's segment root recomputed, the checkpoint that committed
// the segment and whether that checkpoint's signature verifies against the trust store. A gap
// record that is not yet committed is listed as UNCOMMITTED, never hidden.
type GapEntry struct {
	Record       gap.Record `json:"record"`
	EventID      string     `json:"event_id"`
	SegmentID    string     `json:"segment_id"`
	LeafIndex    int        `json:"leaf_index"`
	RawHash      string     `json:"raw_hash"`
	CheckpointID string     `json:"checkpoint_id,omitempty"`
	AuthorityID  string     `json:"authority_id,omitempty"`
	CommitMode   string     `json:"commit_mode,omitempty"`
	Committed    bool       `json:"committed"`
	RootVerified bool       `json:"root_verified"`
	SignatureOK  bool       `json:"signature_ok"`
	Problem      string     `json:"problem,omitempty"`
}

// Gaps lists every gap record in the evidence directory with its commitment status.
func Gaps(dir, cdir string, trust keys.TrustStore) ([]GapEntry, error) {
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	// checkpoint per segment, from the signed checkpoints (the segment root file alone is unsigned)
	type ckInfo struct {
		id, authority, mode, root string
		sigOK                     bool
	}
	bySeg := map[string]ckInfo{}
	files, _ := filepath.Glob(filepath.Join(cdir, "checkpoints", "ckpt_*.json"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var ck Checkpoint
		if json.Unmarshal(b, &ck) != nil {
			continue
		}
		sigB, err := os.ReadFile(f + ".sig")
		sigOK := err == nil && trust.Verify(ck.AuthorityID, b, strings.TrimSpace(string(sigB))) == nil
		for _, sr := range ck.Segments {
			bySeg[sr.SegmentID] = ckInfo{ck.CheckpointID, ck.AuthorityID, ck.Mode(), sr.Root, sigOK}
		}
	}
	var out []GapEntry
	for _, seg := range evidence.Segments(dir) {
		recs, err := evidence.ReadIndex(dir, seg)
		if err != nil {
			return out, err
		}
		raw, err := os.ReadFile(filepath.Join(dir, seg+".raw"))
		if err != nil {
			return out, err
		}
		var rootOK bool
		var rootChecked bool
		for i, r := range recs {
			if r.Framing.Method != evidence.MethodGapRecord {
				continue
			}
			e := GapEntry{EventID: r.EventID, SegmentID: seg, LeafIndex: i, RawHash: r.RawHash}
			if r.Offset+int64(r.Length) <= int64(len(raw)) {
				b := raw[r.Offset : r.Offset+int64(r.Length)]
				if evidence.Hash(b) != r.RawHash {
					e.Problem = "raw bytes do not match the record's raw_hash"
				}
				if rec, err := gap.Parse(b); err == nil {
					e.Record = rec
				} else {
					e.Problem = "unparseable gap record: " + err.Error()
				}
			} else {
				e.Problem = "record exceeds the segment"
			}
			if ck, ok := bySeg[seg]; ok {
				e.Committed, e.CheckpointID, e.AuthorityID, e.CommitMode, e.SignatureOK = true, ck.id, ck.authority, ck.mode, ck.sigOK
				if !rootChecked {
					rootChecked = true
					if leaves, _, err := SegmentLeaves(dir, seg); err == nil {
						rootOK = merkleRootString(leaves) == ck.root
					}
				}
				e.RootVerified = rootOK
			}
			out = append(out, e)
		}
	}
	return out, nil
}
