// Package archive is the evidence archive (laptop branch, 2026-09-27; docs/evidence-archive-design.md): the local
// evidence directory is a bounded buffer. The COMMITTER ships — sealed, committed segments and every checkpoint
// covering them, byte-exact, read back and hash-checked against the seal record; a matching read-back is the receipt.
// It reads evidence and writes only to the archive (and its own commit tree); it never modifies or deletes evidence.
// The STORE deletes (Buffer): it holds CAP_LINUX_IMMUTABLE, set the kernel flag and is the only one to clear it —
// and only when every deletion condition holds. Never by age alone.
//
// Protection, stated plainly: the kernel immutable flag (P5) protects only the LOCAL buffer. In the archive,
// tampering is DETECTED by the Merkle proofs and the signed checkpoints (the verifier names the exact event);
// PREVENTING it needs write-once storage (object lock / WORM), which the deployment supplies. The demo's archive is a
// plain folder.
package archive

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/evidence"
)

const ReceiptVersion = "1.0.0"

// Receipt is written into the archive LAST, once every file of the segment and every checkpoint covering it is
// there and its read-back hashes match: its existence is the shipment's completion.
type Receipt struct {
	ReceiptVersion string            `json:"receipt_version"`
	StoreID        string            `json:"store_id"`
	SegmentID      string            `json:"segment_id"`
	Files          map[string]string `json:"files"`       // archived file name -> sha256 of the bytes read back from the archive
	Checkpoints    []string          `json:"checkpoints"` // the minute checkpoints covering the segment, shipped with it
	ShippedAt      int64             `json:"shipped_at"`  // epoch ms
}

// ShipReport is one shipping pass.
type ShipReport struct {
	Shipped     []string          `json:"shipped"`
	Pending     map[string]string `json:"pending"` // segment -> why it is not shipped yet
	CommitFiles int               `json:"commit_files_shipped"`
}

// testHookAfterPut, when set (tests), is called after every file lands in the archive: a crash mid-shipment.
var testHookAfterPut func(dst string) error

// StoreDir is where a store's evidence lives in the archive.
func StoreDir(archive, storeID string) string { return evidence.ArchiveStoreDir(archive, storeID) }

// ReceiptPath is a segment's receipt in the archive.
func ReceiptPath(archive, storeID, segID string) string {
	return filepath.Join(StoreDir(archive, storeID), "receipts", segID+".json")
}

// ReadReceipt reads a segment's receipt (error when there is none).
func ReadReceipt(archive, storeID, segID string) (Receipt, error) {
	var r Receipt
	b, err := os.ReadFile(ReceiptPath(archive, storeID, segID))
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(b, &r)
}

// Ship copies, for the evidence directory dir with its commit tree cdir, every committed segment not yet receipted
// into the archive; the commit tree (checkpoints, daily roots, segment roots) goes first. Idempotent and resumable:
// a file already in the archive with the expected hash is not copied again; a DIFFERENT file under the same name is
// never overwritten — it is reported and that segment is not receipted.
func Ship(dir, cdir, archive string, now time.Time) (ShipReport, error) {
	rep := ShipReport{Pending: map[string]string{}}
	if archive == "" {
		return rep, errors.New("no archive configured")
	}
	if cdir == "" {
		cdir = filepath.Join(dir, "commit")
	}
	storeID := evidence.ReadStoreID(dir)
	if storeID == "" { // the store has not opened yet (the committer may start before the runtime): nothing to ship
		return rep, nil
	}
	base := StoreDir(archive, storeID)
	for _, d := range []string{"segments", "receipts", "commit/segments", "commit/checkpoints", "commit/daily"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			return rep, err
		}
	}
	if _, err := putLocal(filepath.Join(dir, "store.json"), filepath.Join(base, "store.json"), ""); err != nil {
		return rep, err
	}
	// 1. the commit tree: small, signed, append-only — shipped as it appears
	for _, pat := range []string{"checkpoints/ckpt_*.json", "checkpoints/ckpt_*.json.sig", "daily/day_*.json", "daily/day_*.json.sig", "segments/*.root.json"} {
		files, _ := filepath.Glob(filepath.Join(cdir, pat))
		sort.Strings(files)
		for _, f := range files {
			rel, _ := filepath.Rel(cdir, f)
			copied, err := putLocal(f, filepath.Join(base, "commit", rel), "")
			if err != nil {
				return rep, err
			}
			if copied {
				rep.CommitFiles++
			}
		}
	}
	covering := CoveringCheckpoints(cdir)
	// 2. committed segments not yet receipted
	roots, _ := filepath.Glob(filepath.Join(cdir, "segments", "seg_*.root.json"))
	sort.Strings(roots)
	for _, rp := range roots {
		seg := strings.TrimSuffix(filepath.Base(rp), ".root.json")
		if _, err := os.Stat(ReceiptPath(archive, storeID, seg)); err == nil {
			continue
		}
		cks := covering[seg]
		if len(cks) == 0 {
			rep.Pending[seg] = "committed root written, no signed checkpoint lists it yet"
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, seg+evidence.SuffixRaw)); err != nil {
			rep.Pending[seg] = "not in the local buffer and not receipted in the archive: cannot ship (reported, never assumed)"
			continue
		}
		sealB, err := os.ReadFile(filepath.Join(dir, seg+evidence.SuffixSeal))
		if err != nil {
			rep.Pending[seg] = "no seal record"
			continue
		}
		var man evidence.SealManifest
		if err := json.Unmarshal(sealB, &man); err != nil {
			rep.Pending[seg] = "unreadable seal record"
			continue
		}
		want := map[string]string{evidence.SuffixRaw: man.RawSHA256, evidence.SuffixIdx: man.IdxSHA256, evidence.SuffixSeal: evidence.Hash(sealB)}
		files := map[string]string{}
		failed := ""
		for _, suf := range evidence.SegmentSuffixes {
			got, err := putVerified(filepath.Join(dir, seg+suf), evidence.ArchiveSegmentPath(archive, storeID, seg, suf), want[suf])
			if err != nil {
				failed = err.Error()
				break
			}
			files[seg+suf] = got
		}
		if failed != "" {
			rep.Pending[seg] = failed
			continue
		}
		// every checkpoint covering it must be in the archive, byte-identical, before the receipt
		for _, ck := range cks {
			for _, suf := range []string{".json", ".json.sig"} {
				local := filepath.Join(cdir, "checkpoints", ck+suf)
				if ok, why := SameBytes(local, filepath.Join(base, "commit", "checkpoints", ck+suf)); !ok {
					failed = "covering checkpoint " + ck + suf + ": " + why
				}
			}
		}
		if failed != "" {
			rep.Pending[seg] = failed
			continue
		}
		r := Receipt{ReceiptVersion: ReceiptVersion, StoreID: storeID, SegmentID: seg, Files: files, Checkpoints: cks, ShippedAt: now.UnixMilli()}
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := writeAtomic(ReceiptPath(archive, storeID, seg), append(b, '\n')); err != nil {
			return rep, err
		}
		rep.Shipped = append(rep.Shipped, seg)
	}
	return rep, nil
}

// CoveringCheckpoints maps segment -> the minute checkpoints (ids) listing it, from the commit tree.
func CoveringCheckpoints(cdir string) map[string][]string {
	out := map[string][]string{}
	files, _ := filepath.Glob(filepath.Join(cdir, "checkpoints", "ckpt_*.json"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var ck checkpoint.Checkpoint
		if json.Unmarshal(b, &ck) != nil {
			continue
		}
		for _, sr := range ck.Segments {
			out[sr.SegmentID] = append(out[sr.SegmentID], ck.CheckpointID)
		}
	}
	return out
}

// SameBytes reports whether two files exist and hold identical bytes.
func SameBytes(a, b string) (bool, string) {
	ab, err := os.ReadFile(a)
	if err != nil {
		return false, "local copy unreadable: " + err.Error()
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		return false, "not in the archive"
	}
	if evidence.Hash(ab) != evidence.Hash(bb) {
		return false, "the archived copy differs"
	}
	return true, ""
}

// putLocal ships a small file whose expected hash is its own content; returns whether it was copied now.
func putLocal(src, dst, _ string) (bool, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(dst); err == nil {
		if ok, why := SameBytes(src, dst); !ok {
			return false, fmt.Errorf("%s: %s — the archive is never overwritten", dst, why)
		}
		return false, nil
	}
	if _, err := putVerified(src, dst, evidence.Hash(b)); err != nil {
		return false, err
	}
	return true, nil
}

// putVerified copies src to dst byte-exact (temporary name, fsync, rename, fsync of the directory), then reads dst
// back and returns its hash, which must equal want. An existing dst with the expected hash is accepted as it is (a
// resumed shipment); an existing dst with another hash is refused, never overwritten.
func putVerified(src, dst, want string) (string, error) {
	if b, err := os.ReadFile(dst); err == nil {
		if h := evidence.Hash(b); h != want {
			return "", fmt.Errorf("%s already in the archive with %s, expected %s — never overwritten", filepath.Base(dst), h, want)
		}
		return want, nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if h := evidence.Hash(data); h != want {
		return "", fmt.Errorf("local %s hashes to %s, its seal record says %s: not shipped", filepath.Base(src), h, want)
	}
	if err := writeAtomic(dst, data); err != nil {
		return "", err
	}
	if testHookAfterPut != nil {
		if err := testHookAfterPut(dst); err != nil {
			return "", err
		}
	}
	back, err := os.ReadFile(dst)
	if err != nil {
		return "", err
	}
	if h := evidence.Hash(back); h != want {
		return "", fmt.Errorf("%s read back from the archive as %s, expected %s", filepath.Base(dst), h, want)
	}
	return want, nil
}

func writeAtomic(dst string, data []byte) error {
	tmp := dst + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(dst)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
