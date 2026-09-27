package evidence

// The evidence archive (laptop branch, 2026-09-27): the local evidence directory is a bounded BUFFER. Sealed,
// committed segments are shipped byte-exact to the archive by the committer and deleted locally by the store only
// when every deletion condition holds (internal/archive). Every reader — "Prove it", export, the verifier,
// reconstruct, renormalize — goes through the Locator: the local copy when it is still there, otherwise the
// archived copy. An archived copy is checked against its seal record (CheckSeal) and, per event, against the raw
// hash in its index (the verifier names the exact event whose bytes changed).
//
// Archive layout: <archive>/<store_id>/segments/seg_N.{raw,idx.jsonl,seal.json}
//                 <archive>/<store_id>/commit/{segments,checkpoints,daily}/...   (mirrors the commit tree)
//                 <archive>/<store_id>/receipts/seg_N.json                       (written last: shipment complete)
//                 <archive>/<store_id>/store.json
// Local, kept after deletion: <evidence>/store.json, <evidence>/catalog/seg_N.ids (the event ids a deleted
// segment held — the local event-to-segment index), <evidence>/deleted.jsonl.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SuffixRaw  = ".raw"
	SuffixIdx  = ".idx.jsonl"
	SuffixSeal = ".seal.json"
)

// SegmentSuffixes are a segment's three files, in shipping order (the seal record last).
var SegmentSuffixes = []string{SuffixRaw, SuffixIdx, SuffixSeal}

// ArchiveStoreDir is where one store's evidence lives in the archive.
func ArchiveStoreDir(archive, storeID string) string { return filepath.Join(archive, storeID) }

// ArchiveSegmentPath is the archived copy of one of a segment's files.
func ArchiveSegmentPath(archive, storeID, segID, suffix string) string {
	return filepath.Join(archive, storeID, "segments", segID+suffix)
}

// Locator is the one lookup path for evidence: local first, then the archive.
type Locator struct {
	Dir     string
	Archive string // "" = local only
	StoreID string
}

func NewLocator(dir, archive string) *Locator {
	return &Locator{Dir: dir, Archive: archive, StoreID: ReadStoreID(dir)}
}

// Path returns where a segment file is: ("local"|"archive", path).
func (l *Locator) Path(segID, suffix string) (string, string, error) {
	p := filepath.Join(l.Dir, segID+suffix)
	if _, err := os.Stat(p); err == nil {
		return p, "local", nil
	}
	if l.Archive != "" && l.StoreID != "" {
		a := ArchiveSegmentPath(l.Archive, l.StoreID, segID, suffix)
		if _, err := os.Stat(a); err == nil {
			return a, "archive", nil
		}
	}
	return "", "", fmt.Errorf("%s%s: not in the local evidence buffer%s", segID, suffix, map[bool]string{true: " nor in the archive " + l.Archive, false: " (no archive configured)"}[l.Archive != ""])
}

// ReadFile reads a segment file from wherever it is.
func (l *Locator) ReadFile(segID, suffix string) ([]byte, string, error) {
	p, where, err := l.Path(segID, suffix)
	if err != nil {
		return nil, "", err
	}
	b, err := os.ReadFile(p)
	return b, where, err
}

// Where reports "local", "archive" or "" for a segment's raw file.
func (l *Locator) Where(segID string) string {
	_, w, _ := l.Path(segID, SuffixRaw)
	return w
}

// ReadIndex reads a segment's index records from wherever the index is.
func (l *Locator) ReadIndex(segID string) ([]Record, error) {
	data, _, err := l.ReadFile(segID, SuffixIdx)
	if err != nil {
		return nil, err
	}
	return parseIndex(segID, data)
}

// Manifest reads a segment's seal record from wherever it is.
func (l *Locator) Manifest(segID string) (SealManifest, error) {
	var m SealManifest
	b, _, err := l.ReadFile(segID, SuffixSeal)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// CheckSeal verifies that the raw file and the index (wherever they are) hash to what the seal record says.
func (l *Locator) CheckSeal(segID string) error {
	m, err := l.Manifest(segID)
	if err != nil {
		return err
	}
	raw, wr, err := l.ReadFile(segID, SuffixRaw)
	if err != nil {
		return err
	}
	idx, wi, err := l.ReadFile(segID, SuffixIdx)
	if err != nil {
		return err
	}
	if Hash(raw) != m.RawSHA256 {
		return fmt.Errorf("%s: the %s raw file no longer matches its seal record", segID, wr)
	}
	if Hash(idx) != m.IdxSHA256 {
		return fmt.Errorf("%s: the %s index no longer matches its seal record", segID, wi)
	}
	return nil
}

// Segments lists every segment held locally or in the archive, in order.
func (l *Locator) Segments() []string {
	seen := map[string]bool{}
	for _, s := range Segments(l.Dir) {
		seen[s] = true
	}
	if l.Archive != "" && l.StoreID != "" {
		for _, s := range Segments(filepath.Join(l.Archive, l.StoreID, "segments")) {
			seen[s] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// FindEvent locates an event: the local indexes first, then the local catalogue of shipped-and-deleted segments,
// then (archive configured) the archived indexes. Returns its segment, its record and its leaf index.
func (l *Locator) FindEvent(eventID string) (string, Record, int, error) {
	find := func(seg string) (Record, int, bool) {
		recs, err := l.ReadIndex(seg)
		if err != nil {
			return Record{}, 0, false
		}
		for i, r := range recs {
			if r.EventID == eventID {
				return r, i, true
			}
		}
		return Record{}, 0, false
	}
	for _, seg := range Segments(l.Dir) {
		if r, i, ok := find(seg); ok {
			return seg, r, i, nil
		}
	}
	if seg := CatalogLookup(l.Dir, eventID); seg != "" {
		if r, i, ok := find(seg); ok {
			return seg, r, i, nil
		}
		return seg, Record{}, 0, fmt.Errorf("event %s: the catalogue names %s, which is neither local nor readable in the archive", eventID, seg)
	}
	if l.Archive != "" {
		local := map[string]bool{}
		for _, s := range Segments(l.Dir) {
			local[s] = true
		}
		for _, seg := range l.Segments() {
			if local[seg] {
				continue
			}
			if r, i, ok := find(seg); ok {
				return seg, r, i, nil
			}
		}
	}
	return "", Record{}, 0, fmt.Errorf("event %s not found in %s%s", eventID, l.Dir, map[bool]string{true: " or in the archive", false: ""}[l.Archive != ""])
}

func parseIndex(segID string, data []byte) ([]Record, error) {
	var recs []Record
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("%s index: %w", segID, err)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// ---------------------------------------------------------------- the local catalogue

// WriteCatalog records the event ids a segment holds before its local copy is deleted (fsynced): the local
// event-to-segment index, kept for good (about 30 bytes per event).
func WriteCatalog(dir, segID string, recs []Record) error {
	if err := os.MkdirAll(filepath.Join(dir, "catalog"), 0o755); err != nil {
		return err
	}
	var b bytes.Buffer
	for _, r := range recs {
		b.WriteString(r.EventID)
		b.WriteByte('\n')
	}
	p := filepath.Join(dir, "catalog", segID+".ids")
	f, err := os.Create(p + ".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(b.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(p+".tmp", p)
}

// CatalogLookup returns the deleted segment that held eventID ("" when no catalogue names it).
func CatalogLookup(dir, eventID string) string {
	files, _ := filepath.Glob(filepath.Join(dir, "catalog", "seg_*.ids"))
	needle := []byte(eventID + "\n")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.HasPrefix(b, needle) || bytes.Contains(b, append([]byte{'\n'}, needle...)) {
			return strings.TrimSuffix(filepath.Base(f), ".ids")
		}
	}
	return ""
}

// ---------------------------------------------------------------- leases: a proof in progress

// TakeLease marks a segment as being read for a proof: the store does not delete a leased segment. The lease
// expires by itself after ttl (a reader that dies does not pin a segment forever). Release removes it.
func TakeLease(dir, segID string, ttl time.Duration) (release func()) {
	d := filepath.Join(dir, "leases")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return func() {}
	}
	p := filepath.Join(d, fmt.Sprintf("%s.%d.%d", segID, os.Getpid(), time.Now().UnixNano()))
	if err := os.WriteFile(p, []byte(strconv.FormatInt(time.Now().Add(ttl).UnixMilli(), 10)+"\n"), 0o644); err != nil {
		return func() {}
	}
	return func() { os.Remove(p) }
}

// Leased reports whether an unexpired lease holds the segment.
func Leased(dir, segID string, now time.Time) bool {
	files, _ := filepath.Glob(filepath.Join(dir, "leases", segID+".*"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		ms, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err == nil && ms > now.UnixMilli() {
			return true
		}
	}
	return false
}
