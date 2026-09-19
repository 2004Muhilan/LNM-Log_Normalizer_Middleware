// Package lake is the versioned store of normalized events (invariant 8): historical normalization is
// immutable; a correction emits a NEW version that names the version it derives from. The layout is one
// JSONL file per version with a manifest beside it:
//
//	normalization-v1.jsonl   normalization-v1.manifest.json
//	normalization-v2.jsonl   normalization-v2.manifest.json   (derived_from: 1)
//
// There is no write path to an existing version, by construction of this package's API: the only way to
// obtain a writer is Create, which opens the version file with O_CREATE|O_EXCL (it fails if the version
// exists), requires the version to be exactly latest+1, and on Close fsyncs, drops the write bits and
// records the file's sha256 in a manifest created the same way. Nothing here opens, truncates, renames or
// removes a version file; a static test holds the package to that. Verify recomputes every version's
// hash against its manifest, so "v1 is byte-identical after a correction" is a check, not a claim.
//
// What this is not: kernel-enforced immutability. The files are read-only by mode, which stops this
// process and an honest operator, not root. The evidence log's FS_IMMUTABLE_FL boundary (P5) is the
// mechanism for that and is not applied to the lake (raised in the P8 report).
package lake

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

type Manifest struct {
	Version     int    `json:"normalization_version"`
	DerivedFrom int    `json:"derived_from,omitempty"`
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	Events      int    `json:"events"`
	CreatedAt   int64  `json:"created_at"` // epoch ms
	// Reason says why the version exists: "ingest" for v1; for a correction, what was corrected
	// (the certificate resolved, the pack version that now applies).
	Reason string   `json:"reason"`
	Packs  []string `json:"packs,omitempty"` // pack_id@pack_version of every pack that produced events in this version
}

var reVersion = regexp.MustCompile(`^normalization-v([0-9]+)\.jsonl$`)

func dataPath(dir string, v int) string {
	return filepath.Join(dir, fmt.Sprintf("normalization-v%d.jsonl", v))
}
func manifestPath(dir string, v int) string {
	return filepath.Join(dir, fmt.Sprintf("normalization-v%d.manifest.json", v))
}

// Versions lists the versions present, ascending.
func Versions(dir string) []int {
	ents, _ := os.ReadDir(dir)
	var out []int
	for _, e := range ents {
		if m := reVersion.FindStringSubmatch(e.Name()); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// Writer appends events to a version that did not exist before Create and will not be writable after Close.
type Writer struct {
	dir    string
	m      Manifest
	f      *os.File
	w      *bufio.Writer
	h      hash.Hash
	closed bool
}

// Create starts version `version`. It must be exactly latest+1; version 1 derives from nothing, every
// later version must name an existing version it derives from. It fails if the version already exists.
func Create(dir string, version, derivedFrom int, reason string, now time.Time) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	vs := Versions(dir)
	latest := 0
	if len(vs) > 0 {
		latest = vs[len(vs)-1]
	}
	if version != latest+1 {
		return nil, fmt.Errorf("lake: version %d refused: the next version is %d (existing versions are never reopened)", version, latest+1)
	}
	if version == 1 && derivedFrom != 0 {
		return nil, errors.New("lake: version 1 derives from nothing")
	}
	if version > 1 {
		if derivedFrom < 1 || derivedFrom >= version {
			return nil, fmt.Errorf("lake: version %d must name the existing version it derives from", version)
		}
		if _, err := os.Stat(manifestPath(dir, derivedFrom)); err != nil {
			return nil, fmt.Errorf("lake: derived_from %d has no manifest (it was never closed): %w", derivedFrom, err)
		}
	}
	f, err := os.OpenFile(dataPath(dir, version), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lake: version %d: %w", version, err)
	}
	h := sha256.New()
	return &Writer{dir: dir, f: f, w: bufio.NewWriter(io.MultiWriter(f, h)), h: h,
		m: Manifest{Version: version, DerivedFrom: derivedFrom, File: filepath.Base(f.Name()), Reason: reason, CreatedAt: now.UnixMilli()}}, nil
}

// Write appends bytes (JSONL: the caller writes one event per line). It counts lines as events.
func (w *Writer) Write(b []byte) (int, error) {
	if w.closed {
		return 0, errors.New("lake: version is closed")
	}
	for _, c := range b {
		if c == '\n' {
			w.m.Events++
		}
	}
	return w.w.Write(b)
}

// AddPack records a pack that produced events in this version.
func (w *Writer) AddPack(idAtVersion string) {
	for _, p := range w.m.Packs {
		if p == idAtVersion {
			return
		}
	}
	w.m.Packs = append(w.m.Packs, idAtVersion)
}

// Close seals the version: flush, fsync, drop the write bits, write the manifest (exclusive, read-only).
func (w *Writer) Close() (Manifest, error) {
	if w.closed {
		return w.m, nil
	}
	w.closed = true
	if err := w.w.Flush(); err != nil {
		return w.m, err
	}
	if err := w.f.Sync(); err != nil {
		return w.m, err
	}
	if err := w.f.Chmod(0o444); err != nil {
		return w.m, err
	}
	if err := w.f.Close(); err != nil {
		return w.m, err
	}
	w.m.SHA256 = "sha256:" + hex.EncodeToString(w.h.Sum(nil))
	sort.Strings(w.m.Packs)
	mb, _ := json.MarshalIndent(w.m, "", " ")
	mf, err := os.OpenFile(manifestPath(w.dir, w.m.Version), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return w.m, err
	}
	if _, err := mf.Write(append(mb, '\n')); err != nil {
		mf.Close()
		return w.m, err
	}
	if err := mf.Sync(); err != nil {
		mf.Close()
		return w.m, err
	}
	return w.m, mf.Close()
}

// ReadManifest returns a version's manifest.
func ReadManifest(dir string, v int) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(manifestPath(dir, v))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// Read streams a version's events in order.
func Read(dir string, v int, fn func(line []byte) error) error {
	f, err := os.Open(dataPath(dir, v))
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := fn(append([]byte(nil), sc.Bytes()...)); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Finding is one way a version fails verification.
type Finding struct {
	Version int    `json:"normalization_version"`
	Problem string `json:"problem"`
}

// Verify recomputes every version's sha256 and event count against its manifest and checks the
// derivation chain. No findings means every version is byte-identical to what was sealed.
func Verify(dir string) ([]Manifest, []Finding) {
	var ms []Manifest
	var fs []Finding
	for _, v := range Versions(dir) {
		m, err := ReadManifest(dir, v)
		if err != nil {
			fs = append(fs, Finding{v, "no manifest: the version was never sealed (" + err.Error() + ")"})
			continue
		}
		ms = append(ms, m)
		f, err := os.Open(dataPath(dir, v))
		if err != nil {
			fs = append(fs, Finding{v, err.Error()})
			continue
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			fs = append(fs, Finding{v, err.Error()})
			continue
		}
		n := 0
		if err := Read(dir, v, func([]byte) error { n++; return nil }); err != nil || n != m.Events {
			fs = append(fs, Finding{v, fmt.Sprintf("event count %d, manifest says %d (read error: %v)", n, m.Events, err)})
		}
		if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
			fs = append(fs, Finding{v, fmt.Sprintf("bytes changed since sealing: file hashes to %s, manifest says %s", got, m.SHA256)})
		}
		if m.Version != v {
			fs = append(fs, Finding{v, fmt.Sprintf("manifest names version %d", m.Version)})
		}
		if v > 1 && (m.DerivedFrom < 1 || m.DerivedFrom >= v) {
			fs = append(fs, Finding{v, "derived_from does not name an earlier version"})
		}
		if st, err := os.Stat(dataPath(dir, v)); err == nil && st.Mode().Perm()&0o222 != 0 {
			fs = append(fs, Finding{v, fmt.Sprintf("version file is writable (mode %o)", st.Mode().Perm())})
		}
	}
	return ms, fs
}

// Get returns every version of one event, ascending by version.
func Get(dir, eventID string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for _, v := range Versions(dir) {
		err := Read(dir, v, func(line []byte) error {
			var probe struct {
				L struct {
					EventID string `json:"event_id"`
				} `json:"_lineage"`
			}
			if json.Unmarshal(line, &probe) == nil && probe.L.EventID == eventID {
				out = append(out, json.RawMessage(line))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
