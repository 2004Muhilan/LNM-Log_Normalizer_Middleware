package lake

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func seal(t *testing.T, dir string, v, from int, lines ...string) Manifest {
	t.Helper()
	w, err := Create(dir, v, from, "test", time.UnixMilli(1))
	if err != nil {
		t.Fatalf("create v%d: %v", v, err)
	}
	for _, l := range lines {
		if _, err := w.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	m, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func fileHash(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Invariant 8 at the store: there is no way to obtain a writer on an existing version.
func TestNoWritePathToAnExistingVersion(t *testing.T) {
	dir := t.TempDir()
	e1 := `{"_lineage":{"event_id":"ev_1","normalization_version":1}}`
	m1 := seal(t, dir, 1, 0, e1)
	if m1.Events != 1 || m1.SHA256 != fileHash(t, dataPath(dir, 1)) {
		t.Fatalf("manifest does not describe the file: %+v", m1)
	}
	// every attempt to get a writer on v1 again is refused, and says why
	for _, c := range []struct{ v, from int }{{1, 0}, {1, 1}} {
		if w, err := Create(dir, c.v, c.from, "again", time.Now()); err == nil {
			w.Close()
			t.Fatalf("Create(v%d) on an existing version must fail", c.v)
		} else if !strings.Contains(err.Error(), "never reopened") {
			t.Fatalf("refusal must name the reason: %v", err)
		}
	}
	// versions are consecutive and a correction must name what it derives from
	for _, c := range []struct{ v, from int }{{3, 1}, {2, 0}, {2, 2}, {2, 5}} {
		if w, err := Create(dir, c.v, c.from, "bad", time.Now()); err == nil {
			w.Close()
			t.Fatalf("Create(v%d, derived_from %d) must fail", c.v, c.from)
		}
	}
	// a closed writer refuses further writes
	w, err := Create(dir, 2, 1, "correction", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(`{"_lineage":{"event_id":"ev_1","normalization_version":2,"derived_from":1}}` + "\n"))
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("late\n")); err == nil {
		t.Fatal("write after Close must fail")
	}
	// v1 is byte-identical after the correction, by hash against its manifest and against the hash taken before
	if got := fileHash(t, dataPath(dir, 1)); got != m1.SHA256 {
		t.Fatalf("v1 changed: %s != %s", got, m1.SHA256)
	}
	ms, findings := Verify(dir)
	if len(findings) != 0 || len(ms) != 2 || ms[1].DerivedFrom != 1 {
		t.Fatalf("verify: %+v %+v", ms, findings)
	}
	// the version files are read-only by mode (asserted on the mode bits, so it holds for root in a container too)
	for _, p := range []string{dataPath(dir, 1), manifestPath(dir, 1), dataPath(dir, 2)} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm()&0o222 != 0 {
			t.Fatalf("%s must carry no write bit: %v %v", p, st.Mode().Perm(), err)
		}
	}
	// and an unprivileged process cannot open v1 for writing at all. Root bypasses file modes: say so rather than skip silently.
	if os.Geteuid() != 0 {
		if f, err := os.OpenFile(dataPath(dir, 1), os.O_WRONLY|os.O_APPEND, 0); err == nil {
			f.Close()
			t.Fatal("v1 opened for append by an unprivileged process")
		}
	} else {
		t.Log("NOTE: running as root — the open-for-write refusal is NOT exercised (file modes do not bind root); the mode-bit assertion above is")
	}
	// both versions of the event are retrievable
	evs, err := Get(dir, "ev_1")
	if err != nil || len(evs) != 2 || !strings.Contains(string(evs[0]), `"normalization_version":1`) || !strings.Contains(string(evs[1]), `"derived_from":1`) {
		t.Fatalf("get: %v %s", err, evs)
	}
}

// Verify is a check, not a claim: a byte changed behind the API's back is found and named.
func TestVerifyFindsAnAlteredVersion(t *testing.T) {
	dir := t.TempDir()
	seal(t, dir, 1, 0, `{"_lineage":{"event_id":"ev_1"}}`, `{"_lineage":{"event_id":"ev_2"}}`)
	p := dataPath(dir, 1)
	if err := os.Chmod(p, 0o644); err != nil { // what an operator with shell access could do; the API cannot
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	b[5] ^= 1
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := Verify(dir)
	var hash, mode bool
	for _, f := range findings {
		hash = hash || strings.Contains(f.Problem, "bytes changed since sealing")
		mode = mode || strings.Contains(f.Problem, "writable")
	}
	if !hash || !mode {
		t.Fatalf("an altered, writable v1 must be reported on both counts: %+v", findings)
	}
	// and an unsealed version (no manifest) is a finding, not a pass
	dir2 := t.TempDir()
	w, _ := Create(dir2, 1, 0, "ingest", time.Now())
	w.Write([]byte("{}\n"))
	if _, findings := Verify(dir2); len(findings) != 1 || !strings.Contains(findings[0].Problem, "never sealed") {
		t.Fatalf("unsealed version: %+v", findings)
	}
	w.Close()
}

// Static check (invariant 8): the package has exactly two file-creating calls, both exclusive, and
// nothing that could rewrite, truncate, rename or remove a version. A new write path has to get past this.
func TestStaticNoRewritePath(t *testing.T) {
	src, err := os.ReadFile("lake.go")
	if err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAll(src, nil)
	opens := regexp.MustCompile(`os\.OpenFile\([^\n]*`).FindAll(code, -1)
	if len(opens) != 2 {
		t.Fatalf("expected exactly 2 os.OpenFile calls (version file, manifest), found %d", len(opens))
	}
	for _, o := range opens {
		if !strings.Contains(string(o), "os.O_CREATE|os.O_EXCL|os.O_WRONLY") {
			t.Fatalf("a file is opened for writing without O_EXCL: %s", o)
		}
	}
	for _, banned := range []string{"os.WriteFile", "os.Create(", "os.Rename", "os.Remove", "Truncate(", "O_TRUNC", "O_APPEND", "O_RDWR", "os.Chmod("} {
		if strings.Contains(string(code), banned) {
			t.Fatalf("lake.go must not contain %s", banned)
		}
	}
	// the only other package that writes a lake goes through Create: no direct path construction elsewhere
	for _, f := range []string{filepath.Join("..", "pipeline", "renormalize.go"), filepath.Join("..", "..", "cmd", "ulpf-runtime", "main.go")} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`normalization-v`).Match(b) {
			t.Fatalf("%s builds a lake path itself instead of going through the lake package", f)
		}
	}
}
