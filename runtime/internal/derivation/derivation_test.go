package derivation

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/pipeline"
	"ulpf/runtime/internal/tlog"
)

func repo(t *testing.T) string {
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

type fixture struct {
	ev, cdir, trust string
	tlogDir         string
	out             [][]byte
	o               VerifyOptions
	b               BuildOptions
}

// The golden pack over its samples through the real pipeline; the segment committed by a test committer; the pack logged
// in a transparency log of the test's own (its own key), so the test needs nothing local to a machine but the signed
// golden pack and the trust store.
func setup(t *testing.T) *fixture {
	r := repo(t)
	f := &fixture{ev: t.TempDir(), cdir: filepath.Join(t.TempDir(), "commit"), trust: t.TempDir()}
	for _, e := range []string{"ulpf-pack-authority-dev.pub.json"} {
		b, err := os.ReadFile(filepath.Join(r, "keys", "trust", e))
		if err != nil {
			t.Skip("no pack authority in the trust store (scripts/keys-bootstrap.sh)")
		}
		os.WriteFile(filepath.Join(f.trust, e), b, 0o644)
	}
	golden := t.TempDir()
	src := filepath.Join(r, "contracts", "golden", "squid-native")
	filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(golden, rel), 0o755)
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(filepath.Join(golden, rel), b, 0o644)
	})
	seed := make([]byte, 32)
	rand.Read(seed)
	ls, _ := tlog.NewSigner("test-parser-log", seed, 0x01)
	os.WriteFile(filepath.Join(f.trust, "test-parser-log.vkey"), []byte(ls.VerifierKey()+"\n"), 0o644)
	tl := &tlog.Log{Dir: t.TempDir(), Signer: ls}
	if _, _, err := tl.Append(golden, "hand-written"); err != nil {
		t.Fatal(err)
	}
	lo := pack.LoadOptions{ContractsDir: filepath.Join(r, "contracts"), PinnedIndex: filepath.Join(r, "ocsf", "pinned", "index.json"), TrustDir: f.trust}
	p, err := pack.Load(golden, lo)
	if err != nil {
		t.Fatalf("the golden pack, logged in the test's log, must load: %v", err)
	}
	f.tlogDir = tl.Dir
	in, _ := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	var out bytes.Buffer
	if _, err := pipeline.Run(bytes.NewReader(in), pipeline.Options{Pack: p, EvidenceDir: f.ev, Collector: "col-01", Channel: "file:test", Out: &out}); err != nil {
		t.Fatal(err)
	}
	f.out = bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n"))
	key, _ := keys.Generate("ulpf-committer-test")
	key.PublicOnly().Save(filepath.Join(f.trust, key.AuthorityID+".pub.json"))
	pretend := func(dir, seg string) string {
		if st := evidence.SegmentState(dir, seg); st != "sealed" {
			return st
		}
		return "immutable"
	}
	if rep, err := checkpoint.Commit(f.ev, f.cdir, key, pretend, time.Now()); err != nil || len(rep.Committed) == 0 {
		t.Fatalf("commit: %+v %v", rep, err)
	}
	f.o = VerifyOptions{TrustDir: f.trust, ContractsDir: lo.ContractsDir, PinnedIndex: lo.PinnedIndex}
	f.b = BuildOptions{Locator: evidence.NewLocator(f.ev, ""), CommitDir: f.cdir, TLogDir: f.tlogDir, ContractsDir: lo.ContractsDir, PinnedIndex: lo.PinnedIndex}
	return f
}

func (f *fixture) bundle(t *testing.T, i int) *Bundle {
	var ev map[string]any
	json.Unmarshal(f.out[i], &ev)
	o := f.b
	o.EventID, o.Expected = ev["_lineage"].(map[string]any)["event_id"].(string), f.out[i]
	b, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	// through a file, as it travels
	data, _ := json.Marshal(b)
	var back Bundle
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	return &back
}

// The derivation proves: the logged pack, re-run on the committed raw bytes, reproduces the SIEM's event exactly.
func TestDerivationReproducesTheSIEMEvent(t *testing.T) {
	f := setup(t)
	for i := range f.out {
		r := Verify(f.bundle(t, i), f.o)
		if !r.OK {
			t.Fatalf("event %d: %+v", i, r.Steps)
		}
		if r.TLog == nil || r.TLog.Entry.ProducedBy != "hand-written" {
			t.Fatalf("the report names the pack's log entry: %+v", r.TLog)
		}
	}
	if len(Excluded) != 1 {
		t.Fatalf("the exclusion list is one field and stays one: %v", Excluded)
	}
}

// Tampering, each on its own, is caught — and the verifier says which part.
func TestDerivationNamesWhatWasTampered(t *testing.T) {
	f := setup(t)
	// a changed raw byte
	b := f.bundle(t, 1)
	b.Evidence.Raw[5] ^= 0x01
	if r := Verify(b, f.o); r.OK || r.Culprit != "raw bytes" {
		t.Fatalf("a changed raw byte must be named: %s %+v", r.Culprit, r.Steps)
	}
	// a changed pack (one byte of pack.json)
	b = f.bundle(t, 1)
	b.Pack.Files["pack.json"] = bytes.Replace(b.Pack.Files["pack.json"], []byte("ulpf-gen-0.1"), []byte("ulpf-gen-0.2"), 1)
	if r := Verify(b, f.o); r.OK || r.Culprit != "pack" {
		t.Fatalf("a changed pack must be named: %s %+v", r.Culprit, r.Steps)
	}
	// a changed SIEM field
	b = f.bundle(t, 1)
	var ev map[string]any
	json.Unmarshal(b.Expected, &ev)
	ev["src_endpoint"].(map[string]any)["ip"] = "10.66.66.66"
	b.Expected, _ = json.Marshal(ev)
	r := Verify(b, f.o)
	if r.OK || r.Culprit != "SIEM document" || len(r.Differing) != 1 || r.Differing[0].Field != "src_endpoint.ip" {
		t.Fatalf("a changed SIEM field must be named: %s %+v", r.Culprit, r.Differing)
	}
	// the excluded field alone never fails a derivation
	b = f.bundle(t, 1)
	json.Unmarshal(b.Expected, &ev)
	ev["_lineage"].(map[string]any)["processing_time"] = 1
	b.Expected, _ = json.Marshal(ev)
	if r := Verify(b, f.o); !r.OK {
		t.Fatalf("processing_time is excluded: %+v", r.Steps)
	}
	// but a runtime-assigned INPUT is compared: a changed ingest_time is caught
	b = f.bundle(t, 1)
	json.Unmarshal(b.Expected, &ev)
	ev["_lineage"].(map[string]any)["ingest_time"] = 1
	b.Expected, _ = json.Marshal(ev)
	if r := Verify(b, f.o); r.OK || !strings.Contains(r.Differing[0].Field, "ingest_time") {
		t.Fatalf("ingest_time is compared, not excluded: %+v", r.Differing)
	}
}
