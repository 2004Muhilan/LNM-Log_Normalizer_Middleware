package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/pack"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

func loadGoldenPack(t *testing.T) *pack.Pack {
	t.Helper()
	root := repoRoot(t)
	p, err := pack.Load(filepath.Join(root, "contracts", "golden", "squid-native"), pack.LoadOptions{ContractsDir: filepath.Join(root, "contracts"), PinnedIndex: filepath.Join(root, "ocsf", "pinned", "index.json"), TrustDir: filepath.Join(root, "keys", "trust")})
	if err != nil {
		t.Fatalf("golden pack must load (regenerate vectors with build_vectors.py if parser_hash changed): %v", err)
	}
	return p
}

func fixedOpts(t *testing.T, p *pack.Pack, out, q *bytes.Buffer) Options {
	now := time.UnixMilli(1734567890481).UTC()
	n := 0
	return Options{Pack: p, EvidenceDir: t.TempDir(), Collector: "col-01", Channel: "file:/var/log/squid/access.log", Out: out, Quarantine: q,
		Now: func() time.Time { return now }, NewID: func(time.Time) string { n++; return "ev_" + strings.Repeat("0", 25) + string(rune('0'+n)) }}
}

func TestGoldenSamplesEndToEnd(t *testing.T) {
	p := loadGoldenPack(t)
	in, err := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	var out, q bytes.Buffer
	st, err := Run(bytes.NewReader(in), fixedOpts(t, p, &out, &q))
	if err != nil {
		t.Fatal(err)
	}
	// six lines: all parse and all are usable. Two carry Squid's "-" for the upstream address
	// (HIER_NONE): dst_endpoint.ip is mapped but absent for that event — a fact, not a defect —
	// and the absence is flagged with its cause (a span exists, so the cause is uncoercible).
	// With the pack declaring "-" as Squid's null marker, the two HIER_NONE/- lines are declared
	// nulls (vendor said "no upstream"), not coercion failures.
	if st.Frames != 6 || st.Emitted != 6 || st.Quarantined != 0 || st.Usable != 6 || st.UnmappedMandatory != 0 || st.AbsentDeclared != 2 || st.AbsentUncoercible != 0 || st.AbsentStructural != 0 {
		t.Fatalf("stats: %+v\n%s", st, q.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var second map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &second)
	absent, _ := second["_lineage"].(map[string]any)["absent"].([]any)
	if len(absent) != 1 || absent[0].(map[string]any)["attribute"] != "dst_endpoint.ip" || absent[0].(map[string]any)["cause"] != "declared_null" {
		t.Fatalf("line 2 should flag dst_endpoint.ip absent (declared_null): %v", second["_lineage"])
	}
	if _, has := second["dst_endpoint"]; has {
		t.Fatalf("line 2 must not carry a guessed dst_endpoint: %v", second["dst_endpoint"])
	}
	first := strings.SplitN(out.String(), "\n", 2)[0]
	var ev map[string]any
	if err := json.Unmarshal([]byte(first), &ev); err != nil {
		t.Fatal(err)
	}
	if ev["class_uid"] != float64(4002) || ev["time"] != float64(1734567890123) {
		t.Fatalf("class/time: %v %v", ev["class_uid"], ev["time"])
	}
	src := ev["src_endpoint"].(map[string]any)
	dst := ev["dst_endpoint"].(map[string]any)
	if src["ip"] != "10.20.14.62" || dst["ip"] != "93.184.216.34" {
		t.Fatalf("endpoints: %v %v", src, dst)
	}
	if ev["activity_id"] != float64(3) || ev["action_id"] != float64(1) {
		t.Fatalf("activity_id/action_id: %v %v", ev["activity_id"], ev["action_id"])
	}
	lin := ev["_lineage"].(map[string]any)
	if lin["raw_hash"] != "sha256:b6bf09bdddc9b70a39a856ee4ed153964dbb91c435e5a64bb7e721fc9ffca00b" || lin["offset"] != float64(0) || lin["length"] != float64(124) {
		t.Fatalf("lineage: %v", lin)
	}
	fr := lin["framing"].(map[string]any)
	if fr["raw_suffix"] != "Cg==" || fr["raw_prefix"] != "" {
		t.Fatalf("framing must carry the literal stripped bytes: %v", fr)
	}
	// OCSF base attributes: derived category/type/metadata, pack-declared severity (P3 boundary)
	if ev["category_uid"] != float64(4) || ev["type_uid"] != float64(400203) || ev["severity_id"] != float64(1) {
		t.Fatalf("base attributes: category=%v type=%v severity=%v", ev["category_uid"], ev["type_uid"], ev["severity_id"])
	}
	if md, ok := ev["metadata"].(map[string]any); !ok || md["version"] != "1.3.0" {
		t.Fatalf("metadata: %v", ev["metadata"])
	}
}

// Invariant 6 (interim): an event whose signature matches no family is quarantined at routing,
// before any parser runs; it is never guessed into a family.
func TestUnknownSignatureQuarantines(t *testing.T) {
	p := loadGoldenPack(t)
	var out, q bytes.Buffer
	in := "this line is not squid at all\n1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://example.com/ - HIER_DIRECT/93.184.216.34 text/html\n"
	st, err := Run(strings.NewReader(in), fixedOpts(t, p, &out, &q))
	if err != nil {
		t.Fatal(err)
	}
	if st.Emitted != 1 || st.Quarantined != 1 || st.Reasons["routing"] != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if !strings.Contains(q.String(), `"stage":"routing"`) {
		t.Fatalf("quarantine record: %s", q.String())
	}
}

// Invariant 3 kill-test: the process dies right after the Nth raw write, before parsing. The
// evidence store must then reconstruct the ingested stream BYTE-EXACTLY (prefix + raw + suffix),
// including the event that was never parsed.
func TestKillAfterRawWriteReconstructsByteExact(t *testing.T) {
	if os.Getenv("ULPF_KILL_HELPER") == "1" {
		return
	}
	p := loadGoldenPack(t)
	in, _ := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	// make the terminators interesting: CRLF on line 2
	in = bytes.Replace(in, []byte("image/png\n"), []byte("image/png\r\n"), 1)
	inPath := filepath.Join(t.TempDir(), "in.log")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	evDir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestKillHelper")
	cmd.Env = append(os.Environ(), "ULPF_KILL_HELPER=1", "ULPF_KILL_INPUT="+inPath, "ULPF_KILL_EVIDENCE="+evDir, "ULPF_KILL_PACK="+p.Dir, "ULPF_KILL_ROOT="+repoRoot(t))
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 137 {
		t.Fatalf("helper should have died with 137, got %v", err)
	}
	got, recs, err := evidence.Reconstruct(evDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 durable records, got %d", len(recs))
	}
	lines := bytes.SplitAfterN(in, []byte("\n"), 4)
	want := append(append(append([]byte{}, lines[0]...), lines[1]...), lines[2]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("reconstruction is not byte-exact\n got=%q\nwant=%q", got, want)
	}
}

func TestKillHelper(t *testing.T) {
	if os.Getenv("ULPF_KILL_HELPER") != "1" {
		t.Skip("helper process only")
	}
	root := os.Getenv("ULPF_KILL_ROOT")
	p, err := pack.Load(os.Getenv("ULPF_KILL_PACK"), pack.LoadOptions{ContractsDir: filepath.Join(root, "contracts"), PinnedIndex: filepath.Join(root, "ocsf", "pinned", "index.json"), TrustDir: filepath.Join(root, "keys", "trust")})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(os.Getenv("ULPF_KILL_INPUT"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, _ = Run(f, Options{Pack: p, EvidenceDir: os.Getenv("ULPF_KILL_EVIDENCE"), Collector: "col-01", Channel: "file:test", Out: &out, FailAfterRawWrite: 3})
	t.Fatal("Run returned; the kill hook did not fire")
}
