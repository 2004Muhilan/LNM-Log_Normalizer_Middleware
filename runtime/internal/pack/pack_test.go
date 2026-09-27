package pack

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ulpf/runtime/internal/keys"
)

func root(t *testing.T) string {
	if r := os.Getenv("ULPF_ROOT"); r != "" {
		return r
	}
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

func copyPack(t *testing.T, src string) string {
	dst := t.TempDir()
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		if e.IsDir() {
			os.MkdirAll(filepath.Join(dst, e.Name()), 0o755)
			sub, _ := os.ReadDir(filepath.Join(src, e.Name()))
			for _, s := range sub {
				b, _ := os.ReadFile(filepath.Join(src, e.Name(), s.Name()))
				os.WriteFile(filepath.Join(dst, e.Name(), s.Name()), b, 0o644)
			}
			continue
		}
		b, _ := os.ReadFile(filepath.Join(src, e.Name()))
		os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644)
	}
	return dst
}

// Signing is live and fail-closed (P5 exit criterion): a valid signature by a trusted authority loads;
// everything else is refused before any spec is compiled.
func TestPackSignatureFailClosed(t *testing.T) {
	r := root(t)
	golden := filepath.Join(r, "contracts", "golden", "squid-native")
	if _, err := os.Stat(filepath.Join(golden, "pack.json.sig")); err != nil {
		t.Skip("golden pack not signed yet (run contracts/golden/tools/build_vectors.py)")
	}
	base := LoadOptions{ContractsDir: filepath.Join(r, "contracts"), PinnedIndex: filepath.Join(r, "ocsf", "pinned", "index.json"), TrustDir: filepath.Join(r, "keys", "trust")}
	p, err := Load(golden, base)
	if err != nil || !p.SignatureVerified {
		t.Fatalf("signed golden pack must load with the signature verified: %v", err)
	}
	// no trust store configured
	if _, err := Load(golden, LoadOptions{ContractsDir: base.ContractsDir, PinnedIndex: base.PinnedIndex}); err == nil || !strings.Contains(err.Error(), "fail closed") {
		t.Fatalf("no trust store must refuse: %v", err)
	}
	// unknown authority (empty trust store)
	if _, err := Load(golden, LoadOptions{ContractsDir: base.ContractsDir, PinnedIndex: base.PinnedIndex, TrustDir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "not in the trust store") {
		t.Fatalf("unknown authority must refuse: %v", err)
	}
	// missing signature file
	d := copyPack(t, golden)
	os.Remove(filepath.Join(d, "pack.json.sig"))
	if _, err := Load(d, base); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing signature must refuse: %v", err)
	}
	// one byte of pack.json changed in a way the contract still accepts — only the signature can catch it
	d = copyPack(t, golden)
	b, _ := os.ReadFile(filepath.Join(d, "pack.json"))
	tampered := strings.Replace(string(b), "ulpf-gen-0.1", "ulpf-gen-0.1x", 1)
	if tampered == string(b) {
		t.Fatal("test fixture: generator_version not found to tamper")
	}
	os.WriteFile(filepath.Join(d, "pack.json"), []byte(tampered), 0o644)
	if _, err := Load(d, base); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("tampered pack must refuse: %v", err)
	}
	// corrupted signature bytes
	d = copyPack(t, golden)
	sig, _ := os.ReadFile(filepath.Join(d, "pack.json.sig"))
	// `<authority> <hex>`: corrupt one hex digit of the signature (keep it hex)
	s := strings.TrimSpace(string(sig))
	last := s[len(s)-1]
	if last == '0' {
		s = s[:len(s)-1] + "1"
	} else {
		s = s[:len(s)-1] + "0"
	}
	os.WriteFile(filepath.Join(d, "pack.json.sig"), []byte(s+"\n"), 0o644)
	if _, err := Load(d, base); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("corrupted signature must refuse: %v", err)
	}
	// the .sig names an authority the document does not: refused after the bytes verify
	d = copyPack(t, golden)
	b2, _ := os.ReadFile(filepath.Join(d, "pack.json"))
	renamed := strings.Replace(string(b2), "\"authority_id\": \"ulpf-pack-authority-dev\"", "\"authority_id\": \"ulpf-pack-authority-other\"", 1)
	os.WriteFile(filepath.Join(d, "pack.json"), []byte(renamed), 0o644)
	if _, err := Load(d, base); err == nil {
		t.Fatal("a document naming a different authority than its signature must refuse")
	}
	// development escape hatch loads, but says so
	d = copyPack(t, golden)
	os.Remove(filepath.Join(d, "pack.json.sig"))
	p, err = Load(d, LoadOptions{ContractsDir: base.ContractsDir, PinnedIndex: base.PinnedIndex, TrustDir: base.TrustDir, AllowUnsigned: true})
	if err != nil || p.SignatureVerified {
		t.Fatalf("allow-unsigned must load without claiming verification: %v", err)
	}
}

// Parser Transparency Log: a pack loads only with a valid inclusion proof. A copy without its proof is refused; a pack
// changed after it was logged — re-signed, so its SIGNATURE is valid — is refused because its bytes differ from the
// logged entry; the development escape hatch for signatures does not skip the log.
func TestPackMustBeInTheTransparencyLog(t *testing.T) {
	r := root(t)
	golden := filepath.Join(r, "contracts", "golden", "squid-native")
	base := LoadOptions{ContractsDir: filepath.Join(r, "contracts"), PinnedIndex: filepath.Join(r, "ocsf", "pinned", "index.json"), TrustDir: filepath.Join(r, "keys", "trust")}
	p, err := Load(golden, base)
	if err != nil || p.TLog.Log != "ulpf-tlog-dev" || p.TLog.Entry.PackSHA256 != p.FileSHA256 {
		t.Fatalf("the golden pack must load with its log entry: %+v %v", p.TLog, err)
	}
	d := copyPack(t, golden)
	os.Remove(filepath.Join(d, "pack.json.tlog-proof"))
	if _, err := Load(d, base); err == nil || !strings.Contains(err.Error(), "not in the parser transparency log") {
		t.Fatalf("a pack without an inclusion proof must be refused: %v", err)
	}
	if _, err := Load(d, LoadOptions{ContractsDir: base.ContractsDir, PinnedIndex: base.PinnedIndex, TrustDir: base.TrustDir, AllowUnsigned: true}); err == nil {
		t.Fatal("--allow-unsigned must not skip the transparency log")
	}
	// changed after logging, and RE-SIGNED: the signature verifies, the log does not
	d = copyPack(t, golden)
	b, _ := os.ReadFile(filepath.Join(d, "pack.json"))
	changed := strings.Replace(string(b), "ulpf-gen-0.1", "ulpf-gen-0.1x", 1)
	os.WriteFile(filepath.Join(d, "pack.json"), []byte(changed), 0o644)
	k, err := keys.Load(filepath.Join(r, "keys", "dev", "ulpf-pack-authority-dev.json"))
	if err != nil {
		t.Skip("no dev pack authority key (scripts/keys-bootstrap.sh)")
	}
	sig, _ := k.Sign([]byte(changed))
	os.WriteFile(filepath.Join(d, "pack.json.sig"), []byte(k.AuthorityID+" "+sig+"\n"), 0o644)
	if _, err := Load(d, base); err == nil || !strings.Contains(err.Error(), "differ from its logged entry") {
		t.Fatalf("a pack whose bytes differ from its logged entry must be refused: %v", err)
	}
	// a trust store that names no log
	td := t.TempDir()
	for _, f := range []string{"ulpf-pack-authority-dev.pub.json"} {
		bb, _ := os.ReadFile(filepath.Join(base.TrustDir, f))
		os.WriteFile(filepath.Join(td, f), bb, 0o644)
	}
	if _, err := Load(golden, LoadOptions{ContractsDir: base.ContractsDir, PinnedIndex: base.PinnedIndex, TrustDir: td}); err == nil || !strings.Contains(err.Error(), "names no transparency log") {
		t.Fatalf("no log key must refuse: %v", err)
	}
}

// No bypass: a loaded pack exists only through Load. Outside this package nothing constructs a pack.Pack, and every
// program that loads packs (the runtime: startup and hot reload — auto-heal reaches the runtime as a hot reload; the
// bench) calls Load.
func TestEveryPackLoadGoesThroughTheTransparencyCheck(t *testing.T) {
	r := root(t)
	construct := regexp.MustCompile(`(^|[^*\]])pack\.Pack\{|new\(pack\.Pack\)|json\.Unmarshal\([^)]*&[a-zA-Z_]*[pP]ack\b`) // a []*pack.Pack{…} literal holds loaded packs
	loads := 0
	filepath.Walk(filepath.Join(r, "runtime"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.Contains(p, filepath.Join("internal", "pack")) {
			return nil
		}
		b, _ := os.ReadFile(p)
		if construct.Match(b) && strings.Contains(string(b), "internal/pack") {
			t.Errorf("%s constructs a pack.Pack outside pack.Load", p)
		}
		loads += strings.Count(string(b), "pack.Load(")
		return nil
	})
	if loads < 2 {
		t.Fatalf("expected the runtime and the bench to load through pack.Load, found %d call(s)", loads)
	}
}
