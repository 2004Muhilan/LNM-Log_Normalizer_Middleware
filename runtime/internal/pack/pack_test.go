package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	sig[0] ^= 0x0f
	if sig[0] == 'g' || sig[0] > 'f' && sig[0] < 'a' { // keep it hex
		sig[0] = '0'
	}
	os.WriteFile(filepath.Join(d, "pack.json.sig"), sig, 0o644)
	if _, err := Load(d, base); err == nil {
		t.Fatal("corrupted signature must refuse")
	}
	// development escape hatch loads, but says so
	d = copyPack(t, golden)
	os.Remove(filepath.Join(d, "pack.json.sig"))
	p, err = Load(d, LoadOptions{ContractsDir: base.ContractsDir, PinnedIndex: base.PinnedIndex, AllowUnsigned: true})
	if err != nil || p.SignatureVerified {
		t.Fatalf("allow-unsigned must load without claiming verification: %v", err)
	}
}
