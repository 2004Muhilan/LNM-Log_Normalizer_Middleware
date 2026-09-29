package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Parser Transparency Log, both loading paths of the runtime: an UNLOGGED pack (validly signed, no inclusion proof)
// stops the runtime at startup, and pushed to a running runtime by hot reload (SIGHUP — the path onboarding and
// auto-heal use) it is refused, the running packs stay, and the refusal is a `pack_refused` record in the evidence log.
func TestUnloggedPackIsRefusedAtStartupAndOnReload(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	bin := filepath.Join(t.TempDir(), "ulpf-runtime")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	golden := filepath.Join(root, "contracts", "golden", "squid-native")
	unlogged := t.TempDir()
	filepath.Walk(golden, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(golden, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(unlogged, rel), 0o755)
		}
		if rel == "pack.json.tlog-proof" {
			return nil // signed, but never logged
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(filepath.Join(unlogged, rel), b, 0o644)
	})
	env := append(os.Environ(), "ULPF_ROOT="+root)
	// startup
	cmd := exec.Command(bin, "run", "--dev-no-evidence-archive", "--pack", unlogged, "--input", filepath.Join(golden, "samples", "access.log"), "--evidence", filepath.Join(t.TempDir(), "ev"), "--out", os.DevNull)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "not in the parser transparency log") {
		t.Fatalf("startup with an unlogged pack must fail: %v\n%s", err, out)
	}
	// hot reload
	ev, packs := filepath.Join(t.TempDir(), "ev"), filepath.Join(t.TempDir(), "packs.txt")
	os.WriteFile(packs, nil, 0o644)
	stderr := &syncBuf{b: &bytes.Buffer{}}
	cmd = exec.Command(bin, "run", "--dev-no-evidence-archive", "--pack", golden, "--packs-file", packs, "--listen", "tcp:127.0.0.1:0", "--evidence", ev, "--out", os.DevNull)
	cmd.Env, cmd.Stderr = env, stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	// a deadline, not a count: returns the moment the line appears. The failures under the gate's load (2026-09-29/30) were
	// NOT a slow reload: the SIGHUP below arrives right after "listening", before the pipeline was live, and the runtime
	// dropped it — nothing was ever printed. Fixed in main.go (the reloader waits for the live pipeline; the signal stays
	// queued); this test is what caught it.
	wait := func(s string) bool {
		for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			if strings.Contains(stderr.String(), s) {
				return true
			}
		}
		return false
	}
	if !wait("listening for syslog over TCP") {
		t.Fatalf("runtime did not start: %s", stderr.String())
	}
	os.WriteFile(packs, []byte(unlogged+"\n"), 0o644)
	cmd.Process.Signal(syscall.SIGHUP)
	if !wait("reload REFUSED") || !strings.Contains(stderr.String(), "not in the parser transparency log") {
		t.Fatalf("the reload must be refused by the log: %s", stderr.String())
	}
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	idx, _ := filepath.Glob(filepath.Join(ev, "seg_*.idx.jsonl"))
	found := false
	for _, f := range idx {
		b, _ := os.ReadFile(f)
		raw, _ := os.ReadFile(strings.TrimSuffix(f, ".idx.jsonl") + ".raw")
		found = found || (strings.Contains(string(b), "gap_record") && strings.Contains(string(raw), `"kind":"pack_refused"`))
	}
	if !found {
		t.Fatal("the refusal must be a pack_refused record in the evidence log")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ULPF refuses to start without an evidence archive, and starts with the development override — saying so loudly.
func TestRunRefusesToStartWithoutAnEvidenceArchive(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	bin := filepath.Join(t.TempDir(), "ulpf-runtime")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	golden := filepath.Join(root, "contracts", "golden", "squid-native")
	run := func(extra ...string) (int, string, string) {
		ev := filepath.Join(t.TempDir(), "ev")
		args := append([]string{"run", "--pack", golden, "--input", filepath.Join(golden, "samples", "access.log"), "--evidence", ev, "--out", filepath.Join(t.TempDir(), "out.jsonl")}, extra...)
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "ULPF_ROOT="+root)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, stderr.String(), ev
	}
	code, stderr, ev := run()
	if code != 2 || !strings.Contains(stderr, "REFUSING TO START") || !strings.Contains(stderr, "--evidence-archive") {
		t.Fatalf("without an archive: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(ev); err == nil {
		t.Fatal("a refused start must not have created the evidence directory")
	}
	code, stderr, _ = run("--dev-no-evidence-archive")
	if code != 0 || !strings.Contains(stderr, "WARNING: --dev-no-evidence-archive: NO EVIDENCE ARCHIVE") || !strings.Contains(stderr, `"evidence_archive":"DISABLED`) {
		t.Fatalf("with the development override: exit %d, stderr %q", code, stderr)
	}
	code, stderr, _ = run("--evidence-archive", t.TempDir())
	if code != 0 || strings.Contains(stderr, "WARNING: --dev-no-evidence-archive") || !strings.Contains(stderr, `"evidence_buffer":{`) {
		t.Fatalf("with an archive: exit %d, stderr %q", code, stderr)
	}
}
