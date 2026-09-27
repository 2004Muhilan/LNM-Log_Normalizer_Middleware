package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
