package contracts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vector struct {
	Kind        string          `json:"kind"`
	Path        string          `json:"path"`
	Expect      string          `json:"expect"`
	ReasonMatch json.RawMessage `json:"reason_match"`
}

func (v vector) matches() []string {
	if len(v.ReasonMatch) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(v.ReasonMatch, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(v.ReasonMatch, &many)
	return many
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func newLoader(t *testing.T) *Loader {
	t.Helper()
	root := repoRoot(t)
	l, err := NewLoader(filepath.Join(root, "contracts"), filepath.Join(root, "ocsf", "pinned", "index.json"))
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	return l
}

func TestGoldenVectors(t *testing.T) {
	root := repoRoot(t)
	l := newLoader(t)
	raw, err := os.ReadFile(filepath.Join(root, "contracts", "golden", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	for _, v := range idx.Vectors {
		t.Run(v.Path, func(t *testing.T) {
			_, err := l.Load(Kind(v.Kind), filepath.Join(root, "contracts", "golden", filepath.FromSlash(v.Path)))
			if v.Expect == "valid" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected the vector to be rejected")
			}
			msg := err.Error()
			for _, m := range v.matches() {
				if strings.Contains(msg, m) {
					return
				}
			}
			t.Fatalf("rejected, but no reason matched %v:\n%s", v.matches(), msg)
		})
	}
}

func TestUnknownVersionIsRefusedBeforeAnythingElse(t *testing.T) {
	l := newLoader(t)
	for _, k := range Kinds {
		errs := l.Validate(k, map[string]any{"schema_version": "2.0.0"}, "")
		if len(errs) != 1 || !errors.Is(errs[0], ErrUnsupportedVersion) {
			t.Fatalf("%s: expected ErrUnsupportedVersion, got %v", k, errs)
		}
	}
}

func TestRuntimeRegexIsRE2(t *testing.T) {
	// A backreference is the canonical non-RE2 construct; the runtime engine must not accept it.
	l := newLoader(t)
	spec := map[string]any{
		"schema_version": "1.0.0", "spec_id": "re2-check", "regex_dialect": "re2",
		"bounds": map[string]any{"max_event_bytes": json.Number("1024"), "max_fields": json.Number("8"), "max_nesting": json.Number("2"), "max_repeat": json.Number("2")},
		"root": map[string]any{"op": "regex", "pattern": "(?P<a>x)\\1", "captures": map[string]any{"a": map[string]any{"field": "a", "kind": "semantic"}}},
	}
	errs := l.Validate(ParserSpec, spec, "")
	if len(errs) == 0 {
		t.Fatal("backreference accepted — runtime regex engine is not RE2-only")
	}
}
