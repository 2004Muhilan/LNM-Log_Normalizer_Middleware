package dsl

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ulpf/runtime/internal/spanmap"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

func goldenDir(t *testing.T) string {
	return filepath.Join(repoRoot(t), "contracts", "golden", "squid-native")
}

func firstSampleLine(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir(t), "samples", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.SplitN(b, []byte("\n"), 2)[0]
}

func canonJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var anyv any
	_ = json.Unmarshal(b, &anyv)
	out, _ := json.MarshalIndent(anyv, "", " ")
	return string(out)
}

// The engine must reproduce the golden span maps exactly — the trace's Stage 7 (candidate) and the
// promoted parser's map for line 1 — not merely something that tiles.
func TestGoldenSpanMaps(t *testing.T) {
	for _, tc := range []struct{ spec, golden string }{
		{"squid-native-positional-10.json", "line1-promoted.json"},
		{"squid-native-candidate.json", "line1-candidate.json"},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			specBytes, err := os.ReadFile(filepath.Join(goldenDir(t), "specs", tc.spec))
			if err != nil {
				t.Fatal(err)
			}
			prog, err := Compile(specBytes)
			if err != nil {
				t.Fatal(err)
			}
			got, err := prog.Parse(firstSampleLine(t), Env{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != "ok" {
				t.Fatalf("parse failed: %+v", got.Failure)
			}
			gb, err := os.ReadFile(filepath.Join(goldenDir(t), "span-maps", tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			var want spanmap.SpanMap
			if err := json.Unmarshal(gb, &want); err != nil {
				t.Fatal(err)
			}
			// the golden carries test-only event fields the engine does not know
			got.Event.EventID, got.Event.RawBase64, got.DSLHash = want.Event.EventID, want.Event.RawBase64, ""
			got.Sort()
			want.Sort()
			if g, w := canonJSON(t, got), canonJSON(t, &want); g != w {
				t.Fatalf("span map differs from golden\n--- got\n%s\n--- want\n%s", g, w)
			}
		})
	}
}

func TestParserHashIsStableAndCompilerBound(t *testing.T) {
	specBytes, _ := os.ReadFile(filepath.Join(goldenDir(t), "specs", "squid-native-positional-10.json"))
	a, _ := Compile(specBytes)
	b, _ := Compile(specBytes)
	if a.ParserHash() != b.ParserHash() {
		t.Fatal("parser_hash is not deterministic")
	}
	if a.ParserHash() == a.DSLHash {
		t.Fatal("parser_hash must be the compiled representation, not the spec bytes")
	}
	// whitespace-only changes to the spec change dsl_hash but not parser_hash
	reformatted := bytes.ReplaceAll(specBytes, []byte("\n"), []byte("\n "))
	c, err := Compile(reformatted)
	if err != nil {
		t.Fatal(err)
	}
	if c.DSLHash == a.DSLHash || c.ParserHash() != a.ParserHash() {
		t.Fatal("parser_hash should be invariant under spec reformatting while dsl_hash changes")
	}
}

// Invariant 1: the compiler refuses anything outside the closed, bounded, RE2-only DSL.
func TestAdversarialSpecsRejected(t *testing.T) {
	base := `{"schema_version":"1.0.0","spec_id":"adv","regex_dialect":"re2","bounds":{"max_event_bytes":1024,"max_fields":4,"max_nesting":2,"max_repeat":3},"root":%s}`
	cell := `{"field":"a","kind":"semantic"}`
	cases := map[string]string{
		"backreference":         `{"op":"regex","pattern":"(?P<a>x)\\1","captures":{"a":` + cell + `}}`,
		"lookahead":             `{"op":"regex","pattern":"(?P<a>x)(?=y)","captures":{"a":` + cell + `}}`,
		"unknown op":            `{"op":"exec","command":"/bin/sh"}`,
		"unlisted named group":  `{"op":"regex","pattern":"(?P<a>x)(?P<b>y)","captures":{"a":` + cell + `}}`,
		"nested named groups":   `{"op":"regex","pattern":"(?P<a>x(?P<b>y))","captures":{"a":` + cell + `,"b":{"field":"b","kind":"semantic"}}}`,
		"duplicate field":       `[{"op":"regex","pattern":"(?P<a>x)","captures":{"a":` + cell + `}},{"op":"regex","pattern":"(?P<b>y)","captures":{"b":` + cell + `}}]`,
		"nesting over bound":    `{"op":"optional","step":{"op":"optional","step":{"op":"optional","step":{"op":"literal","text":"x"}}}}`,
		"repeat over bound":     `{"op":"repeated","min":0,"max":50,"step":{"op":"literal","text":"x"}}`,
		"opaque with class":     `{"op":"regex","pattern":"(?P<a>x)","captures":{"a":{"field":"a","kind":"opaque","class":"word"}}}`,
		"unknown class":         `{"op":"regex","pattern":"(?P<a>x)","captures":{"a":{"field":"a","kind":"semantic","class":"regex"}}}`,
		"non-consuming root":    `[]`,
		"too many fields":       `{"op":"positional","delimiter":{"whitespace_run":true},"leading_delimiter":"reject","trailing_delimiter":"reject","tail":null,"slots":[{"field":"a","kind":"semantic"},{"field":"b","kind":"semantic"},{"field":"c","kind":"semantic"},{"field":"d","kind":"semantic"},{"field":"e","kind":"semantic"}]}`,
		"bad timestamp pattern": `{"op":"regex","pattern":"(?P<a>x)","captures":{"a":{"field":"a","kind":"semantic","coerce":{"op":"coerce","to":"timestamp","on_failure":"reject","format":{"kind":"pattern","pattern":"%Q"}}}}}`,
	}
	for name, root := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Compile([]byte(strings.Replace(base, "%s", root, 1)))
			if err == nil {
				t.Fatalf("accepted an adversarial spec")
			}
		})
	}
}

func TestEventOverBoundIsAFailedParseNotAnError(t *testing.T) {
	specBytes, _ := os.ReadFile(filepath.Join(goldenDir(t), "specs", "squid-native-positional-10.json"))
	prog, _ := Compile(specBytes)
	big := bytes.Repeat([]byte("a"), prog.Bounds.MaxEventBytes+1)
	m, err := prog.Parse(big, Env{})
	if err != nil || m.Status != "failed" || len(m.Spans) != 0 {
		t.Fatalf("expected a failed span map with no spans, got err=%v status=%s", err, m.Status)
	}
}

func TestEpochAutoWindowRule(t *testing.T) {
	cases := []struct {
		in   string
		prec string
		ok   bool
	}{
		{"1554039772", "s", true}, {"1587230079841464445", "ns", true}, {"1734567890123", "ms", true},
		{"1734567890123456", "us", true}, {"12345", "", false}, {"99999999999", "", false},
	}
	for _, c := range cases {
		ms, prec, err := parseTimestamp(specTS("epoch_auto"), c.in, Env{})
		if (err == nil) != c.ok || prec != c.prec {
			t.Fatalf("%s: got prec=%q err=%v ms=%d", c.in, prec, err, ms)
		}
	}
}

func TestPatternSubsetSingleDigitHour(t *testing.T) {
	f := specTS("pattern")
	f.Pattern = "%d/%b/%Y:%H:%M:%S"
	f.Timezone = "utc"
	ms, _, err := parseTimestamp(f, "29/Jan/2016:6:09:59", Env{})
	if err != nil || ms != 1454047799000 {
		t.Fatalf("got %d %v", ms, err)
	}
}
