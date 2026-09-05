package dsl

// First test of P2 (plan): replay the nine sufficiency drafts through the compiler over the corpus
// and compare with the counts P1 recorded. The corpus is git-ignored; these tests skip when it is
// absent. Header stripping below is TEST SCAFFOLDING standing in for envelope unwrap (P5/P7): the
// drafts describe the payload after the syslog header, exactly as P1's checker fed them.

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func corpusLines(t *testing.T, rel string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "corpus", "cache", filepath.FromSlash(rel)))
	if err != nil {
		t.Skipf("corpus not cached (%v); run corpus/tools/fetch_corpus.py", err)
	}
	var out [][]byte
	for _, l := range bytes.Split(b, []byte("\n")) {
		l = bytes.TrimRight(l, "\r")
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}

func draft(t *testing.T, name string) *Program {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "drafts", "sufficiency", name))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return p
}

var asaFiles = []string{"beats-cisco-asa/asa.log", "beats-cisco-asa/additional_messages.log", "beats-cisco-asa/sample.log",
	"beats-cisco-asa/asa-fix.log", "beats-cisco-asa/non-canonical.log", "beats-cisco-asa/hostnames.log", "beats-cisco-asa/not-ip.log"}

var asaPayload = regexp.MustCompile(`(%(?:ASA|FTD|PIX)-(?:[a-z]+-)?\d-(\d{6}).*)$`)

func TestReplayASA(t *testing.T) {
	cases := []struct {
		draft    string
		ids      map[string]bool
		lines    int
		expectOK int
	}{
		{"asa-302013.json", map[string]bool{"302013": true}, 62, 62},
		{"asa-302014.json", map[string]bool{"302014": true, "302016": true}, 81, 81},
		{"asa-106023.json", map[string]bool{"106023": true}, 66, 65}, // one malformed fixture line (stray trailing quote)
		{"asa-305011.json", map[string]bool{"305011": true, "305012": true}, 93, 93},
		{"asa-106100.json", map[string]bool{"106100": true}, 27, 27},
		{"asa-733100.json", map[string]bool{"733100": true}, 5, 5},
	}
	var all [][]byte
	for _, f := range asaFiles {
		all = append(all, corpusLines(t, f)...)
	}
	for _, c := range cases {
		t.Run(c.draft, func(t *testing.T) {
			p := draft(t, c.draft)
			n, ok := 0, 0
			for _, l := range all {
				m := asaPayload.FindSubmatch(l)
				if m == nil || !c.ids[string(m[2])] {
					continue
				}
				n++
				sm, err := p.Parse(m[1], Env{})
				if err != nil {
					t.Fatalf("tiling bug: %v", err)
				}
				if sm.Status == "ok" {
					ok++
				} else if c.expectOK == c.lines {
					t.Errorf("unexpected failure at %d (%s): %s", sm.Failure.AtOffset, sm.Failure.Reason, m[1])
				}
			}
			if n != c.lines || ok != c.expectOK {
				t.Fatalf("lines=%d ok=%d, P1 recorded lines=%d ok=%d", n, ok, c.lines, c.expectOK)
			}
		})
	}
}

var panosPayload = regexp.MustCompile(`(?:^|\s)(\d+,\d{4}[/-]\d\d[/-]\d\d[ T][\d:.]+Z?,.*)$`)

func TestReplayPANOS(t *testing.T) {
	p := draft(t, "panos-traffic.json")
	cases := []struct {
		file     string
		cells    int
		expectOK int
	}{
		{"beats-panw-panos/traffic.log", 65, 100},
		{"beats-panw-panos/pan_inc_traffic.log", 46, 100},
		{"beats-panw-panos/pan_inc_traffic_ietf.log", 75, 100},
		{"beats-panw-panos/traffic_nanos_time.log", 105, 1},
	}
	const declared = 65
	for _, c := range cases {
		t.Run(filepath.Base(c.file), func(t *testing.T) {
			ok := 0
			for _, l := range corpusLines(t, c.file) {
				m := panosPayload.FindSubmatch(l)
				if m == nil {
					t.Fatalf("no payload in %s", l)
				}
				sm, err := p.Parse(m[1], Env{})
				if err != nil {
					t.Fatal(err)
				}
				if sm.Status != "ok" {
					t.Fatalf("failed at %d: %s\n%s", sm.Failure.AtOffset, sm.Failure.Reason, m[1])
				}
				ok++
				// Expected extras = NON-EMPTY cells beyond the 65 declared (an empty cell has no span, by
				// contract); count them with a quoted-aware split of the same payload.
				cells, err := csv.NewReader(bytes.NewReader(m[1])).Read()
				if err != nil {
					t.Fatal(err)
				}
				if len(cells) != c.cells {
					t.Fatalf("quoted-aware split gives %d cells, P1 recorded %d", len(cells), c.cells)
				}
				wantExtras := 0
				for i := declared; i < len(cells); i++ {
					if cells[i] != "" {
						wantExtras++
					}
				}
				extras := 0
				for _, s := range sm.Spans {
					if strings.HasPrefix(s.Path, "extra.") {
						extras++
					}
				}
				if extras != wantExtras {
					t.Fatalf("expected %d non-empty extra cells, got %d", wantExtras, extras)
				}
			}
			if ok != c.expectOK {
				t.Fatalf("ok=%d want %d", ok, c.expectOK)
			}
		})
	}
	// THREAT lines are a different family: the type enum rejects them, they do not silently parse.
	threatOK := 0
	for _, l := range corpusLines(t, "beats-panw-panos/threat.log") {
		m := panosPayload.FindSubmatch(l)
		sm, _ := p.Parse(m[1], Env{})
		if sm.Status == "ok" {
			threatOK++
		}
	}
	if threatOK != 0 {
		t.Fatalf("%d THREAT lines parsed under the TRAFFIC draft", threatOK)
	}
}

// The synthetic line (clearly labelled, never counted in coverage) exercises csv.escape = doubled.
func TestPANOSDoubledQuoteSynthetic(t *testing.T) {
	p := draft(t, "panos-traffic.json")
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "drafts", "sufficiency", "synthetic", "panos-doubled-quote.log"))
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.TrimRight(bytes.SplitN(b, []byte("\n"), 2)[0], "\r")
	sm, err := p.Parse(line, Env{})
	if err != nil {
		t.Fatal(err)
	}
	if sm.Status != "ok" {
		t.Fatalf("failed at %d: %s", sm.Failure.AtOffset, sm.Failure.Reason)
	}
	for _, s := range sm.Spans {
		if s.Path == "rule_name" {
			if s.Value == nil || *s.Value != `rule "quoted" name, with comma` || s.Encoding != "csv-quoted" {
				t.Fatalf("rule_name decoded wrongly: %+v", s)
			}
			return
		}
	}
	t.Fatal("rule_name span not found")
}

var priPrefix = regexp.MustCompile(`^<\d+>`)

func TestReplayFortiGate(t *testing.T) {
	p := draft(t, "fortigate-traffic.json")
	lines := corpusLines(t, "beats-fortinet-firewall/traffic.log")
	if len(lines) != 13 {
		t.Fatalf("expected 13 lines, got %d", len(lines))
	}
	precisions := map[string]int{}
	for _, l := range lines {
		payload := priPrefix.ReplaceAll(l, nil)
		sm, err := p.Parse(payload, Env{})
		if err != nil {
			t.Fatal(err)
		}
		if sm.Status != "ok" {
			t.Fatalf("failed at %d: %s\n%s", sm.Failure.AtOffset, sm.Failure.Reason, payload)
		}
		for _, s := range sm.Spans {
			if strings.HasPrefix(s.Path, "unknown.") {
				t.Fatalf("undeclared key reached the parser: %s", s.Path)
			}
			if s.Path == "eventtime" && s.Coerced != nil {
				precisions[s.Coerced.PrecisionSelected]++
			}
		}
	}
	if precisions["s"] == 0 || precisions["ns"] == 0 {
		t.Fatalf("epoch_auto should have selected both s and ns across the file: %v", precisions)
	}
}

func TestReplaySquidCustomLogformat(t *testing.T) {
	p := draft(t, "squid-custom-logformat.json")
	ok, failed := 0, 0
	for _, l := range corpusLines(t, "beats-squid-log/generated.log") {
		sm, err := p.Parse(l, Env{})
		if err != nil {
			t.Fatal(err)
		}
		if sm.Status == "ok" {
			ok++
		} else {
			failed++
		}
	}
	if ok != 97 || failed != 3 {
		t.Fatalf("ok=%d failed=%d; P1 recorded 97/100 with 3 lines belonging to a shorter family", ok, failed)
	}
}

func TestReplaySquidNativeCorpus(t *testing.T) {
	specBytes, _ := os.ReadFile(filepath.Join(goldenDir(t), "specs", "squid-native-positional-10.json"))
	p, _ := Compile(specBytes)
	ok := 0
	lines := corpusLines(t, "beats-squid-log/access1.log")
	for _, l := range lines {
		sm, err := p.Parse(l, Env{})
		if err != nil {
			t.Fatal(err)
		}
		if sm.Status == "ok" {
			ok++
		} else {
			t.Logf("native line failed at %d: %s | %s", sm.Failure.AtOffset, sm.Failure.Reason, l)
		}
	}
	if ok != len(lines) {
		t.Fatalf("golden Squid spec parsed %d/%d real native lines", ok, len(lines))
	}
}
