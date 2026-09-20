package dsl

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The corpus replay tests (replay_test.go) assert counts and `status == ok`. They compared NO EXTRACTED
// VALUE: every field could have held the wrong substring and they would pass — P4's defect, still present on
// the Go side until the P8 audit (§3.4). This file closes it two ways, neither of which commits corpus text
// (the fixtures are Elastic-licensed and never enter the repository):
//
//  1. an INDEPENDENT ORACLE per vendor extracts the same fields by a different method (a hand-written regex
//     for ASA, encoding/csv for PAN-OS, a separate key=value scanner for FortiGate, strings.Fields for Squid)
//     and every value the spec extracted is compared with it, line by line;
//  2. a DIGEST PIN per case: sha256 over every (path, value) the spec extracted from every line. A digest
//     reveals nothing of the fixture and changes if any extracted value changes; updating it is a reviewed act.
//
// A case with zero parsed lines fails (an empty fixture used to pass as 0 == 0).

func extracted(t *testing.T, p *Program, payload []byte) map[string]string {
	t.Helper()
	sm, err := p.Parse(payload, Env{})
	if err != nil {
		t.Fatal(err)
	}
	if sm.Status != "ok" {
		return nil
	}
	out := map[string]string{}
	for _, s := range sm.Spans {
		if s.Kind != "semantic" || s.Value == nil {
			continue
		}
		if _, seen := out[s.Path]; !seen {
			out[s.Path] = *s.Value
		}
	}
	return out
}

type digester struct{ lines []string }

func (d *digester) add(i int, vals map[string]string) {
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%d", i)
	for _, k := range keys {
		fmt.Fprintf(&b, "\x1f%s\x1e%s", k, vals[k])
	}
	d.lines = append(d.lines, b.String())
}

func (d *digester) sum() string {
	h := sha256.Sum256([]byte(strings.Join(d.lines, "\n")))
	return hex.EncodeToString(h[:])
}

func checkPin(t *testing.T, name string, d *digester, n int, want string) {
	t.Helper()
	if n == 0 {
		t.Fatalf("%s: zero lines parsed — an empty or unmatched fixture must not pass", name)
	}
	if got := d.sum(); got != want {
		t.Fatalf("%s: extracted-value digest over %d lines is %s, pinned %s — some extracted value changed (if intended: review, then update the pin)", name, n, got, want)
	}
}

var (
	// independent of the draft specs: written against the message guide's shape, not copied from the drafts
	oracleBuilt    = regexp.MustCompile(`connection (\d+) for [^:]+:([^/\s]+)/(\d+) \(([^/\s]+)/(\d+)\)(?:\([^()]*\))? to [^:]+:([^/\s]+)/(\d+) \(([^/\s]+)/(\d+)\)`)
	oracleTeardown = regexp.MustCompile(`connection (\d+) for [^:]+:([^/\s]+)/(\d+)(?:\([^()]*\))?(?: [^\s:]+)? to [^:]+:([^/\s]+)/(\d+)`) // a bare user token may follow the port
	oracleNAT      = regexp.MustCompile(`translation from [^:]+:([^/\s]+)/(\d+)(?:\([^()]*\))? to [^:]+:([^/\s]+)/(\d+)`)
	oracleKV       = regexp.MustCompile(`([a-z][a-z0-9_]*)=("(?:[^"\\]|\\.)*"|[^\s"]*)`)
)

func TestReplayValuesASA(t *testing.T) {
	cases := []struct {
		draft  string
		ids    map[string]bool
		oracle *regexp.Regexp
		fields []string // spec field for each oracle group, in order
		pin    string
	}{
		{"asa-302013.json", map[string]bool{"302013": true}, oracleBuilt, []string{"conn_id", "src_host", "src_port", "src_mapped_host", "src_mapped_port", "dst_host", "dst_port", "dst_mapped_host", "dst_mapped_port"}, "689c07e8a9920ff9948e93d58fef5a9c3aeef0ef004a4bdf0a0014a098c2eb5b"},
		{"asa-302015.json", map[string]bool{"302015": true}, oracleBuilt, []string{"conn_id", "src_host", "src_port", "src_mapped_host", "src_mapped_port", "dst_host", "dst_port", "dst_mapped_host", "dst_mapped_port"}, "58c446a73820509a3c973b93040c4572e8aa45ba15c7a2570bb34eaf22980641"},
		{"asa-302014.json", map[string]bool{"302014": true, "302016": true}, oracleTeardown, []string{"conn_id", "src_host", "src_port", "dst_host", "dst_port"}, "dad67fe881c248c2c01d2cedddb6d213671203931d983370e05339f740099b40"},
		{"asa-305011.json", map[string]bool{"305011": true, "305012": true}, oracleNAT, []string{"src_host", "src_port", "dst_host", "dst_port"}, "857e7853f5b4c9c15bea1046baf7e0fa09053b5acdf1f31e8b2c2064dad439af"},
	}
	for _, c := range cases {
		t.Run(c.draft, func(t *testing.T) {
			p := draft(t, c.draft)
			d := &digester{}
			n, compared := 0, 0
			for _, f := range asaFiles {
				for _, l := range corpusLines(t, f) {
					m := asaPayload.FindSubmatch(l)
					if m == nil || !c.ids[string(m[2])] {
						continue
					}
					vals := extracted(t, p, m[1])
					if vals == nil {
						continue // replay_test.go owns the parse-rate expectation
					}
					n++
					d.add(n, vals)
					o := c.oracle.FindSubmatch(m[1])
					if o == nil {
						t.Fatalf("the oracle does not match a line the spec parsed (line %d of the family): the oracle is too narrow — fix it, do not skip", n)
					}
					for i, field := range c.fields {
						if got, want := vals[field], string(o[i+1]); got != want {
							t.Fatalf("line %d: spec extracted %s=%q, the independent oracle reads %q", n, field, got, want)
						}
						compared++
					}
				}
			}
			t.Logf("%s: %d lines, %d values compared with the oracle", c.draft, n, compared)
			checkPin(t, c.draft, d, n, c.pin)
		})
	}
}

func TestReplayValuesPANOS(t *testing.T) {
	p := draft(t, "panos-traffic.json")
	order := specCSVFields(t, "panos-traffic.json") // the draft's cell order (the vendor's field reference); the ORACLE is the splitter: encoding/csv, not the DSL's
	pins := map[string]string{"beats-panw-panos/traffic.log": "8b1c03c91cd5868d2514b6faf763c6b7f392a2d15929d27ea49d4d2f13b2e9e8", "beats-panw-panos/pan_inc_traffic.log": "01dab009d075af9483f9422b871b06a13fee035642b2b6b854ea6ad69ef0b924", "beats-panw-panos/pan_inc_traffic_ietf.log": "ac561cf10d1dc286e86b43e98994c12178a009020e864a35ae32282d0b54acc0"}
	for _, file := range []string{"beats-panw-panos/traffic.log", "beats-panw-panos/pan_inc_traffic.log", "beats-panw-panos/pan_inc_traffic_ietf.log"} {
		t.Run(file, func(t *testing.T) {
			d := &digester{}
			n, compared := 0, 0
			for _, l := range corpusLines(t, file) {
				m := panosPayload.FindSubmatch(l)
				if m == nil {
					t.Fatalf("no payload in a %s line", file)
				}
				vals := extracted(t, p, m[1])
				if vals == nil {
					t.Fatalf("line %d does not parse", n+1)
				}
				n++
				d.add(n, vals)
				r := csv.NewReader(strings.NewReader(string(m[1])))
				r.LazyQuotes, r.FieldsPerRecord = true, -1
				cells, err := r.Read()
				if err != nil {
					t.Fatalf("oracle csv: %v", err)
				}
				for i, field := range order {
					if field == "" || i >= len(cells) {
						continue
					}
					got, has := vals[field]
					if !has {
						continue // empty cell, declared null or opaque: nothing extracted to compare
					}
					if got != cells[i] {
						t.Fatalf("line %d cell %d: spec extracted %s=%q, encoding/csv reads %q", n, i, field, got, cells[i])
					}
					compared++
				}
			}
			t.Logf("%s: %d lines, %d cell values compared with encoding/csv", file, n, compared)
			if compared < n*20 {
				t.Fatalf("only %d values compared over %d lines: the comparison is not reaching the cells", compared, n)
			}
			checkPin(t, file, d, n, pins[file])
		})
	}
}

func TestReplayValuesFortiGate(t *testing.T) {
	p := draft(t, "fortigate-traffic.json")
	d := &digester{}
	n, compared := 0, 0
	for _, l := range corpusLines(t, "beats-fortinet-firewall/traffic.log") {
		payload := priPrefix.ReplaceAll(l, nil)
		vals := extracted(t, p, payload)
		if vals == nil {
			t.Fatalf("line %d does not parse", n+1)
		}
		n++
		d.add(n, vals)
		oracle := map[string]string{}
		for _, m := range oracleKV.FindAllSubmatch(payload, -1) {
			v := string(m[2])
			if strings.HasPrefix(v, `"`) {
				v = strings.ReplaceAll(strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`), `\\`, `\`)
			}
			if _, seen := oracle[string(m[1])]; !seen {
				oracle[string(m[1])] = v
			}
		}
		for k, got := range vals {
			want, has := oracle[k]
			if !has {
				t.Fatalf("line %d: spec extracted key %q that the oracle scanner did not find", n, k)
			}
			if got != want {
				t.Fatalf("line %d: spec extracted %s=%q, the independent scanner reads %q", n, k, got, want)
			}
			compared++
		}
	}
	t.Logf("fortigate: %d lines, %d values compared with the independent scanner", n, compared)
	checkPin(t, "fortigate-traffic", d, n, "2fdd4de4ac990ab327a412bf08ad871ff84964a7be5068c139661e7ce82426bf")
}

func TestReplayValuesSquidNative(t *testing.T) {
	p := goldenSquid(t)
	d := &digester{}
	n, compared := 0, 0
	for _, l := range corpusLines(t, "beats-squid-log/access1.log") {
		vals := extracted(t, p, l)
		if vals == nil {
			continue
		}
		n++
		d.add(n, vals)
		tok := strings.Fields(string(l))
		if len(tok) != 10 {
			t.Fatalf("line %d: %d whitespace tokens", n, len(tok))
		}
		cr, sc, _ := strings.Cut(tok[3], "/")
		hc, srv, _ := strings.Cut(tok[8], "/")
		for field, want := range map[string]string{"time": tok[0], "duration": tok[1], "client_ip": tok[2], "cache_result": cr, "status_code": sc, "reply_bytes": tok[4],
			"method": tok[5], "url": tok[6], "hier_code": hc, "server_ip": srv, "content_type": tok[9]} {
			got, has := vals[field]
			if !has {
				continue // "-" null markers and opaque downgrades carry no value
			}
			if got != want {
				t.Fatalf("line %d: spec extracted %s=%q, strings.Fields reads %q", n, field, got, want)
			}
			compared++
		}
	}
	t.Logf("squid native: %d lines, %d values compared with strings.Fields", n, compared)
	checkPin(t, "squid-native", d, n, "84c06efaf1721416afebafa0cc677ba3138cf36f2a6f157427ba58b3d9e37557")
}

// specCSVFields returns the semantic field name of each csv cell of a draft, "" for opaque cells.
func specCSVFields(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "drafts", "sufficiency", name))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Root struct {
			Fields []struct {
				Field string `json:"field"`
				Kind  string `json:"kind"`
			} `json:"fields"`
		} `json:"root"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || len(doc.Root.Fields) == 0 {
		t.Fatalf("%s: not a csv draft (%v)", name, err)
	}
	out := make([]string, len(doc.Root.Fields))
	for i, f := range doc.Root.Fields {
		if f.Kind == "semantic" {
			out[i] = f.Field
		}
	}
	return out
}

func goldenSquid(t *testing.T) *Program {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir(t), "specs", "squid-native-positional-10.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
