package dsl

import (
	"strings"
	"testing"
)

func structuredSpec(root string) []byte {
	return []byte(`{"schema_version":"1.2.0","spec_id":"t-structured","description":"t","regex_dialect":"re2","bounds":{"max_event_bytes":8192,"max_fields":64,"max_nesting":4,"max_repeat":16},"root":` + root + `}`)
}

// values by path, and the tiling rule: the spans, in order, cover every byte of the input exactly once.
func parseTiled(t *testing.T, root, raw string) (map[string]string, map[string]string, string) {
	t.Helper()
	p, err := Compile(structuredSpec(root))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	m, err := p.Parse([]byte(raw), Env{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Status != "ok" {
		return nil, nil, m.Failure.Reason
	}
	vals, kinds, at := map[string]string{}, map[string]string{}, 0
	for _, s := range m.Spans {
		if s.Start != at || s.End <= s.Start {
			t.Fatalf("spans do not tile: span [%d,%d) after %d", s.Start, s.End, at)
		}
		at = s.End
		if s.Kind != "literal" {
			kinds[s.Path] = s.Kind
			if s.Value != nil {
				vals[s.Path] = *s.Value
			}
		}
	}
	if at != len(raw) {
		t.Fatalf("spans cover %d of %d bytes", at, len(raw))
	}
	return vals, kinds, ""
}

const jsonRoot = `{"op":"json","unknown_keys":"opaque","keys":{
 "ts":{"field":"time","kind":"semantic","class":"integer"},
 "src.ip":{"field":"src_ip","kind":"semantic","class":"ipv4"},
 "src.port":{"field":"src_port","kind":"semantic","coerce":{"op":"coerce","to":"int","on_failure":"reject"}},
 "msg":{"field":"message","kind":"semantic"},
 "tags":{"field":"tags","kind":"semantic"}}}`

func TestJSONOpExtractsDeclaredPathsAndTilesEveryByte(t *testing.T) {
	raw := ` {"ts": 1758350000, "src": {"ip": "10.4.2.17", "port": 443, "asn": 64500}, "msg": "blocked \"x\" é\n", "tags": ["a", {"b": "]"}], "extra": null} `
	vals, kinds, fail := parseTiled(t, jsonRoot, raw)
	if fail != "" {
		t.Fatal(fail)
	}
	want := map[string]string{"time": "1758350000", "src_ip": "10.4.2.17", "src_port": "443", "message": "blocked \"x\" é\n", "tags": `["a", {"b": "]"}]`}
	for k, v := range want {
		if vals[k] != v {
			t.Fatalf("%s = %q, want %q", k, vals[k], v)
		}
	}
	if kinds["unknown.src.asn"] != "opaque" || kinds["unknown.extra"] != "opaque" {
		t.Fatalf("undeclared leaves must be opaque spans: %v", kinds)
	}
}

func TestJSONOpRefusesWhatItCannotStandBehind(t *testing.T) {
	for name, raw := range map[string]string{
		"not an object":      `[1,2]`,
		"trailing bytes":     `{"ts": 1} x`,
		"duplicate declared": `{"ts": 1, "ts": 2}`,
		"bad escape":         `{"msg": "a\q"}`,
		"lone surrogate":     `{"msg": "\ud800"}`,
		"class violation":    `{"src": {"ip": "not-an-ip"}}`,
		"unterminated":       `{"msg": "abc`,
		"missing colon":      `{"ts" 1}`,
	} {
		if _, _, fail := parseTiled(t, jsonRoot, raw); fail == "" {
			t.Fatalf("%s: %q must fail", name, raw)
		}
	}
	reject := strings.Replace(jsonRoot, `"unknown_keys":"opaque"`, `"unknown_keys":"reject"`, 1)
	if _, _, fail := parseTiled(t, reject, `{"ts": 1, "other": 2}`); !strings.Contains(fail, "undeclared") {
		t.Fatalf("unknown_keys reject: %q", fail)
	}
}

const xmlRoot = `{"op":"xml","unknown":"opaque","paths":{
 "Event/System/EventID":{"field":"event_code","kind":"semantic","class":"integer"},
 "Event/System/TimeCreated@SystemTime":{"field":"time","kind":"semantic"},
 "Event/EventData/TargetUserName":{"field":"user","kind":"semantic"},
 "Event/EventData/Note":{"field":"note","kind":"semantic"}}}`

func TestXMLOpExtractsElementsAttributesAndCDATA(t *testing.T) {
	raw := `<?xml version="1.0"?><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><!-- c --><System><EventID>4625</EventID>
  <TimeCreated SystemTime="2026-09-20T06:33:20.042Z"/><Computer>dc01</Computer></System>
  <EventData><TargetUserName> alice </TargetUserName><Note><![CDATA[a <b> & c]]></Note></EventData></Event>
`
	vals, kinds, fail := parseTiled(t, xmlRoot, raw)
	if fail != "" {
		t.Fatal(fail)
	}
	want := map[string]string{"event_code": "4625", "time": "2026-09-20T06:33:20.042Z", "user": "alice", "note": "a <b> & c"}
	for k, v := range want {
		if vals[k] != v {
			t.Fatalf("%s = %q, want %q", k, vals[k], v)
		}
	}
	if kinds["unknown.Event.System.Computer"] != "opaque" || kinds["unknown.Event.xmlns"] != "opaque" {
		t.Fatalf("undeclared text and attributes must be opaque spans: %v", kinds)
	}
}

func TestXMLOpRefusesMalformedAndAmbiguousDocuments(t *testing.T) {
	for name, raw := range map[string]string{
		"mismatched end tag": `<a><b>1</a></b>`,
		"unclosed":           `<Event><System>`,
		"two roots":          `<a>1</a><b>2</b>`,
		"text outside root":  `x<a>1</a>`,
		"repeated declared":  `<Event><System><EventID>1</EventID><EventID>2</EventID></System></Event>`,
		"unquoted attribute": `<Event a=1></Event>`,
		"no root":            `   `,
	} {
		if _, _, fail := parseTiled(t, xmlRoot, raw); fail == "" {
			t.Fatalf("%s: %q must fail", name, raw)
		}
	}
}
