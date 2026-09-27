package pipeline

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/pack"
)

// formatPack builds, in memory, a one-family pack around a spec: the three formats added with parser-spec 1.2.0 and
// normalized-event 1.4.0 each get one, exactly as cefPack does for CEF.
func formatPack(t *testing.T, id, l1, l2, spec string, timePath, srcPath, dstPath string) *pack.Pack {
	t.Helper()
	prog, err := dsl.Compile([]byte(spec))
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	p := &pack.Pack{PackID: id, PackVersion: "1.0"}
	p.Source.SourceID, p.Source.Vendor, p.Source.Product = id+"-01", "Acme", id
	p.OCSF.Version = "1.3.0"
	p.Time.TimezoneConfidence = "unresolved"
	p.CategoryUIDs = map[int]int64{4001: 4}
	var f pack.Family
	f.FamilyID, f.EventClassUID = id+"-events", 4001
	f.Routing.L1, f.Routing.L2 = l1, l2
	f.Parser.SpecID, f.Parser.DSLHash, f.Parser.ParserHash = id, prog.DSLHash, prog.ParserHash()
	f.Program = prog
	prov := json.RawMessage(`{"category":"vendor_schema_or_device_configuration"}`)
	f.Mapping.MappingVersion = "1.0"
	f.Mapping.Fields = []pack.MappingField{
		{Path: timePath, OCSFAttribute: "time", Mandatory: true, Provenance: prov},
		{Path: srcPath, OCSFAttribute: "src_endpoint.ip", Mandatory: true, Provenance: prov},
		{Path: dstPath, OCSFAttribute: "dst_endpoint.ip", Mandatory: true, Provenance: prov},
		{Constant: 1, OCSFAttribute: "action_id", Mandatory: true, Provenance: prov},
	}
	f.Mapping.Acceptance.MandatoryAttributes = []string{"time", "src_endpoint.ip", "dst_endpoint.ip", "action_id"}
	p.Families = []pack.Family{f}
	return p
}

const (
	tsCell   = `"kind":"semantic","class":"integer","coerce":{"op":"coerce","to":"timestamp","on_failure":"reject","format":{"kind":"epoch_auto","timezone":"utc"}}`
	ipCell   = `"kind":"semantic","class":"ip","coerce":{"op":"coerce","to":"ip","on_failure":"reject"}`
	specHead = `"regex_dialect":"re2","bounds":{"max_event_bytes":16384,"max_fields":64,"max_nesting":3,"max_repeat":16},"root":`
)

// One stream, three structured formats, one Squid line and one line nobody can read: JSON and XML payloads route by
// surface to their own parser, LEEF comes out of its envelope (behind a syslog header, with no tag) and its
// attributes are parsed as TAB-separated key=value; every emitted event validates against the contract, the LEEF
// event declares 1.4.0 and carries the header, the others still declare 1.3.0; malformed JSON is quarantined, bytes kept.
func TestJSONXMLAndLEEFRouteParseAndValidate(t *testing.T) {
	squid := loadGoldenPack(t)
	jsonP := formatPack(t, "json-sensor", "raw", "json", `{"schema_version":"1.2.0","spec_id":"json-sensor",`+specHead+
		`{"op":"json","unknown_keys":"opaque","keys":{"ts":{"field":"ts",`+tsCell+`},"src.ip":{"field":"src",`+ipCell+`},"dst.ip":{"field":"dst",`+ipCell+`},"msg":{"field":"msg","kind":"semantic"}}}}`, "ts", "src", "dst")
	xmlP := formatPack(t, "xml-sensor", "raw", "xml", `{"schema_version":"1.2.0","spec_id":"xml-sensor",`+specHead+
		`{"op":"xml","unknown":"opaque","paths":{"flow@ts":{"field":"ts",`+tsCell+`},"flow/src":{"field":"src",`+ipCell+`},"flow/dst":{"field":"dst",`+ipCell+`}}}}`, "ts", "src", "dst")
	leefP := formatPack(t, "leef-gw", "leef", "kv", `{"schema_version":"1.1.0","spec_id":"leef-gw",`+specHead+
		`{"op":"kv","pair_separator":{"char":"\t"},"key_value_separator":"=","quote":null,"escape":"none","key_pattern":"[A-Za-z][A-Za-z0-9_]*","unknown_keys":"opaque","order":"any",
		  "keys":{"devTime":{"field":"ts",`+tsCell+`},"src":{"field":"src",`+ipCell+`},"dst":{"field":"dst",`+ipCell+`},"usrName":{"field":"user","kind":"semantic"}}}}`, "ts", "src", "dst")
	in := `{"ts": 1734567890123, "src": {"ip": "10.0.0.1", "port": 1}, "dst": {"ip": "10.0.0.2"}, "msg": "a \"quoted\" thing"}` + "\n" +
		`<flow ts="1734567890124" proto='tcp'><src>10.0.0.3</src><dst>10.0.0.4</dst><note>x</note></flow>` + "\n" +
		"<134>Dec 19 00:00:00 gw01 LEEF:1.0|Acme|Gate|4.2|login_fail|devTime=1734567890125\tsrc=10.0.0.5\tdst=10.0.0.6\tusrName=alice smith\n" +
		"<134>Dec 19 00:00:00 proxy01 squid[1234]: 1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://x/ - HIER_DIRECT/1.2.3.4 text/html\n" +
		`{"ts": 1734567890126, "src": {"ip": "10.0.0.7"}, "dst": {"ip": "10.0.0.8"}` + "\n"
	var out, q bytes.Buffer
	o := fixedOpts(t, squid, &out, &q)
	o.Pack, o.Packs, o.SourceID = nil, []*pack.Pack{squid, jsonP, xmlP, leefP}, "relay-01"
	st, err := Run(strings.NewReader(in), o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Emitted != 4 || st.Quarantined != 1 || st.Reasons["parse"] != 1 {
		t.Fatalf("stats: %+v\nquarantine: %s", st, q.String())
	}
	if n := validateEvents(t, out.String()); n != 4 {
		t.Fatalf("validated %d events", n)
	}
	// every event names its evidence store since the evidence archive: 1.5.0 (which includes 1.4.0's LEEF envelope). These
	// packs are built in the test, not loaded from a pack.json file, so they carry no file hash and no parser_sha256 (1.6.0
	// is declared only by events of a pack loaded through pack.Load)
	want := map[string][3]any{"json-sensor": {float64(1734567890123), "10.0.0.1", "1.5.0"}, "xml-sensor": {float64(1734567890124), "10.0.0.3", "1.5.0"}, "leef-gw": {float64(1734567890125), "10.0.0.5", "1.5.0"}}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		lin := ev["_lineage"].(map[string]any)
		w, ok := want[lin["parser_id"].(string)]
		if !ok {
			continue
		}
		if ev["time"] != w[0] || ev["src_endpoint"].(map[string]any)["ip"] != w[1] || lin["schema_version"] != w[2] || lin["store_id"] == nil {
			t.Fatalf("%s: time %v src %v version %v", lin["parser_id"], ev["time"], ev["src_endpoint"], lin["schema_version"])
		}
		if lin["parser_id"] == "leef-gw" {
			env := lin["envelope"].(map[string]any)
			if env["kind"] != "leef" || env["signature_id"] != "login_fail" || env["device_vendor"] != "Acme" {
				t.Fatalf("LEEF header must be carried in the envelope record: %v", env)
			}
		}
		delete(want, lin["parser_id"].(string))
	}
	if len(want) != 0 {
		t.Fatalf("no event from: %v", want)
	}
}
