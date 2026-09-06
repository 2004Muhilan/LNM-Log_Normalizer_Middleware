package pipeline

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/spec"
)

// asaPack builds, in memory, a one-family ASA pack from the committed draft spec (no corpus, no signing):
// an rfc3164-declared template family anchored on the message id, `time` sourced from the envelope
// (parser-pack 1.3.0), the two endpoints and a constant action_id — the minimum the 4001 policy needs.
func asaPack(t *testing.T) *pack.Pack {
	t.Helper()
	specBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "drafts", "sufficiency", "asa-302013.json"))
	if err != nil {
		t.Fatal(err)
	}
	prog, err := dsl.Compile(specBytes)
	if err != nil {
		t.Fatal(err)
	}
	p := &pack.Pack{PackID: "asa-test", PackVersion: "1.0"}
	p.Source.SourceID, p.Source.Vendor, p.Source.Product = "asa-fw-01", "Cisco", "ASA"
	p.OCSF.Version = "1.3.0"
	p.Time.TimezoneConfidence = "unresolved"
	p.CategoryUIDs = map[int]int64{4001: 4}
	var a pack.Anchor
	a.AnchorID, a.Status = "asa-message-id", "active"
	a.Locator.Kind, a.Locator.Pattern = "pattern", `%(?:ASA|FTD|PIX)-(?:[a-z]+-)?[0-7]-(?P<anchor>[0-9]{6})`
	a.Domain.Kind, a.Domain.Values = "enum", []string{"302013", "302014"}
	p.Anchors = []pack.Anchor{a}
	var f pack.Family
	f.FamilyID, f.EventClassUID = "asa-302013", 4001
	f.Routing.L1, f.Routing.L2 = "rfc3164", "template"
	f.Routing.L3AnchorIDs = []string{"asa-message-id"}
	f.Routing.L3AnchorValues = []pack.AnchorValues{{AnchorID: "asa-message-id", Values: []string{"302013"}}}
	f.Parser.SpecID, f.Parser.DSLHash, f.Parser.ParserHash = "asa-302013", prog.DSLHash, prog.ParserHash()
	f.Program = prog
	prov := json.RawMessage(`{"category":"vendor_schema_or_device_configuration"}`)
	f.Mapping.MappingVersion = "1.0"
	f.Mapping.Fields = []pack.MappingField{
		{EnvelopeField: "timestamp", OCSFAttribute: "time", Mandatory: true, Provenance: prov,
			Transform: &pack.Transform{Kind: "timestamp", Format: mustTS(`{"kind":"rfc3164","assume_year":"ingest","timezone":"source"}`)}},
		{Path: "src_host", OCSFAttribute: "src_endpoint.ip", Mandatory: true, Provenance: prov},
		{Path: "dst_host", OCSFAttribute: "dst_endpoint.ip", Mandatory: true, Provenance: prov},
		{Path: "conn_id", OCSFAttribute: "connection_info.uid", Provenance: prov},
		{Constant: 1, OCSFAttribute: "action_id", Mandatory: true, Provenance: prov},
	}
	f.Mapping.Acceptance.MandatoryAttributes = []string{"time", "src_endpoint.ip", "dst_endpoint.ip", "action_id"}
	p.Families = []pack.Family{f}
	return p
}

func mustTS(s string) *spec.TSFormat {
	var f spec.TSFormat
	_ = json.Unmarshal([]byte(s), &f)
	return &f
}

// A mixed stream — syslog-wrapped Squid, relay-form ASA, an anchor-defeating ASA line — through one
// runtime with two packs loaded: every event routes by the DAG to its own family, the adversarial line
// is quarantined as a drift signal without any parser running, the evidence record names the stream's
// source, the ML feature tuple is emitted per event and validates against the draft contract shape.
func TestMixedStreamTwoPacksRoutesQuarantinesAndEmitsML(t *testing.T) {
	squid := loadGoldenPack(t)
	asa := asaPack(t)
	in := strings.Join([]string{
		"<134>Dec 19 00:00:00 proxy01 squid[1234]: 1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://example.com/index.html - HIER_DIRECT/93.184.216.34 text/html",
		"Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-302013: Built outbound TCP connection 11757 for outside:100.66.205.104/80 (100.66.205.104/80) to inside:172.31.98.44/1772 (172.31.98.44/1772)",
		"Oct 10 2018 12:34:57 localhost CiscoASA[999]: %ASA-6-999999: Built outbound TCP connection 1 for outside:1.1.1.1/80 (1.1.1.1/80) to inside:2.2.2.2/1 (2.2.2.2/1)",
		"Oct 10 2018 12:34:58 localhost CiscoASA[999]: %ASA-6-302014: Teardown TCP connection 11749 for outside:100.66.211.242/80 to inside:172.31.98.44/1758 duration 0:01:07 bytes 38110 TCP Reset-I",
	}, "\n") + "\n"
	var out, q, ml bytes.Buffer
	o := fixedOpts(t, nil, &out, &q)
	o.Packs = []*pack.Pack{squid, asa}
	o.SourceID = "relay-01"
	o.ML = &ml
	st, err := Run(strings.NewReader(in), o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frames != 4 || st.Emitted != 2 || st.Quarantined != 2 || st.DriftSignals != 1 || st.MLRecords != 2 {
		t.Fatalf("stats: %+v\n%s", st, q.String())
	}
	if st.Reasons["routing_drift"] != 1 || st.Reasons["routing"] != 1 {
		t.Fatalf("quarantine reasons: %v", st.Reasons)
	}
	if st.CandidateSets["1"] != 2 || st.CandidateSets["0"] != 2 {
		t.Fatalf("candidate-set distribution: %v", st.CandidateSets)
	}
	if st.ByFamily["squid-native/positional-10"] != 1 || st.ByFamily["asa-test/asa-302013"] != 1 {
		t.Fatalf("by family: %v", st.ByFamily)
	}
	// the in-domain-but-unowned message id (302014) is family-discovery input, not drift
	if !strings.Contains(q.String(), "no onboarded family owns it") || !strings.Contains(q.String(), "outside its declared domain") {
		t.Fatalf("quarantine records: %s", q.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var asaEv map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &asaEv); err != nil {
		t.Fatal(err)
	}
	lin := asaEv["_lineage"].(map[string]any)
	if lin["source_id"] != "asa-fw-01" || lin["family_id"] != "asa-302013" {
		t.Fatalf("lineage names the routed pack's source and family: %v", lin)
	}
	// time came from the envelope (relay form with a year): 2018-10-10T12:34:56 in the source zone (UTC here)
	if asaEv["time"].(float64) != 1539174896000 {
		t.Fatalf("envelope-sourced time: %v", asaEv["time"])
	}
	// ML tuple
	mls := strings.Split(strings.TrimSpace(ml.String()), "\n")
	var rec map[string]any
	if err := json.Unmarshal([]byte(mls[1]), &rec); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec["template_id"].(string), "asa-test/asa-302013@sha256:") || rec["timestamp"].(float64) != 1539174896000 {
		t.Fatalf("ml record: %v", rec)
	}
	ents := rec["entity_ids"].(map[string]any)
	if ents["src_ip"] != "100.66.205.104" || ents["dst_ip"] != "172.31.98.44" || ents["device"] != "localhost" || ents["session"] != float64(11757) {
		t.Fatalf("entity ids: %v", ents)
	}
	names := rec["parameter_names"].([]any)
	vec := rec["parameter_vector"].([]any)
	if len(names) != len(vec) || len(names) < 10 {
		t.Fatalf("parameter vector shape: %d names, %d values", len(names), len(vec))
	}
	// optional groups that did not participate are null, not invented
	idx := map[string]int{}
	for i, n := range names {
		idx[n.(string)] = i
	}
	if vec[idx["src_user"]] != nil || vec[idx["conn_id"]] != float64(11757) {
		t.Fatalf("parameter values: src_user=%v conn_id=%v", vec[idx["src_user"]], vec[idx["conn_id"]])
	}
	// the evidence record carries the stream's declared source, not the routed pack's
	if lin["ingest_channel"] == nil {
		t.Fatal("lineage lacks ingest channel")
	}
}

// A mixed stream without a declared source id is refused before anything is written: the evidence
// record cannot name a pack that is only known after routing (raised in the P6 report).
func TestMixedStreamNeedsSourceID(t *testing.T) {
	var out, q bytes.Buffer
	o := fixedOpts(t, nil, &out, &q)
	o.Packs = []*pack.Pack{loadGoldenPack(t), asaPack(t)}
	if _, err := Run(strings.NewReader("x\n"), o); err == nil || !strings.Contains(err.Error(), "source-id") {
		t.Fatalf("expected a source-id error, got %v", err)
	}
}
