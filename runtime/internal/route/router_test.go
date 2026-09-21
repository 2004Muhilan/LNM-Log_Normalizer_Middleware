package route

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/pack"
)

func TestSignatureClassifierMatchesGoldenSketch(t *testing.T) {
	line := []byte("1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://example.com/index.html - HIER_DIRECT/93.184.216.34 text/html")
	_, _, classes := Signature(line)
	want := []string{"float", "integer", "ipv4", "text", "integer", "word", "url", "word", "text", "text"}
	if strings.Join(classes, ",") != strings.Join(want, ",") {
		t.Fatalf("classes %v", classes)
	}
	// CONNECT lines carry host:port, still a url token
	_, _, classes = Signature([]byte("1734567896.010     78 10.20.31.7 TCP_DENIED/403 1893 CONNECT badsite.example:443 - HIER_NONE/- text/html"))
	if classes[6] != "url" {
		t.Fatalf("host:port should classify as url, got %s", classes[6])
	}
}

// ---------------------------------------------------------------- fixtures: four vendors, in memory

func anchor(id, kind, sel string, domain ...string) pack.Anchor {
	var a pack.Anchor
	a.AnchorID, a.Status = id, "active"
	a.Locator.Kind = kind
	switch kind {
	case "pattern":
		a.Locator.Pattern = sel
	case "key":
		a.Locator.Key = sel
	case "slot":
		fmt.Sscanf(sel, "%d", &a.Locator.SlotIndex)
	case "envelope_header":
		a.Locator.HeaderField = sel
	}
	a.Domain.Kind, a.Domain.Values = "enum", domain
	return a
}

func family(id, l1, l2, bucket string, av map[string][]string) pack.Family {
	var f pack.Family
	f.FamilyID, f.EventClassUID = id, 4001
	f.Routing.L1, f.Routing.L2 = l1, l2
	f.Routing.L4.ArityBucket = bucket
	for k, v := range av {
		f.Routing.L3AnchorIDs = append(f.Routing.L3AnchorIDs, k)
		f.Routing.L3AnchorValues = append(f.Routing.L3AnchorValues, pack.AnchorValues{AnchorID: k, Values: v})
	}
	return f
}

func asaPack() *pack.Pack {
	p := &pack.Pack{PackID: "asa"}
	p.Anchors = []pack.Anchor{anchor("asa-message-id", "pattern", `%(?:ASA|FTD|PIX)-(?:[a-z]+-)?[0-7]-(?P<anchor>[0-9]{6})`, "106023", "302013", "302014", "302016", "305011")}
	p.Families = []pack.Family{
		family("asa-302013", "rfc3164", "template", "", map[string][]string{"asa-message-id": {"302013"}}),
		family("asa-302014", "rfc3164", "template", "", map[string][]string{"asa-message-id": {"302014", "302016"}}),
		family("asa-106023", "rfc3164", "template", "", map[string][]string{"asa-message-id": {"106023"}}),
	}
	return p
}

func panosPack() *pack.Pack {
	p := &pack.Pack{PackID: "panos"}
	p.Anchors = []pack.Anchor{anchor("panos-log-type", "slot", "3", "TRAFFIC", "THREAT", "SYSTEM")}
	p.Families = []pack.Family{family("panos-traffic", "rfc3164", "csv", "46-105", map[string][]string{"panos-log-type": {"TRAFFIC"}})}
	return p
}

func fgtPack() *pack.Pack {
	p := &pack.Pack{PackID: "fgt"}
	p.Anchors = []pack.Anchor{anchor("fortigate-type", "key", "type", "traffic", "event", "utm"), anchor("fortigate-subtype", "key", "subtype", "forward", "local", "vpn", "system")}
	p.Families = []pack.Family{family("fortigate-traffic", "rfc3164", "kv", "20-80", map[string][]string{"fortigate-type": {"traffic"}})}
	return p
}

func squidPack() *pack.Pack {
	p := &pack.Pack{PackID: "squid"}
	f := family("positional-10", "raw", "positional", "10", nil)
	f.Routing.L4.TokenClassSequence = []string{"float", "integer", "ipv4", "text", "integer", "word", "url", "literal", "text", "text"}
	f.Routing.L3StructuralLits = []pack.StructuralLiteral{{SlotIndex: 7, Text: "-"}}
	p.Families = []pack.Family{f}
	return p
}

const (
	asaLine   = "%ASA-6-302013: Built outbound TCP connection 11757 for outside:100.66.205.104/80 (100.66.205.104/80) to inside:172.31.98.44/1772 (172.31.98.44/1772)"
	asaTear   = "%ASA-6-302016: Teardown UDP connection 11751 for outside:100.66.205.104/53 to inside:172.31.98.44/60123 duration 0:00:00 bytes 120"
	panosLine = "1,2018/11/30 16:09:07,012801096514,TRAFFIC,end,2049,2018/11/30 16:09:07,192.168.15.207,184.51.253.152,192.168.1.63,184.51.253.152,new_outbound_from_trust,,,apple-maps,vsys1,trust,untrust,ethernet1/2,ethernet1/1,send_to_mac,2018/11/30 16:09:07,22751,1,55113,443,16418,443,0x400053,tcp,allow,7734,1758,5976,36,2018/11/30 15:59:04,586,computer-and-internet-info,0,32091112,0x0,192.168.0.0-192.168.255.255,United States,0,16,20,tcp-fin,0,0,0,0,,PA-220,from-policy,,,0,,0,,N/A,0,0,0,0"
	fgtLine   = `date=2020-04-23 time=01:16:08 devname="testswitch1" devid="somerouterid" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="OPERATIONAL" eventtime=1592961368 srcip=10.10.10.10 srcport=60899 srcintf="srcintfname" srcintfrole="lan" dstip=175.16.199.1 dstport=161 dstintf="dstintfname" dstintfrole="lan" sessionid=155313 proto=17 action="deny" policyid=0 policytype="policy" service="SNMP" dstcountry="Reserved" srccountry="Reserved" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 appcat="unscanned" crscore=30 craction=131072 crlevel="high"`
	squidLine = "1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://example.com/index.html - HIER_DIRECT/93.184.216.34 text/html"
)

func env3164() *frame.Envelope { return &frame.Envelope{Kind: "rfc3164", Hostname: "h"} }

func TestMixedStreamRoutesEachVendorToItsFamily(t *testing.T) {
	r := New(asaPack(), panosPack(), fgtPack(), squidPack())
	if r.Err() != nil {
		t.Fatal(r.Err())
	}
	cases := []struct {
		payload string
		env     *frame.Envelope
		want    string
	}{
		{asaLine, env3164(), "asa/asa-302013"},
		{asaTear, env3164(), "asa/asa-302014"},
		{panosLine, env3164(), "panos/panos-traffic"},
		{fgtLine, env3164(), "fgt/fortigate-traffic"},
		{squidLine, nil, "squid/positional-10"},
		{squidLine, env3164(), "squid/positional-10"}, // raw family: no envelope requirement (P5 test already routes wrapped Squid)
	}
	for _, c := range cases {
		d := r.Route([]byte(c.payload), c.env)
		if d.Family == nil {
			t.Fatalf("%q: quarantined at %s: %s", c.payload[:20], d.Stage, d.Reason)
		}
		if got := d.Pack.PackID + "/" + d.Family.FamilyID; got != c.want {
			t.Fatalf("%q: routed to %s, want %s (sig %s)", c.payload[:20], got, c.want, d.Signature)
		}
		if d.Candidates != 1 {
			t.Fatalf("%q: candidate set %d, want 1", c.payload[:20], d.Candidates)
		}
	}
}

// Invariant 6 exit criterion: an adversarial event built to defeat the anchor lands in quarantine.
// (a) the anchor locates a value OUTSIDE its declared domain -> a drift signal, quarantined;
// (b) a value INSIDE the domain that no family owns -> quarantined as family-discovery input;
// (c) an ASA-shaped payload with no anchor at all -> unknown signature. None of them is ever parsed.
func TestAnchorDefeatingEventsQuarantine(t *testing.T) {
	r := New(asaPack(), panosPack(), fgtPack(), squidPack())
	cases := []struct{ payload, stage, contains string }{
		{"%ASA-6-999999: Built outbound TCP connection 1 for outside:1.1.1.1/80 (1.1.1.1/80) to inside:2.2.2.2/1 (2.2.2.2/1)", "routing_drift", "outside its declared domain"},
		{"%ASA-6-305011: Built dynamic TCP translation from inside:172.31.98.44/1772 to outside:100.66.98.44/8256", "routing", "no onboarded family owns it"},
		{"Built outbound TCP connection 11757 for outside:100.66.205.104/80 (100.66.205.104/80) to inside:172.31.98.44/1772 (172.31.98.44/1772)", "routing", "unknown signature"},
		{strings.Replace(panosLine, ",TRAFFIC,", ",WEIRD,", 1), "routing_drift", "panos-log-type"},
		{strings.Replace(panosLine, ",TRAFFIC,", ",THREAT,", 1), "routing", "family discovery"},
		{strings.Replace(fgtLine, `type="traffic"`, `type="bogus"`, 1), "routing_drift", "fortigate-type"},
		{strings.Replace(fgtLine, `type="traffic"`, `type="utm"`, 1), "routing", "no onboarded family owns it"},
		// a FortiGate line whose type is right but whose pair count is far outside the family's arity bucket
		{`date=2020-04-23 time=01:16:08 type="traffic" subtype="forward"`, "routing", "unknown signature"},
	}
	for _, c := range cases {
		d := r.Route([]byte(c.payload), env3164())
		if d.Family != nil {
			t.Fatalf("%q must quarantine, routed to %s", c.payload[:24], d.Family.FamilyID)
		}
		if d.Stage != c.stage || !strings.Contains(d.Reason, c.contains) {
			t.Fatalf("%q: stage %s reason %q; want %s containing %q", c.payload[:24], d.Stage, d.Reason, c.stage, c.contains)
		}
		if (d.Stage == "routing_drift") != d.Drift {
			t.Fatalf("drift flag must follow the drift stage: %+v", d)
		}
	}
}

// The hard cap and the 2..K case: both quarantine, naming what they saw; anchors — not a tiebreaker —
// are what separates families that share a surface.
func TestCapAndAmbiguousQuarantine(t *testing.T) {
	// five FortiGate families that all own type=traffic: the candidate set is 5 > K
	p := fgtPack()
	for _, sub := range []string{"a", "b", "c", "d"} {
		p.Families = append(p.Families, family("fgt-"+sub, "rfc3164", "kv", "20-80", map[string][]string{"fortigate-type": {"traffic"}}))
	}
	d := New(p).Route([]byte(fgtLine), env3164())
	if d.Family != nil || d.Stage != "routing_cap" || d.Candidates != 5 {
		t.Fatalf("expected cap quarantine with 5 candidates, got %+v", d)
	}
	// two candidates -> ambiguous quarantine naming both
	p = fgtPack()
	p.Families = append(p.Families, family("fortigate-traffic-2", "rfc3164", "kv", "20-80", map[string][]string{"fortigate-type": {"traffic"}}))
	d = New(p).Route([]byte(fgtLine), env3164())
	if d.Family != nil || d.Stage != "routing_ambiguous" || !strings.Contains(d.Reason, "fgt/fortigate-traffic fgt/fortigate-traffic-2") || d.Candidates != 2 {
		t.Fatalf("expected ambiguous quarantine, got %+v", d)
	}
	// when a second anchor (subtype) separates the two families, L3 does it
	p = fgtPack()
	p.Families = append(p.Families, family("fortigate-traffic-local", "rfc3164", "kv", "20-80", map[string][]string{"fortigate-type": {"traffic"}, "fortigate-subtype": {"local"}}))
	p.Families[0].Routing.L3AnchorValues = append(p.Families[0].Routing.L3AnchorValues, pack.AnchorValues{AnchorID: "fortigate-subtype", Values: []string{"forward"}})
	d = New(p).Route([]byte(fgtLine), env3164())
	if d.Family == nil || d.Family.FamilyID != "fortigate-traffic" || d.Candidates != 1 {
		t.Fatalf("subtype anchor should separate the families at L3: %+v", d)
	}
	// two candidates from two packs quarantine the same way
	q := fgtPack()
	q.PackID = "fgt-copy"
	d = New(fgtPack(), q).Route([]byte(fgtLine), env3164())
	if d.Family != nil || d.Stage != "routing_ambiguous" || !strings.Contains(d.Reason, "fgt-copy/") {
		t.Fatalf("cross-pack candidates must quarantine: %+v", d)
	}
}

// Static check (invariant 6): the router never calls a parser, and the pipeline calls exactly one
// parser exactly once — after routing. There is no "try every pack" path anywhere in the runtime.
func TestStaticNoTryAllPath(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`\.Parse\(`).Match(src) || strings.Contains(string(src), "Program") {
		t.Fatal("router.go must not reference any parser program or call Parse")
	}
	pipe, err := os.ReadFile(filepath.Join("..", "pipeline", "pipeline.go"))
	if err != nil {
		t.Fatal(err)
	}
	calls := regexp.MustCompile(`\.Program\.Parse\(`).FindAllIndex(pipe, -1)
	if len(calls) != 1 {
		t.Fatalf("pipeline must call Program.Parse exactly once (found %d)", len(calls))
	}
	// and that single call is on the routed family, after the routing decision
	if !regexp.MustCompile(`(?s)router\.Route(Chain)?\(.*d\.Family\.Program\.Parse\(`).Match(pipe) { // P7: RouteChain is the chain-aware entry
		t.Fatal("the single Parse call must be on the family the router chose, after Route")
	}
	// P8: the correction path (renormalize.go) is the runtime's only other parser call site, and it is held to the
	// same rule — exactly one Parse, on the family the router chose, after the routing decision.
	ren, err := os.ReadFile(filepath.Join("..", "pipeline", "renormalize.go"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(regexp.MustCompile(`\.Program\.Parse\(`).FindAllIndex(ren, -1)); n != 1 {
		t.Fatalf("renormalize.go must call Program.Parse exactly once (found %d)", n)
	}
	if !regexp.MustCompile(`(?s)router\.RouteChain\(.*d\.Family\.Program\.Parse\(`).Match(ren) {
		t.Fatal("renormalize.go: the single Parse call must be on the routed family, after RouteChain")
	}
	// and no other non-test file of the pipeline package calls a parser at all
	files, _ := filepath.Glob(filepath.Join("..", "pipeline", "*.go"))
	for _, f := range files {
		base := filepath.Base(f)
		if strings.HasSuffix(base, "_test.go") || base == "pipeline.go" || base == "renormalize.go" {
			continue
		}
		b, _ := os.ReadFile(f)
		if regexp.MustCompile(`\.Parse\(`).Match(b) {
			t.Fatalf("%s calls a parser: only pipeline.go and renormalize.go may, once each, after routing", base)
		}
	}
	// no loop over packs or families reaches a Parse
	if regexp.MustCompile(`(?s)for _, [a-z]+ := range [a-zA-Z.]*(Packs|Families)[^\n]*\n[^\n]*Parse`).Match(pipe) {
		t.Fatal("a loop over packs/families followed by Parse is a try-all path")
	}
}

// L2 detection is a surface reading, deterministic and ordered.
func TestDetectL2(t *testing.T) {
	cases := map[string]string{
		`{"a":1}`: "json", fgtLine: "kv", panosLine: "csv", squidLine: "tokens", asaLine: "tokens",
		`a=1 b=2`: "tokens", // two pairs are not enough to call it kv
		"x,y,z":   "tokens", // a few commas are not a csv record
	}
	for in, want := range cases {
		if got := detectL2([]byte(in)).l2; got != want {
			t.Fatalf("%q: %s, want %s", in[:min(len(in), 20)], got, want)
		}
	}
	if n := detectL2([]byte(panosLine)).arity; n != 65 {
		t.Fatalf("PAN-OS 8.1 record has 65 cells, counted %d", n)
	}
	if kv := detectL2([]byte(fgtLine)); kv.pairs["devname"] != "testswitch1" || kv.arity != 35 {
		t.Fatalf("kv surface: %d pairs, devname=%q", kv.arity, kv.pairs["devname"])
	}
}

// Laptop branch (narrows the P6 L1 decision): a `raw` family imposes no requirement on a RELAY's syslog header, but it does
// not own a payload that arrived inside an APPLICATION envelope (CEF, LEEF) — that envelope names the format. Without this, a
// bare key=value family and a LEEF family of the same pair count were two candidates for every LEEF line: quarantined.
func TestRawFamilyDoesNotOwnWhatArrivedInAnApplicationEnvelope(t *testing.T) {
	p := &pack.Pack{PackID: "src"}
	p.Families = []pack.Family{family("bare-kv-3", "raw", "kv", "3", nil), family("leef-kv-3", "leef", "kv", "3", nil)}
	r := New(p)
	payload := []byte("a=1\tb=2\tc=3")
	leef := frame.Chain{Envelopes: []frame.Envelope{{Kind: "leef"}}}
	if d := r.RouteChain(payload, leef); d.Family == nil || d.Family.FamilyID != "leef-kv-3" {
		t.Fatalf("inside a LEEF header: %+v", d)
	}
	if d := r.RouteChain(payload, frame.Chain{}); d.Family == nil || d.Family.FamilyID != "bare-kv-3" {
		t.Fatalf("bare: %+v", d)
	}
	relayed := frame.Chain{Envelopes: []frame.Envelope{{Kind: "rfc3164", Hostname: "relay"}}}
	if d := r.RouteChain(payload, relayed); d.Family == nil || d.Family.FamilyID != "bare-kv-3" {
		t.Fatalf("a relay's syslog header is still no requirement for a raw family: %+v", d)
	}
}
