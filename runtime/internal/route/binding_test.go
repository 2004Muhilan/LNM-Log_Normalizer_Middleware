package route

import (
	"strings"
	"testing"

	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/pack"
)

// The rehearsal's collision (2026-09-30), in memory: a drafted FortiGate JSON family and a drafted Suricata JSON family,
// both behind an RFC 3164 header, no anchors — one L1–L4 key. Structure-only routing quarantines both as ambiguous;
// routed among the packs bound to the sending peer, each device's line has exactly one owner.
func TestABoundPeerRoutesOnlyAmongItsSourcesPacks(t *testing.T) {
	fgt := &pack.Pack{PackID: "fortigate-lab-01-rfc3164-json-53-traffic", Families: []pack.Family{family("rfc3164-json-53", "rfc3164", "json", "", nil)}}
	ids := &pack.Pack{PackID: "suricata-lab-01-rfc3164-json-20-alert", Families: []pack.Family{family("rfc3164-json-20", "rfc3164", "json", "", nil)}}
	r := New(fgt, ids)
	ch := frame.Chain{Envelopes: []frame.Envelope{{Kind: "rfc3164"}}}
	fline := []byte(`{"date":"2026-09-30","type":"traffic","srcip":"10.10.1.10","action":"deny"}`)
	sline := []byte(`{"timestamp":"2026-09-30T10:00:00.000000+0000","event_type":"alert","src_ip":"10.10.1.10"}`)

	if d := r.RouteChain(fline, ch); d.Family != nil || d.Stage != "routing_ambiguous" {
		t.Fatalf("structure-only routing must find the two families ambiguous, got %+v", d)
	}
	if d := r.RouteChainAmong(fline, ch, map[string]bool{fgt.PackID: true}, "bound to fortigate-lab-01"); d.Pack != fgt {
		t.Fatalf("the FortiGate's line must route to its own pack, got %+v", d)
	}
	if d := r.RouteChainAmong(sline, ch, map[string]bool{ids.PackID: true}, "bound to suricata-lab-01"); d.Pack != ids {
		t.Fatalf("Suricata's line must route to its own pack, got %+v", d)
	}
	// a bound source's line no pack of ITS source owns is that source's unknown line — never another source's family
	csv := []byte("date=2026-09-30,time=10:00:00,devname=fgt,type=traffic,a=1,b=2,c=3,d=4,e=5")
	d := r.RouteChainAmong(csv, ch, map[string]bool{fgt.PackID: true}, "routed only among the packs bound to peer 172.20.20.2")
	if d.Family != nil || d.Stage != "routing" || !strings.Contains(d.Reason, "bound to peer 172.20.20.2") {
		t.Fatalf("an unowned line of a bound peer is quarantined with the binding named, got %+v", d)
	}
}
