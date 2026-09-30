package pipeline

import (
	"strings"
	"testing"
)

// Which packs a line may route among: the loaded packs bound to the sender's HOST (the port is the connection's, not
// the device's); nothing bound, or nothing bound that is loaded: every pack, as before (new-source onboarding unchanged).
func TestAllowedForIsTheLoadedPacksBoundToTheSendersHost(t *testing.T) {
	p := &Pipeline{active: map[string]string{"fortigate-fw-01": "1.0", "fortigate-lab-01-rfc3164-json-53-traffic": "1.0", "suricata-lab-01-rfc3164-json-20-alert": "1.0"},
		bindings: map[string]map[string]bool{
			"172.20.20.2":  {"fortigate-fw-01": true, "fortigate-lab-01-rfc3164-json-53-traffic": true, "fortigate-lab-01-rolled-back": true},
			"172.20.20.11": {"suricata-lab-01-rfc3164-json-20-alert": true},
			"172.20.20.99": {"not-loaded": true},
		}}
	a, note := p.allowedFor("172.20.20.2:41234")
	if len(a) != 2 || !a["fortigate-fw-01"] || a["fortigate-lab-01-rolled-back"] || !strings.Contains(note, "peer 172.20.20.2") {
		t.Fatalf("FortiGate: %v %q", a, note)
	}
	if a, _ := p.allowedFor("172.20.20.11:514"); len(a) != 1 || !a["suricata-lab-01-rfc3164-json-20-alert"] {
		t.Fatalf("Suricata: %v", a)
	}
	for _, peer := range []string{"127.0.0.1:5000", "172.20.20.99:1", ""} {
		if a, note := p.allowedFor(peer); a != nil || note != "" {
			t.Fatalf("%q must route over every pack, got %v %q", peer, a, note)
		}
	}
}
