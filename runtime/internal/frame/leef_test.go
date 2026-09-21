package frame

import "testing"

// LEEF (normalized-event 1.4.0): an application envelope like CEF — recognised only at the start of the payload,
// after the transport envelopes; the header is carried in the envelope record and the attribute list is the payload.
func TestUnwrapLEEF(t *testing.T) {
	v1 := "LEEF:1.0|Acme|Gate|4.2|login_fail|src=10.4.2.17\tdst=203.0.113.9\tusrName=alice"
	e, ok := UnwrapLEEF([]byte(v1))
	if !ok || e.Kind != "leef" || *e.Version != 1 || e.DeviceVendor != "Acme" || e.DeviceProduct != "Gate" || e.DeviceVersion != "4.2" || e.SignatureID != "login_fail" || e.LEEFDelimiter != "" {
		t.Fatalf("LEEF 1.0 header: %+v %v", e, ok)
	}
	if got := v1[e.PayloadOffset : e.PayloadOffset+e.PayloadLength]; got != "src=10.4.2.17\tdst=203.0.113.9\tusrName=alice" {
		t.Fatalf("payload: %q", got)
	}
	for in, delim := range map[string]string{"LEEF:2.0|Acme|Gate|4.2|42|^|src=1.1.1.1^dst=2.2.2.2": "^", "LEEF:2.0|Acme|Gate|4.2|42|0x09|src=1.1.1.1\tdst=2.2.2.2": "0x09", "LEEF:2.0|Acme|Gate|4.2|42|src=1.1.1.1\tdst=2.2.2.2": ""} {
		e, ok := UnwrapLEEF([]byte(in))
		if !ok || *e.Version != 2 || e.LEEFDelimiter != delim || in[e.PayloadOffset:e.PayloadOffset+4] != "src=" {
			t.Fatalf("LEEF 2.0 %q: %+v %v", in, e, ok)
		}
	}
	for _, in := range []string{"LEEF:1.0|Acme|Gate|4.2|login_fail|", "LEEF:1.0|Acme|Gate", "LEEF:x|a|b|c|d|k=v", "user typed LEEF:1.0|a|b|c|d|k=v"} {
		if _, ok := UnwrapLEEF([]byte(in)); ok {
			t.Fatalf("%q is not a LEEF envelope", in)
		}
	}
	// transport before application, and text that merely contains a header is payload
	c := UnwrapChain([]byte("<134>Sep 20 06:33:20 gw01 " + v1))
	if k := c.Kinds(); len(k) != 2 || k[0] != "rfc3164" || k[1] != "leef" || c.Innermost().SignatureID != "login_fail" {
		t.Fatalf("chain: %v", c.Kinds())
	}
	if k := UnwrapChain([]byte("note: LEEF:1.0|a|b|c|d|k=v")).Kinds(); len(k) != 0 {
		t.Fatalf("a header inside text must stay payload: %v", k)
	}
}
