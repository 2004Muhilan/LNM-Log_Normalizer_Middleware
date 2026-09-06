package frame

import (
	"strings"
	"testing"
)

const squidLine = "1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://x/ - HIER_DIRECT/1.2.3.4 text/html"

// Recursive unwrap: a relay re-wraps a device's RFC 3164 message as RFC 5424. Two envelopes come off,
// outermost first; the innermost is the device's header; the payload is the device's message.
func TestUnwrapChainRelayed(t *testing.T) {
	raw := []byte("<134>1 2024-12-19T00:00:00Z relay01 relay - - - <134>Dec 19 00:00:00 proxy01 squid[1234]: " + squidLine)
	c := UnwrapChain(raw)
	if c.Depth() != 2 || c.Envelopes[0].Kind != "rfc5424" || c.Envelopes[1].Kind != "rfc3164" {
		t.Fatalf("chain: %+v", c)
	}
	if c.Envelopes[0].Level != 1 || c.Envelopes[1].Level != 2 || c.Envelopes[0].Hostname != "relay01" || c.Innermost().Hostname != "proxy01" || c.Innermost().AppName != "squid" {
		t.Fatalf("levels/hosts: %+v", c.Envelopes)
	}
	if string(raw[c.PayloadOffset:c.PayloadOffset+c.PayloadLength]) != squidLine {
		t.Fatalf("payload: %q", raw[c.PayloadOffset:])
	}
	// absolute offsets: the inner envelope's payload offset addresses the received bytes
	if string(raw[c.Envelopes[1].PayloadOffset:]) != squidLine {
		t.Fatal("inner payload offset must be absolute")
	}
	if got := c.Kinds(); strings.Join(got, ",") != "rfc5424,rfc3164" {
		t.Fatalf("kinds: %v", got)
	}
}

// Depth is bounded at two syslog levels: a third header stays in the payload, visible, not discarded.
func TestUnwrapChainDepthBound(t *testing.T) {
	inner := "<13>Jan  5 04:05:06 dev app: message"
	raw := []byte("<13>1 2024-01-05T04:05:06Z r2 relay - - - <13>1 2024-01-05T04:05:06Z r1 relay - - - " + inner)
	c := UnwrapChain(raw)
	if c.Depth() != 2 || string(raw[c.PayloadOffset:]) != inner {
		t.Fatalf("third level must remain in the payload: depth=%d payload=%q", c.Depth(), raw[c.PayloadOffset:])
	}
	if e := Unwrap([]byte(inner)); e.Kind != "rfc3164" {
		t.Fatal("sanity: the retained third level is itself an envelope, left for the record")
	}
}

// CEF: the application envelope comes off after the transport envelopes, only at the start of the
// innermost payload.
func TestUnwrapCEF(t *testing.T) {
	raw := []byte(`CEF:0|Vendor\|Inc|Product|1.0|100|Name with \\ backslash|5|src=10.0.0.1 dst=10.0.0.2 act=blocked`)
	e, ok := UnwrapCEF(raw)
	if !ok || e.Kind != "cef" || *e.Version != 0 || e.DeviceVendor != "Vendor|Inc" || e.DeviceProduct != "Product" || e.DeviceVersion != "1.0" || e.SignatureID != "100" || e.Name != `Name with \ backslash` || e.CEFSeverity != "5" {
		t.Fatalf("cef header: ok=%v %+v", ok, e)
	}
	if string(raw[e.PayloadOffset:]) != "src=10.0.0.1 dst=10.0.0.2 act=blocked" {
		t.Fatalf("extension: %q", raw[e.PayloadOffset:])
	}
	for _, bad := range []string{"CEF:0|a|b|c|d|e|f|", "CEF:0|a|b|c|d|e", "CEF:x|a|b|c|d|e|f|k=v", " CEF:0|a|b|c|d|e|f|k=v", "cef:0|a|b|c|d|e|f|k=v"} {
		if _, ok := UnwrapCEF([]byte(bad)); ok {
			t.Fatalf("%q must not be a CEF envelope", bad)
		}
	}
}

// The envelope-ambiguity rule (plan P7 exit criterion): precedence is transport before application and
// position decides — header-looking text that is not at the start of the current payload is payload.
func TestEnvelopeAmbiguityResolvesByPrecedence(t *testing.T) {
	// syslog-forwarded CEF: both come off, in order
	raw := []byte("<13>Jan  5 04:05:06 host app: CEF:0|V|P|1|100|Name|5|src=1.1.1.1 dst=2.2.2.2")
	c := UnwrapChain(raw)
	if strings.Join(c.Kinds(), ",") != "rfc3164,cef" || string(raw[c.PayloadOffset:]) != "src=1.1.1.1 dst=2.2.2.2" {
		t.Fatalf("forwarded CEF: %v %q", c.Kinds(), raw[c.PayloadOffset:])
	}
	// application text that merely contains a CEF header: the syslog envelope comes off, the CEF-looking
	// text is payload, every byte of it retained where it was
	raw = []byte("<13>Jan  5 04:05:06 host app: user pasted CEF:0|V|P|1|100|Name|5|src=1.1.1.1 into a ticket")
	c = UnwrapChain(raw)
	if strings.Join(c.Kinds(), ",") != "rfc3164" || !strings.HasPrefix(string(raw[c.PayloadOffset:]), "user pasted CEF:0|") {
		t.Fatalf("CEF text inside a payload must stay payload: %v %q", c.Kinds(), raw[c.PayloadOffset:])
	}
	// a syslog-looking header INSIDE a CEF extension is payload: the application envelope is the last
	// one removed, never followed by another transport unwrap
	raw = []byte("CEF:0|V|P|1|100|Name|5|msg=<13>1 2024-01-05T04:05:06Z h a - - - inner src=1.1.1.1")
	c = UnwrapChain(raw)
	if strings.Join(c.Kinds(), ",") != "cef" || !strings.HasPrefix(string(raw[c.PayloadOffset:]), "msg=<13>1 ") {
		t.Fatalf("syslog text inside a CEF extension must stay payload: %v %q", c.Kinds(), raw[c.PayloadOffset:])
	}
	// a 5424 message whose payload looks like a 3164 header (P5 rule) is unchanged under the chain: the
	// inner text IS a 3164 header at the start of the payload, so it is the device's envelope (depth 2)
	raw = []byte("<13>1 2024-01-05T04:05:06Z host app - - - Jan  5 04:05:06 host2 app2: text")
	c = UnwrapChain(raw)
	if strings.Join(c.Kinds(), ",") != "rfc5424,rfc3164" || string(raw[c.PayloadOffset:]) != "text" {
		t.Fatalf("nested 3164 at the start of a 5424 payload is a relay chain: %v %q", c.Kinds(), raw[c.PayloadOffset:])
	}
	// no envelope at all: a Squid line is untouched
	if c := UnwrapChain([]byte(squidLine)); c.Depth() != 0 || c.PayloadLength != len(squidLine) {
		t.Fatalf("plain line: %+v", c)
	}
}
