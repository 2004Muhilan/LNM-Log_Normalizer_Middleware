package frame

import "testing"

func TestUnwrapRFC5424(t *testing.T) {
	raw := []byte(`<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry...`)
	e := Unwrap(raw)
	if e.Kind != "rfc5424" || *e.Priority != 165 || *e.Facility != 20 || *e.Severity != 5 || *e.Version != 1 || e.Hostname != "mymachine.example.com" || e.AppName != "evntslog" || e.ProcID != "1234" || e.MsgID != "ID47" {
		t.Fatalf("%+v", e)
	}
	if e.StructuredData != `[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]` {
		t.Fatalf("sd: %q", e.StructuredData)
	}
	if string(raw[e.PayloadOffset:e.PayloadOffset+e.PayloadLength]) != "BOMAn application event log entry..." {
		t.Fatalf("payload: %q", raw[e.PayloadOffset:])
	}
	// NILVALUE structured data, PAN-OS style payload
	raw = []byte(`<14>1 2021-05-26T16:27:07Z PA-220 - - - - 1,2021/05/26 16:27:07,012801096514,TRAFFIC,end,2561,...`)
	e = Unwrap(raw)
	if e.Kind != "rfc5424" || e.StructuredData != "-" || string(raw[e.PayloadOffset:e.PayloadOffset+3]) != "1,2" {
		t.Fatalf("%+v", e)
	}
}

func TestUnwrapRFC3164Forms(t *testing.T) {
	cases := []struct{ raw, host, app, proc, payload string }{
		{"<189>date=2020-04-23 time=01:16:08 devname=\"fw\" type=\"traffic\"", "-", "", "", "date=2020-04-23 time=01:16:08 devname=\"fw\" type=\"traffic\""}, // PRI-only (RFC 3164 §4.3.3, FortiGate): envelope is the PRI alone
		{"date=2020-04-23 time=01:16:08 devname=\"fw\"", "", "", "", ""},                                                                                     // no PRI, no header: none
		{"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8", "mymachine", "su", "", "'su root' failed for lonvick on /dev/pts/8"},
		{"Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-302013: Built outbound TCP connection 11757", "localhost", "CiscoASA", "999", "%ASA-6-302013: Built outbound TCP connection 11757"},
		{"Nov 30 16:09:08 PA-220 1,2018/11/30 16:09:07,012801096514,TRAFFIC,end", "PA-220", "", "", "1,2018/11/30 16:09:07,012801096514,TRAFFIC,end"},
		{"<13>Jan  5 04:05:06 host app: msg", "host", "app", "", "msg"},
	}
	for i, c := range cases {
		e := Unwrap([]byte(c.raw))
		if c.host == "" {
			if e.Kind != "none" || e.PayloadOffset != 0 || e.PayloadLength != len(c.raw) {
				t.Fatalf("case %d: expected none, got %+v", i, e)
			}
			continue
		}
		got := c.raw[e.PayloadOffset : e.PayloadOffset+e.PayloadLength]
		if c.host == "-" { // PRI-only: no hostname, priority carried
			if e.Kind != "rfc3164" || e.Priority == nil || *e.Priority != 189 || e.Hostname != "" || got != c.payload {
				t.Fatalf("case %d: %+v payload=%q", i, e, got)
			}
			continue
		}
		if e.Kind != "rfc3164" || e.Hostname != c.host || e.AppName != c.app || e.ProcID != c.proc || got != c.payload {
			t.Fatalf("case %d: %+v payload=%q", i, e, got)
		}
	}
}

// Envelope precedence (P5 exit criterion): application text that resembles a header is payload; only
// the outermost envelope is removed; 5424 wins over 3164 when both could match the start.
func TestEnvelopePrecedence(t *testing.T) {
	// a 3164 message whose payload is itself a 5424-looking line: unwrap once, payload keeps its inner header
	raw := []byte("<13>Jan  5 04:05:06 relay fwd: <165>1 2003-10-11T22:14:15Z inner app - - - inner message")
	e := Unwrap(raw)
	if e.Kind != "rfc3164" || string(raw[e.PayloadOffset:]) != "<165>1 2003-10-11T22:14:15Z inner app - - - inner message" {
		t.Fatalf("outer 3164 must be unwrapped once: %+v", e)
	}
	// a 5424 message whose payload looks like a 3164 header
	raw = []byte("<13>1 2024-01-05T04:05:06Z host app - - - Jan  5 04:05:06 host2 app2: text")
	e = Unwrap(raw)
	if e.Kind != "rfc5424" || string(raw[e.PayloadOffset:]) != "Jan  5 04:05:06 host2 app2: text" {
		t.Fatalf("outer 5424 must win and unwrap once: %+v", e)
	}
	// a header with no payload is not an envelope
	if e := Unwrap([]byte("<13>Jan  5 04:05:06 host app:")); e.Kind != "none" {
		t.Fatalf("headerless payload must not unwrap: %+v", e)
	}
	// a Squid line (float first) is untouched
	if e := Unwrap([]byte("1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://x/ - HIER_DIRECT/1.2.3.4 text/html")); e.Kind != "none" {
		t.Fatalf("squid line must not unwrap: %+v", e)
	}
	// PRI out of range or malformed is not an envelope
	for _, s := range []string{"<192>1 2024-01-05T04:05:06Z h a - - - m", "<01>1 2024-01-05T04:05:06Z h a - - - m", "<>1 2024-01-05T04:05:06Z h a - - - m"} {
		if e := Unwrap([]byte(s)); e.Kind != "none" {
			t.Fatalf("%q must not unwrap: %+v", s, e)
		}
	}
}
