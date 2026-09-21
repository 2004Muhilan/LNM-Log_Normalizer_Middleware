package frame

import (
	"bytes"
	"strconv"
	"strings"
)

// MaxSyslogDepth is how many nested syslog envelopes UnwrapChain removes (plan P7: "recursive envelope
// unwrap to two levels"). A relay that re-wraps a device's RFC 3164 message as RFC 5424 is depth 2;
// anything deeper is left in the payload and is visible there — never silently discarded.
const MaxSyslogDepth = 2

// Chain is the result of recursive unwrapping: every envelope removed, outermost first, with absolute
// payload offsets into the received bytes, and the innermost payload the router and parser see.
// Envelopes[len-1] is the innermost — the device's own header when a relay chain is present — and is
// what routing anchors and envelope-sourced mappings read; the whole chain is recorded in lineage.
type Chain struct {
	Envelopes     []Envelope
	PayloadOffset int
	PayloadLength int
}

// Depth is the number of envelopes removed (0 when the message had none).
func (c Chain) Depth() int { return len(c.Envelopes) }

// Innermost returns the device-side envelope, or nil when there was none.
func (c Chain) Innermost() *Envelope {
	if len(c.Envelopes) == 0 {
		return nil
	}
	return &c.Envelopes[len(c.Envelopes)-1]
}

// Outermost returns the first envelope removed (the relay's, on a relayed message), or nil.
func (c Chain) Outermost() *Envelope {
	if len(c.Envelopes) == 0 {
		return nil
	}
	return &c.Envelopes[0]
}

// Kinds lists the envelope kinds outermost first — what the L1 stage of the router matches against.
func (c Chain) Kinds() []string {
	out := make([]string, 0, len(c.Envelopes))
	for _, e := range c.Envelopes {
		out = append(out, e.Kind)
	}
	return out
}

// UnwrapChain removes up to MaxSyslogDepth syslog envelopes (each by the P5/P6 precedence: RFC 5424,
// then RFC 3164, else none), then one application envelope (CEF) if the innermost payload STARTS with
// a well-formed CEF header. Precedence is therefore transport before application, and outermost
// before inner; application text that merely resembles a header inside a payload is payload — the
// envelope-ambiguity rule (plan P7 exit criterion), tested in chain_test.go.
func UnwrapChain(raw []byte) Chain {
	c := Chain{PayloadOffset: 0, PayloadLength: len(raw)}
	for depth := 0; depth < MaxSyslogDepth; depth++ {
		e := Unwrap(raw[c.PayloadOffset : c.PayloadOffset+c.PayloadLength])
		if e.Kind == "none" {
			break
		}
		e.PayloadOffset += c.PayloadOffset // absolute
		e.Level = depth + 1
		c.Envelopes = append(c.Envelopes, e)
		c.PayloadOffset, c.PayloadLength = e.PayloadOffset, e.PayloadLength
	}
	if e, ok := UnwrapLEEF(raw[c.PayloadOffset : c.PayloadOffset+c.PayloadLength]); ok {
		e.PayloadOffset += c.PayloadOffset
		e.Level = len(c.Envelopes) + 1
		c.Envelopes = append(c.Envelopes, e)
		c.PayloadOffset, c.PayloadLength = e.PayloadOffset, e.PayloadLength
		return c
	}
	if e, ok := UnwrapCEF(raw[c.PayloadOffset : c.PayloadOffset+c.PayloadLength]); ok {
		e.PayloadOffset += c.PayloadOffset
		e.Level = len(c.Envelopes) + 1
		c.Envelopes = append(c.Envelopes, e)
		c.PayloadOffset, c.PayloadLength = e.PayloadOffset, e.PayloadLength
	}
	return c
}

// UnwrapCEF recognises an ArcSight CEF header at the START of raw:
//
//	CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
//
// Pipes inside the seven header fields are escaped as `\|` (backslashes as `\\`); the extension is the
// payload (key=value pairs, parsed by a pack's kv family with the `cef-extension` decoder). A header
// must be followed by a non-empty extension; "CEF:" anywhere but at offset 0 is payload text.
func UnwrapCEF(raw []byte) (Envelope, bool) {
	if !bytes.HasPrefix(raw, []byte("CEF:")) {
		return Envelope{}, false
	}
	pos := 4
	vs := pos
	for pos < len(raw) && raw[pos] >= '0' && raw[pos] <= '9' {
		pos++
	}
	if pos == vs || pos >= len(raw) || raw[pos] != '|' {
		return Envelope{}, false
	}
	ver, _ := strconv.Atoi(string(raw[vs:pos]))
	pos++ // the pipe after the version
	var fields [6]string
	for i := range fields {
		var sb bytes.Buffer
		for {
			if pos >= len(raw) {
				return Envelope{}, false
			}
			ch := raw[pos]
			if ch == '\\' && pos+1 < len(raw) && (raw[pos+1] == '|' || raw[pos+1] == '\\') {
				sb.WriteByte(raw[pos+1])
				pos += 2
				continue
			}
			if ch == '|' {
				pos++
				break
			}
			sb.WriteByte(ch)
			pos++
		}
		fields[i] = sb.String()
	}
	if pos >= len(raw) {
		return Envelope{}, false // header with no extension is not an envelope
	}
	e := Envelope{Kind: "cef", Version: &ver, DeviceVendor: fields[0], DeviceProduct: fields[1], DeviceVersion: fields[2],
		SignatureID: fields[3], Name: fields[4], CEFSeverity: fields[5], PayloadOffset: pos, PayloadLength: len(raw) - pos}
	return e, true
}

// UnwrapLEEF recognises an IBM QRadar LEEF header at the START of raw (normalized-event 1.4.0):
//
//	LEEF:1.0|Vendor|Product|Version|EventID|attr=value<TAB>attr=value…
//	LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|attr=value<Delimiter>attr=value…
//
// The payload is the attribute list (parsed by a pack's kv family whose pair separator is the delimiter: TAB for
// 1.0, the declared character for 2.0). The header fields are not escaped in LEEF. In 2.0 the delimiter field is a
// single character or a hex code (0x09, x7c); it is a delimiter field only when the sixth field is one of those forms
// and is followed by a pipe — otherwise the sixth field is already the payload (a 2.0 sender may omit it). A header must
// be followed by a non-empty payload; "LEEF:" anywhere but at offset 0 is payload text, exactly like CEF.
func UnwrapLEEF(raw []byte) (Envelope, bool) {
	if !bytes.HasPrefix(raw, []byte("LEEF:")) {
		return Envelope{}, false
	}
	pos := 5
	vs := pos
	for pos < len(raw) && (raw[pos] >= '0' && raw[pos] <= '9' || raw[pos] == '.') {
		pos++
	}
	if pos == vs || pos >= len(raw) || raw[pos] != '|' {
		return Envelope{}, false
	}
	verText := string(raw[vs:pos])
	major, err := strconv.Atoi(strings.SplitN(verText, ".", 2)[0])
	if err != nil {
		return Envelope{}, false
	}
	pos++
	var fields [4]string
	for i := range fields {
		e := bytes.IndexByte(raw[pos:], '|')
		if e < 0 {
			return Envelope{}, false
		}
		fields[i] = string(raw[pos : pos+e])
		pos += e + 1
	}
	delim := ""
	if major >= 2 {
		if e := bytes.IndexByte(raw[pos:], '|'); e > 0 && e <= 4 {
			d := string(raw[pos : pos+e])
			if len(d) == 1 || isHexCode(d) {
				delim = d
				pos += e + 1
			}
		}
	}
	if pos >= len(raw) {
		return Envelope{}, false // header with no attributes is not an envelope
	}
	return Envelope{Kind: "leef", Version: &major, DeviceVendor: fields[0], DeviceProduct: fields[1], DeviceVersion: fields[2],
		SignatureID: fields[3], LEEFDelimiter: delim, PayloadOffset: pos, PayloadLength: len(raw) - pos}, true
}

func isHexCode(d string) bool {
	h := strings.TrimPrefix(strings.TrimPrefix(d, "0x"), "x")
	if h == d || len(h) != 2 {
		return false
	}
	_, err := strconv.ParseUint(h, 16, 8)
	return err == nil
}
