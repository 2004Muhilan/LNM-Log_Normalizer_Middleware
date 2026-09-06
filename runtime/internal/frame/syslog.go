package frame

import (
	"bytes"
	"strconv"
)

// Envelope is one transport or application header unwrapped from a received message. The evidence
// record keeps the complete received bytes; the payload the parser sees is
// raw[PayloadOffset : PayloadOffset+PayloadLength] (offsets absolute in the received bytes, also when
// the envelope is an inner one of a relay chain — see UnwrapChain). Header fields are carried verbatim.
// P7 adds Level (1 = outermost) and the CEF header fields (kind cef).
type Envelope struct {
	Kind           string `json:"kind"` // none | rfc3164 | rfc5424 | cef
	Level          int    `json:"level,omitempty"`
	PayloadOffset  int    `json:"payload_offset"`
	PayloadLength  int    `json:"payload_length"`
	Priority       *int   `json:"priority,omitempty"`
	Facility       *int   `json:"facility,omitempty"`
	Severity       *int   `json:"severity,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	AppName        string `json:"app_name,omitempty"`
	ProcID         string `json:"proc_id,omitempty"`
	MsgID          string `json:"msg_id,omitempty"`
	StructuredData string `json:"structured_data,omitempty"`
	Version        *int   `json:"version,omitempty"`
	// CEF header (kind cef): CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
	DeviceVendor  string `json:"device_vendor,omitempty"`
	DeviceProduct string `json:"device_product,omitempty"`
	DeviceVersion string `json:"device_version,omitempty"`
	SignatureID   string `json:"signature_id,omitempty"`
	Name          string `json:"name,omitempty"`
	CEFSeverity   string `json:"cef_severity,omitempty"`
}

// Unwrap recognises a syslog envelope at the START of raw and returns it with the payload bounds.
// Precedence (deterministic, tested): RFC 5424 (`<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP SP PROCID
// SP MSGID SP SD SP MSG`) is tried first; then RFC 3164 (`<PRI>Mmm dd hh:mm:ss HOST TAG: MSG`, also the
// relay form with a year `Mmm dd yyyy hh:mm:ss` and the PRI-less form used by file-collected
// fixtures); otherwise the whole message is the payload (kind none). Only the outermost envelope is
// removed: application text that looks like a header INSIDE the payload is payload, never a second
// unwrap. A candidate header must be followed by a payload; an empty payload is not an envelope.
func Unwrap(raw []byte) Envelope {
	if e, ok := unwrap5424(raw); ok {
		return e
	}
	if e, ok := unwrap3164(raw); ok {
		return e
	}
	return Envelope{Kind: "none", PayloadOffset: 0, PayloadLength: len(raw)}
}

func pri(raw []byte) (p int, n int, ok bool) {
	if len(raw) < 3 || raw[0] != '<' {
		return 0, 0, false
	}
	end := bytes.IndexByte(raw[:min(len(raw), 6)], '>')
	if end < 1 {
		return 0, 0, false
	}
	v, err := strconv.Atoi(string(raw[1:end]))
	if err != nil || v < 0 || v > 191 || (end > 2 && raw[1] == '0') {
		return 0, 0, false
	}
	return v, end + 1, true
}

func field(raw []byte, pos int) (string, int, bool) {
	if pos >= len(raw) {
		return "", pos, false
	}
	sp := bytes.IndexByte(raw[pos:], ' ')
	if sp <= 0 {
		return "", pos, false
	}
	return string(raw[pos : pos+sp]), pos + sp + 1, true
}

func unwrap5424(raw []byte) (Envelope, bool) {
	p, pos, ok := pri(raw)
	if !ok {
		return Envelope{}, false
	}
	ver, next, ok := field(raw, pos)
	if !ok || len(ver) == 0 || len(ver) > 3 {
		return Envelope{}, false
	}
	v, err := strconv.Atoi(ver)
	if err != nil || v < 1 {
		return Envelope{}, false
	}
	e := Envelope{Kind: "rfc5424", Priority: &p, Version: &v}
	f, s := p/8, p%8
	e.Facility, e.Severity = &f, &s
	pos = next
	var parts [5]string
	for i := range parts {
		val, n, ok := field(raw, pos)
		if !ok {
			return Envelope{}, false
		}
		parts[i], pos = val, n
	}
	// TIMESTAMP must be NILVALUE or start with a digit (RFC 3339)
	if parts[0] != "-" && (len(parts[0]) < 19 || parts[0][0] < '0' || parts[0][0] > '9' || parts[0][4] != '-') {
		return Envelope{}, false
	}
	e.Timestamp, e.Hostname, e.AppName, e.ProcID, e.MsgID = parts[0], parts[1], parts[2], parts[3], parts[4]
	// STRUCTURED-DATA: "-" or one or more [..] elements (brackets inside quoted params may be escaped)
	if pos >= len(raw) {
		return Envelope{}, false
	}
	if raw[pos] == '-' {
		e.StructuredData = "-"
		pos++
	} else if raw[pos] == '[' {
		start := pos
		for pos < len(raw) && raw[pos] == '[' {
			close := sdClose(raw, pos)
			if close < 0 {
				return Envelope{}, false
			}
			pos = close + 1
		}
		e.StructuredData = string(raw[start:pos])
	} else {
		return Envelope{}, false
	}
	if pos >= len(raw) || raw[pos] != ' ' {
		return Envelope{}, false
	}
	pos++
	if pos >= len(raw) {
		return Envelope{}, false
	}
	// optional BOM before MSG
	if bytes.HasPrefix(raw[pos:], []byte{0xEF, 0xBB, 0xBF}) {
		pos += 3
	}
	e.PayloadOffset, e.PayloadLength = pos, len(raw)-pos
	return e, true
}

func sdClose(raw []byte, open int) int {
	inQuote := false
	for i := open + 1; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case '"':
			inQuote = !inQuote
		case ']':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

var months = map[string]bool{"Jan": true, "Feb": true, "Mar": true, "Apr": true, "May": true, "Jun": true, "Jul": true, "Aug": true, "Sep": true, "Oct": true, "Nov": true, "Dec": true}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isClock(s string) bool {
	return len(s) == 8 && isDigits(s[0:2]) && s[2] == ':' && isDigits(s[3:5]) && s[5] == ':' && isDigits(s[6:8])
}

func unwrap3164(raw []byte) (Envelope, bool) {
	e := Envelope{Kind: "rfc3164"}
	pos := 0
	if p, n, ok := pri(raw); ok {
		e.Priority = &p
		f, s := p/8, p%8
		e.Facility, e.Severity = &f, &s
		pos = n
	}
	// Mmm dd [yyyy] hh:mm:ss  — "Mmm  d" has two spaces for single-digit days
	if pos+3 > len(raw) || !months[string(raw[pos:pos+3])] || pos+3 >= len(raw) || raw[pos+3] != ' ' {
		// PRI-only form (RFC 3164 §4.3.3: a PRI followed by no valid TIMESTAMP — the whole remainder is
		// content). FortiGate emits exactly this: `<189>date=... time=...`. The envelope is the PRI alone;
		// without a PRI there is no envelope.
		if e.Priority != nil && pos < len(raw) {
			e.PayloadOffset, e.PayloadLength = pos, len(raw)-pos
			return e, true
		}
		return Envelope{}, false
	}
	tsStart := pos
	pos += 4
	for pos < len(raw) && raw[pos] == ' ' {
		pos++
	}
	day, n, ok := field(raw, pos)
	if !ok || !isDigits(day) || len(day) > 2 {
		return Envelope{}, false
	}
	pos = n
	tok, n2, ok := field(raw, pos)
	if !ok {
		return Envelope{}, false
	}
	if len(tok) == 4 && isDigits(tok) { // relay form with a year (Beats ASA fixtures: "Oct 10 2018 12:34:56")
		pos = n2
		tok, n2, ok = field(raw, pos)
		if !ok {
			return Envelope{}, false
		}
	}
	if !isClock(tok) {
		return Envelope{}, false
	}
	e.Timestamp = string(raw[tsStart : pos+len(tok)])
	pos = n2
	host, n3, ok := field(raw, pos)
	if !ok || host == "" {
		return Envelope{}, false
	}
	e.Hostname = host
	pos = n3
	// TAG: "app[pid]: " or "app: " — optional; a payload that does not start with a tag is left intact
	if colon := bytes.IndexByte(raw[pos:min(len(raw), pos+64)], ':'); colon > 0 {
		tag := string(raw[pos : pos+colon])
		if !bytes.ContainsAny([]byte(tag), " \t") {
			if lb := bytes.IndexByte([]byte(tag), '['); lb > 0 && tag[len(tag)-1] == ']' {
				e.AppName, e.ProcID = tag[:lb], tag[lb+1:len(tag)-1]
			} else {
				e.AppName = tag
			}
			pos += colon + 1
			if pos < len(raw) && raw[pos] == ' ' {
				pos++
			}
		}
	}
	if pos >= len(raw) {
		return Envelope{}, false
	}
	e.PayloadOffset, e.PayloadLength = pos, len(raw)-pos
	return e, true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
