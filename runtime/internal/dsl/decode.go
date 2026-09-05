package dsl

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

var encodings = map[string]bool{"base64": true, "hex": true, "url": true, "json-string": true, "c-escape": true, "cef-extension": true}

func knownEncoding(e string) bool { return encodings[e] }

// decode returns the decoded bytes of raw under the named encoding.
func decode(encoding string, raw []byte) ([]byte, error) {
	switch encoding {
	case "base64":
		return base64.StdEncoding.DecodeString(string(raw))
	case "hex":
		return hex.DecodeString(string(raw))
	case "url":
		s, err := url.PathUnescape(string(raw))
		return []byte(s), err
	case "json-string":
		var s string
		if err := json.Unmarshal([]byte(`"`+string(raw)+`"`), &s); err != nil {
			return nil, err
		}
		return []byte(s), nil
	case "c-escape":
		s, err := strconv.Unquote(`"` + string(raw) + `"`)
		return []byte(s), err
	case "cef-extension":
		out := make([]byte, 0, len(raw))
		for i := 0; i < len(raw); i++ {
			if raw[i] == '\\' && i+1 < len(raw) {
				switch raw[i+1] {
				case '\\', '=':
					out = append(out, raw[i+1])
				case 'n':
					out = append(out, '\n')
				case 'r':
					out = append(out, '\r')
				default:
					return nil, fmt.Errorf("bad CEF escape at %d", i)
				}
				i++
				continue
			}
			out = append(out, raw[i])
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown encoding %q", encoding)
}

// unescapeQuoted removes a quoting scheme's escapes from inner bytes. It reports whether any escape
// was present so the caller can decide whether a derived buffer is needed.
func unescapeQuoted(inner []byte, quote byte, escape string) ([]byte, bool) {
	switch escape {
	case "doubled":
		out := make([]byte, 0, len(inner))
		changed := false
		for i := 0; i < len(inner); i++ {
			if inner[i] == quote && i+1 < len(inner) && inner[i+1] == quote {
				out = append(out, quote)
				i++
				changed = true
				continue
			}
			out = append(out, inner[i])
		}
		return out, changed
	case "backslash":
		out := make([]byte, 0, len(inner))
		changed := false
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' && i+1 < len(inner) {
				out = append(out, inner[i+1])
				i++
				changed = true
				continue
			}
			out = append(out, inner[i])
		}
		return out, changed
	}
	return inner, false
}
