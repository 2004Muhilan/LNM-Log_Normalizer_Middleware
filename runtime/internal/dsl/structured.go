package dsl

// parser-spec 1.2.0: the `json` and `xml` ops — structured payloads under the same rule as every other op: every byte
// of the input is covered by exactly one span. A declared leaf's value is a SEMANTIC span; everything that is syntax
// (braces, key text, colons, commas, tags, attribute names, quotes around an XML attribute, whitespace, comments) is a
// LITERAL span; a leaf nobody declared is an OPAQUE span at unknown.<path> (or the parse is rejected). Both ops consume
// to the end of their input, like kv. No value is interpreted beyond what is stated here:
//
//	json  keys are dotted paths from the root object ("src.ip"); a string's span includes its quotes and its value is
//	      the unescaped text (encoding json-string); numbers, true, false and null are their own bytes; an array is one
//	      value, its bytes as they are; an object is descended into. Duplicate declared keys fail.
//	xml   paths are element names joined by "/" from the root, an attribute is path@name ("Event/System/TimeCreated@SystemTime");
//	      an element's value is its trimmed text (CDATA content included as it is written); entities are NOT decoded —
//	      the value is the bytes of the document; mixed content for a declared path fails. Namespaces are part of the name.
//
// The Python twin (learning/ulpf_learn/dslexec.py) implements exactly this; the op-matrix conformance suite compares them.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"ulpf/runtime/internal/spec"
)

const maxStructuredDepth = 32

type jsonNode struct {
	keys    map[string]*cell
	order   []string
	unknown string
}

type xmlNode struct {
	paths   map[string]*cell
	order   []string
	unknown string
}

func (c *compiler) structuredCells(m map[string]spec.CsvCell, depth int, path, what string) (map[string]*cell, []string) {
	out := map[string]*cell{}
	order := sortedKeys(m)
	for _, k := range order {
		f := m[k]
		p := fmt.Sprintf("%s.%s[%s]", path, what, k)
		if f.Cell == nil {
			c.fail(p, "a "+what+" entry must be a cell (sub-parsing a structured value is not supported)")
			continue
		}
		out[k] = c.cell(f.Cell, depth+1, p)
	}
	return out, order
}

func (c *compiler) jsonOp(raw json.RawMessage, depth int, path string) node {
	var v spec.JSONOp
	if err := json.Unmarshal(raw, &v); err != nil {
		c.fail(path, err.Error())
		return nil
	}
	if v.UnknownKeys != "opaque" && v.UnknownKeys != "reject" {
		c.fail(path, "unknown_keys must be opaque or reject")
	}
	n := &jsonNode{unknown: v.UnknownKeys}
	n.keys, n.order = c.structuredCells(v.Keys, depth, path, "keys")
	return n
}

func (c *compiler) xmlOp(raw json.RawMessage, depth int, path string) node {
	var v spec.XMLOp
	if err := json.Unmarshal(raw, &v); err != nil {
		c.fail(path, err.Error())
		return nil
	}
	if v.Unknown != "opaque" && v.Unknown != "reject" {
		c.fail(path, "unknown must be opaque or reject")
	}
	n := &xmlNode{unknown: v.Unknown}
	n.paths, n.order = c.structuredCells(v.Paths, depth, path, "paths")
	return n
}

func canonCells(m map[string]*cell, order []string) any {
	out := make([]any, 0, len(order))
	for _, k := range order {
		if m[k] != nil {
			out = append(out, []any{k, m[k].canon()})
		}
	}
	return out
}

func (n *jsonNode) canon() any {
	return map[string]any{"op": "json", "keys": canonCells(n.keys, n.order), "unknown_keys": n.unknown}
}
func (n *xmlNode) canon() any {
	return map[string]any{"op": "xml", "paths": canonCells(n.paths, n.order), "unknown": n.unknown}
}

// unknownPath makes a structured path a legal span path: every segment [A-Za-z_][A-Za-z0-9_]*.
func unknownPath(p string, seps string) string {
	segs := strings.FieldsFunc(p, func(r rune) bool { return strings.ContainsRune(seps, r) })
	for i, s := range segs {
		b := []byte(s)
		for j, ch := range b {
			if !(ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
				b[j] = '_'
			}
		}
		if len(b) == 0 || b[0] >= '0' && b[0] <= '9' {
			b = append([]byte{'_'}, b...)
		}
		segs[i] = string(b)
	}
	return "unknown." + strings.Join(segs, ".")
}

// walker emits spans in order: literal for everything between two value spans.
type walker struct {
	x     *exec
	lit   int
	seen  map[string]bool
	step  string
	cells map[string]*cell
	unk   string
	seps  string
}

func (w *walker) value(path string, start, end int, val []byte, enc string) *failure {
	w.x.literal(w.lit, start, w.x.buf[w.lit:start])
	w.lit = end
	if c, ok := w.cells[path]; ok && c != nil {
		if w.seen[path] {
			return fail(start, w.step, "%q occurs more than once", path)
		}
		w.seen[path] = true
		return w.x.emitCell(c, start, end, val, enc, w.step+"["+path+"]")
	}
	if w.unk == "reject" {
		return fail(start, w.step, "undeclared %q", path)
	}
	w.x.opaque(&cell{Field: unknownPath(path, w.seps)}, start, end)
	return nil
}

// ---------------------------------------------------------------- json

func isJSONWS(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func jsonStringEnd(buf []byte, pos, end int) int { // pos at the opening quote; returns the index AFTER the closing quote, or -1
	for i := pos + 1; i < end; i++ {
		switch buf[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}

func jsonUnescape(inner []byte) ([]byte, bool) {
	if bytes.IndexByte(inner, '\\') < 0 {
		return inner, utf8.Valid(inner)
	}
	out := make([]byte, 0, len(inner))
	for i := 0; i < len(inner); i++ {
		ch := inner[i]
		if ch != '\\' {
			out = append(out, ch)
			continue
		}
		i++
		if i >= len(inner) {
			return nil, false
		}
		switch inner[i] {
		case '"', '\\', '/':
			out = append(out, inner[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(inner, i+1)
			if !ok {
				return nil, false
			}
			i += 4
			if utf16.IsSurrogate(rune(r)) {
				if i+6 >= len(inner)+0 || i+2 >= len(inner) || inner[i+1] != '\\' || inner[i+2] != 'u' {
					return nil, false
				}
				r2, ok := hex4(inner, i+3)
				dec := utf16.DecodeRune(rune(r), rune(r2))
				if !ok || dec == utf8.RuneError {
					return nil, false
				}
				i += 6
				out = utf8.AppendRune(out, dec)
			} else {
				out = utf8.AppendRune(out, rune(r))
			}
		default:
			return nil, false
		}
	}
	return out, utf8.Valid(out)
}

func hex4(b []byte, at int) (uint16, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var v uint16
	for _, ch := range b[at : at+4] {
		v <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			v |= uint16(ch - '0')
		case ch >= 'a' && ch <= 'f':
			v |= uint16(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			v |= uint16(ch-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

func (n *jsonNode) exec(x *exec, start, end int) (int, *failure) {
	w := &walker{x: x, lit: start, seen: map[string]bool{}, step: ".json", cells: n.keys, unk: n.unknown, seps: "."}
	buf := x.buf
	skip := func(p int) int {
		for p < end && isJSONWS(buf[p]) {
			p++
		}
		return p
	}
	var object func(pos int, path string, depth int) (int, *failure)
	scalarEnd := func(p int) int {
		for p < end && !isJSONWS(buf[p]) && buf[p] != ',' && buf[p] != '}' && buf[p] != ']' {
			p++
		}
		return p
	}
	compositeEnd := func(p int) int { // an array (or anything bracketed) as one value: the matching close, strings respected
		depth := 0
		for p < end {
			switch buf[p] {
			case '"':
				q := jsonStringEnd(buf, p, end)
				if q < 0 {
					return -1
				}
				p = q
				continue
			case '[', '{':
				depth++
			case ']', '}':
				depth--
				if depth == 0 {
					return p + 1
				}
			}
			p++
		}
		return -1
	}
	object = func(pos int, path string, depth int) (int, *failure) {
		if depth > maxStructuredDepth {
			return pos, fail(pos, ".json", "nesting deeper than %d", maxStructuredDepth)
		}
		pos = skip(pos + 1) // after '{'
		if pos < end && buf[pos] == '}' {
			return pos + 1, nil
		}
		for {
			if pos >= end || buf[pos] != '"' {
				return pos, fail(pos, ".json", "expected a key")
			}
			ke := jsonStringEnd(buf, pos, end)
			if ke < 0 {
				return pos, fail(pos, ".json", "unterminated key")
			}
			key := string(buf[pos+1 : ke-1])
			child := key
			if path != "" {
				child = path + "." + key
			}
			pos = skip(ke)
			if pos >= end || buf[pos] != ':' {
				return pos, fail(pos, ".json", "expected ':' after key %q", key)
			}
			pos = skip(pos + 1)
			if pos >= end {
				return pos, fail(pos, ".json", "value missing for %q", key)
			}
			switch buf[pos] {
			case '{':
				p, f := object(pos, child, depth+1)
				if f != nil {
					return p, f
				}
				pos = p
			case '[':
				ve := compositeEnd(pos)
				if ve < 0 {
					return pos, fail(pos, ".json", "unterminated array at %q", child)
				}
				if f := w.value(child, pos, ve, buf[pos:ve], ""); f != nil {
					return pos, f
				}
				pos = ve
			case '"':
				ve := jsonStringEnd(buf, pos, end)
				if ve < 0 {
					return pos, fail(pos, ".json", "unterminated string at %q", child)
				}
				val, ok := jsonUnescape(buf[pos+1 : ve-1])
				if !ok {
					return pos, fail(pos, ".json", "invalid string escape or UTF-8 at %q", child)
				}
				if f := w.value(child, pos, ve, val, "json-string"); f != nil {
					return pos, f
				}
				pos = ve
			default:
				ve := scalarEnd(pos)
				if ve == pos {
					return pos, fail(pos, ".json", "value missing for %q", key)
				}
				if f := w.value(child, pos, ve, buf[pos:ve], ""); f != nil {
					return pos, f
				}
				pos = ve
			}
			pos = skip(pos)
			if pos < end && buf[pos] == ',' {
				pos = skip(pos + 1)
				continue
			}
			if pos < end && buf[pos] == '}' {
				return pos + 1, nil
			}
			return pos, fail(pos, ".json", "expected ',' or '}'")
		}
	}
	pos := skip(start)
	if pos >= end || buf[pos] != '{' {
		return start, fail(pos, ".json", "expected a JSON object")
	}
	p, f := object(pos, "", 1)
	if f != nil {
		return start, f
	}
	if p = skip(p); p != end {
		return start, fail(p, ".json", "bytes after the JSON object")
	}
	x.literal(w.lit, end, buf[w.lit:end])
	return end, nil
}

// ---------------------------------------------------------------- xml

func isXMLWS(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func (n *xmlNode) exec(x *exec, start, end int) (int, *failure) {
	w := &walker{x: x, lit: start, seen: map[string]bool{}, step: ".xml", cells: n.paths, unk: n.unknown, seps: "/@"}
	buf := x.buf
	var stack []string
	path := func() string { return strings.Join(stack, "/") }
	text := func(a, b int) *failure { // trimmed text of the current element
		for a < b && isXMLWS(buf[a]) {
			a++
		}
		for b > a && isXMLWS(buf[b-1]) {
			b--
		}
		if a == b {
			return nil
		}
		if len(stack) == 0 {
			return fail(a, ".xml", "text outside the root element")
		}
		return w.value(path(), a, b, buf[a:b], "")
	}
	pos, rootSeen := start, false
	for pos < end {
		lt := bytes.IndexByte(buf[pos:end], '<')
		if lt < 0 {
			if f := text(pos, end); f != nil {
				return start, f
			}
			pos = end
			break
		}
		if f := text(pos, pos+lt); f != nil {
			return start, f
		}
		pos += lt
		rest := buf[pos:end]
		switch {
		case bytes.HasPrefix(rest, []byte("<!--")):
			e := bytes.Index(rest, []byte("-->"))
			if e < 0 {
				return start, fail(pos, ".xml", "unterminated comment")
			}
			pos += e + 3
		case bytes.HasPrefix(rest, []byte("<![CDATA[")):
			e := bytes.Index(rest, []byte("]]>"))
			if e < 0 {
				return start, fail(pos, ".xml", "unterminated CDATA")
			}
			if len(stack) == 0 {
				return start, fail(pos, ".xml", "CDATA outside the root element")
			}
			if e > 9 {
				if f := w.value(path(), pos+9, pos+e, buf[pos+9:pos+e], ""); f != nil {
					return start, f
				}
			}
			pos += e + 3
		case bytes.HasPrefix(rest, []byte("<?")) || bytes.HasPrefix(rest, []byte("<!")):
			e := bytes.IndexByte(rest, '>')
			if e < 0 {
				return start, fail(pos, ".xml", "unterminated declaration")
			}
			pos += e + 1
		case bytes.HasPrefix(rest, []byte("</")):
			e := bytes.IndexByte(rest, '>')
			if e < 0 {
				return start, fail(pos, ".xml", "unterminated end tag")
			}
			name := strings.TrimSpace(string(rest[2:e]))
			if len(stack) == 0 || stack[len(stack)-1] != name {
				return start, fail(pos, ".xml", "end tag </%s> does not close the open element", name)
			}
			stack = stack[:len(stack)-1]
			pos += e + 1
		default:
			p := pos + 1
			ns := p
			for p < end && !isXMLWS(buf[p]) && buf[p] != '>' && buf[p] != '/' {
				p++
			}
			if p == ns {
				return start, fail(pos, ".xml", "tag without a name")
			}
			if len(stack) == 0 {
				if rootSeen {
					return start, fail(pos, ".xml", "a second root element")
				}
				rootSeen = true
			}
			if len(stack) >= maxStructuredDepth {
				return start, fail(pos, ".xml", "nesting deeper than %d", maxStructuredDepth)
			}
			stack = append(stack, string(buf[ns:p]))
			closed := false
			for {
				for p < end && isXMLWS(buf[p]) {
					p++
				}
				if p >= end {
					return start, fail(pos, ".xml", "unterminated start tag")
				}
				if buf[p] == '>' {
					p++
					break
				}
				if buf[p] == '/' && p+1 < end && buf[p+1] == '>' {
					p += 2
					closed = true
					break
				}
				as := p
				for p < end && buf[p] != '=' && !isXMLWS(buf[p]) && buf[p] != '>' {
					p++
				}
				attr := string(buf[as:p])
				for p < end && isXMLWS(buf[p]) {
					p++
				}
				if p >= end || buf[p] != '=' || attr == "" {
					return start, fail(as, ".xml", "attribute without a value")
				}
				p++
				for p < end && isXMLWS(buf[p]) {
					p++
				}
				if p >= end || (buf[p] != '"' && buf[p] != '\'') {
					return start, fail(p, ".xml", "attribute value must be quoted")
				}
				q := buf[p]
				ve := bytes.IndexByte(buf[p+1:end], q)
				if ve < 0 {
					return start, fail(p, ".xml", "unterminated attribute value")
				}
				if ve > 0 {
					if f := w.value(path()+"@"+attr, p+1, p+1+ve, buf[p+1:p+1+ve], ""); f != nil {
						return start, f
					}
				}
				p += ve + 2
			}
			if closed {
				stack = stack[:len(stack)-1]
			}
			pos = p
		}
	}
	if len(stack) != 0 {
		return start, fail(end, ".xml", "element <%s> is not closed", stack[len(stack)-1])
	}
	if !rootSeen {
		return start, fail(start, ".xml", "no root element")
	}
	x.literal(w.lit, end, buf[w.lit:end])
	return end, nil
}
