package dsl

import (
	"bytes"
	"fmt"
	"regexp"
	"unicode/utf8"

	"ulpf/runtime/internal/spanmap"
	"ulpf/runtime/internal/spec"
)

// failure is a parse failure at an offset; it becomes the span map's failure record.
type failure struct {
	off    int
	reason string
	step   string
}

func fail(off int, step, format string, a ...any) *failure {
	return &failure{off: off, reason: fmt.Sprintf(format, a...), step: step}
}

type exec struct {
	prog   *Program
	env    Env
	m      *spanmap.SpanMap
	buf    []byte
	bufID  string
	suffix string // occurrence suffix for repeated steps
}

// Parse runs the program over raw and returns a span map. A structural failure yields status
// "failed" with the failure recorded; the tiling invariant is checked on every ok result and a
// violation is returned as an error because it is a parser bug, not an input property.
func (p *Program) Parse(raw []byte, env Env) (*spanmap.SpanMap, error) {
	m := spanmap.New(p.SpecID, raw)
	m.DSLHash = p.DSLHash
	if len(raw) > p.Bounds.MaxEventBytes {
		m.Status = "failed"
		m.Failure = &spanmap.Failure{AtOffset: p.Bounds.MaxEventBytes, Reason: fmt.Sprintf("event of %d bytes exceeds bounds.max_event_bytes %d", len(raw), p.Bounds.MaxEventBytes), Step: "$"}
		m.Spans = []spanmap.Span{}
		return m, nil
	}
	x := &exec{prog: p, env: env, m: m, buf: raw, bufID: "raw"}
	pos, f := p.root.exec(x, 0, len(raw))
	if f == nil && pos != len(raw) {
		f = fail(pos, "$.root", "trailing bytes not consumed by the spec")
	}
	if f != nil {
		m.Status = "failed"
		m.Failure = &spanmap.Failure{AtOffset: f.off, Reason: f.reason, Step: f.step}
		m.Spans = []spanmap.Span{}
		m.Buffers = m.Buffers[:1]
		return m, nil
	}
	m.Sort()
	if err := m.CheckTiling(); err != nil {
		return nil, fmt.Errorf("parser bug: span map violates tiling: %w", err)
	}
	return m, nil
}

func (x *exec) mark() (int, int) { return len(x.m.Spans), len(x.m.Buffers) }
func (x *exec) reset(s, b int)   { x.m.Spans = x.m.Spans[:s]; x.m.Buffers = x.m.Buffers[:b] }

func (x *exec) literal(start, end int, text []byte) {
	if end > start {
		x.m.Spans = append(x.m.Spans, spanmap.Span{Buffer: x.bufID, Start: start, End: end, Kind: "literal", Text: string(text)})
	}
}

func (x *exec) opaque(c *cell, start, end int) {
	if end > start {
		x.m.Spans = append(x.m.Spans, spanmap.Span{Buffer: x.bufID, Start: start, End: end, Kind: "opaque", Path: c.Field + x.suffix})
	}
}

// emitCell records a field span whose raw bytes are [start,end) and whose textual value is value
// (== raw bytes unless the cell was quoted/escaped, in which case encoding names the scheme).
func (x *exec) emitCell(c *cell, start, end int, value []byte, encoding string, step string) *failure {
	if end <= start {
		return nil // empty cell: declared field absent, no span
	}
	if c.Kind == "opaque" {
		x.opaque(c, start, end)
		return nil
	}
	sp := spanmap.Span{Buffer: x.bufID, Start: start, End: end, Kind: "semantic", Path: c.Field + x.suffix, Class: c.Class, Encoding: encoding}
	if c.Class != "" && !classOK(c.Class, value) {
		return fail(start, step, "value %q does not match token class %s", clip(value), c.Class)
	}
	if !utf8.Valid(value) {
		sp.DecodeStatus = "invalid"
	} else {
		v := string(value)
		sp.Value = &v
	}
	if c.Decode != nil {
		dec, err := decode(c.Decode.Encoding, value)
		if err != nil {
			if c.Decode.OnFailure == "reject" {
				return fail(start, step, "decode %s failed: %v", c.Decode.Encoding, err)
			}
			x.opaque(c, start, end)
			return nil
		}
		sp.Encoding = c.Decode.Encoding
		if utf8.Valid(dec) {
			v := string(dec)
			sp.Value, sp.DecodeStatus = &v, "ok"
		} else {
			sp.Value, sp.DecodeStatus = nil, "invalid"
		}
		value = dec
		if c.Decode.Then != nil {
			id := c.Field + x.suffix + "#decoded"
			x.m.Buffers = append(x.m.Buffers, spanmap.Buffer{ID: id, Length: len(dec), DerivedFrom: c.Field + x.suffix, Encoding: c.Decode.Encoding})
			sub := &exec{prog: x.prog, env: x.env, m: x.m, buf: dec, bufID: id, suffix: x.suffix}
			pos, f := c.Decode.Then.exec(sub, 0, len(dec))
			if f == nil && pos != len(dec) {
				f = fail(pos, step+".decode.then", "trailing bytes in decoded buffer")
			}
			if f != nil {
				if c.Decode.OnFailure == "reject" {
					return f
				}
				x.opaque(c, start, end)
				return nil
			}
		}
	}
	if c.Coerce != nil && sp.DecodeStatus != "invalid" {
		co, err := coerce(c.Coerce, string(value), x.env)
		if err != nil {
			if c.Coerce.OnFailure == "reject" {
				return fail(start, step, "coerce to %s failed: %v", c.Coerce.To, err)
			}
			x.opaque(c, start, end)
			return nil
		}
		sp.Coerced = co
	}
	x.m.Spans = append(x.m.Spans, sp)
	return nil
}

func clip(b []byte) string {
	if len(b) > 40 {
		return string(b[:40]) + "…"
	}
	return string(b)
}

// ---- sequence ----

func (n *seqNode) exec(x *exec, start, end int) (int, *failure) {
	pos := start
	for i, s := range n.steps {
		p, f := s.exec(x, pos, end)
		if f != nil {
			f.step = fmt.Sprintf("[%d]%s", i, f.step)
			return pos, f
		}
		pos = p
	}
	return pos, nil
}

// ---- literal ----

func (n *literalNode) exec(x *exec, start, end int) (int, *failure) {
	if !bytes.HasPrefix(x.buf[start:end], n.text) {
		return start, fail(start, ".literal", "expected %q", string(n.text))
	}
	x.literal(start, start+len(n.text), n.text)
	return start + len(n.text), nil
}

// ---- regex ----

func (n *regexNode) exec(x *exec, start, end int) (int, *failure) {
	m := n.re.FindSubmatchIndex(x.buf[start:end])
	if m == nil {
		return start, fail(start, ".regex", "no match for /%s/", n.pattern)
	}
	type cap struct {
		s, e int
		c    *cell
		name string
	}
	var caps []cap
	for i, name := range n.names {
		if name == "" || m[2*i] < 0 || m[2*i] == m[2*i+1] {
			continue
		}
		caps = append(caps, cap{start + m[2*i], start + m[2*i+1], n.captures[name], name})
	}
	// sort by start (few captures; insertion sort)
	for i := 1; i < len(caps); i++ {
		for j := i; j > 0 && caps[j].s < caps[j-1].s; j-- {
			caps[j], caps[j-1] = caps[j-1], caps[j]
		}
	}
	pos := start
	for _, c := range caps {
		if c.s < pos {
			return start, fail(c.s, ".regex", "overlapping captures")
		}
		x.literal(pos, c.s, x.buf[pos:c.s])
		if f := x.emitCell(c.c, c.s, c.e, x.buf[c.s:c.e], "", ".regex."+c.name); f != nil {
			return start, f
		}
		pos = c.e
	}
	matchEnd := start + m[1]
	x.literal(pos, matchEnd, x.buf[pos:matchEnd])
	return matchEnd, nil
}

// ---- delimiters ----

// delimRun returns the length of the delimiter (run) at pos, or 0.
func delimRun(d spec.Delim, buf []byte, pos, end int) int {
	switch {
	case d.WhitespaceRun:
		i := pos
		for i < end && (buf[i] == ' ' || buf[i] == '\t') {
			i++
		}
		return i - pos
	case d.Char != "":
		if pos < end && buf[pos] == d.Char[0] {
			return 1
		}
		return 0
	default:
		if bytes.HasPrefix(buf[pos:end], []byte(d.String)) {
			return len(d.String)
		}
		return 0
	}
}

// tokenEnd returns the end of the maximal run of non-delimiter bytes from pos.
func tokenEnd(d spec.Delim, buf []byte, pos, end int) int {
	i := pos
	for i < end {
		if delimRun(d, buf, i, end) > 0 {
			break
		}
		i++
	}
	return i
}

// ---- positional ----

func (n *positionalNode) exec(x *exec, start, end int) (int, *failure) {
	pos := start
	if l := delimRun(n.delim, x.buf, pos, end); l > 0 {
		if n.leading == "reject" {
			return start, fail(pos, ".positional", "leading delimiter not allowed")
		}
		x.literal(pos, pos+l, x.buf[pos:pos+l])
		pos += l
	}
	for i, s := range n.slots {
		step := fmt.Sprintf(".positional.slots[%d]", i)
		if i > 0 {
			l := delimRun(n.delim, x.buf, pos, end)
			if l == 0 {
				return start, fail(pos, step, "expected delimiter before slot %d", i)
			}
			x.literal(pos, pos+l, x.buf[pos:pos+l])
			pos += l
		}
		switch {
		case s.step != nil:
			p, f := s.step.exec(x, pos, end)
			if f != nil {
				f.step = step + f.step
				return start, f
			}
			pos = p
		default:
			te := tokenEnd(n.delim, x.buf, pos, end)
			if te == pos {
				return start, fail(pos, step, "empty token for slot %d", i)
			}
			if s.cell != nil {
				if f := x.emitCell(s.cell, pos, te, x.buf[pos:te], "", step); f != nil {
					return start, f
				}
			} else {
				p, f := s.token.exec(x, pos, te)
				if f != nil {
					f.step = step + ".token" + f.step
					return start, f
				}
				if p != te {
					return start, fail(p, step, "token sub-parse did not consume the whole token")
				}
			}
			pos = te
		}
	}
	if n.tail != nil {
		if pos < end {
			if l := delimRun(n.delim, x.buf, pos, end); l > 0 {
				x.literal(pos, pos+l, x.buf[pos:pos+l])
				pos += l
			}
			if f := x.emitCell(n.tail, pos, end, x.buf[pos:end], "", ".positional.tail"); f != nil {
				return start, f
			}
			pos = end
		}
		return pos, nil
	}
	if l := delimRun(n.delim, x.buf, pos, end); l > 0 {
		if n.trailing == "reject" {
			return start, fail(pos, ".positional", "trailing delimiter not allowed")
		}
		x.literal(pos, pos+l, x.buf[pos:pos+l])
		pos += l
	}
	return pos, nil
}

// ---- quoted ----

// scanQuoted finds the closing quote honouring the escape scheme; returns index of the close quote.
func scanQuoted(buf []byte, pos, end int, quote byte, escape string) int {
	i := pos
	for i < end {
		switch {
		case escape == "backslash" && buf[i] == '\\' && i+1 < end:
			i += 2
		case buf[i] == quote:
			if escape == "doubled" && i+1 < end && buf[i+1] == quote {
				i += 2
				continue
			}
			return i
		default:
			i++
		}
	}
	return -1
}

func (n *quotedNode) exec(x *exec, start, end int) (int, *failure) {
	if start >= end || x.buf[start] != n.open {
		return start, fail(start, ".quoted", "expected opening %q", string(n.open))
	}
	closeAt := scanQuoted(x.buf, start+1, end, n.close, n.escape)
	if closeAt < 0 {
		return start, fail(start, ".quoted", "unterminated quote")
	}
	x.literal(start, start+1, x.buf[start:start+1])
	inner := x.buf[start+1 : closeAt]
	value, changed := unescapeQuoted(inner, n.close, n.escape)
	enc := ""
	if n.escape != "none" {
		enc = "quoted-" + n.escape
	}
	if n.parse != nil {
		if changed {
			// escaped content is parsed in a derived buffer
			id := n.content.Field + x.suffix + "#decoded"
			if f := x.emitCell(n.content, start+1, closeAt, value, enc, ".quoted.content"); f != nil {
				return start, f
			}
			x.m.Buffers = append(x.m.Buffers, spanmap.Buffer{ID: id, Length: len(value), DerivedFrom: n.content.Field + x.suffix, Encoding: enc})
			sub := &exec{prog: x.prog, env: x.env, m: x.m, buf: value, bufID: id, suffix: x.suffix}
			p, f := n.parse.exec(sub, 0, len(value))
			if f == nil && p != len(value) {
				f = fail(p, ".quoted.parse", "trailing bytes in quoted content")
			}
			if f != nil {
				return start, f
			}
		} else {
			// unescaped content: sub-parse tiles the inner raw bytes directly; the content cell's
			// value is still recorded as the whole inner span only when the sub-parse emits nothing.
			p, f := n.parse.exec(x, start+1, closeAt)
			if f == nil && p != closeAt {
				f = fail(p, ".quoted.parse", "trailing bytes in quoted content")
			}
			if f != nil {
				return start, f
			}
		}
	} else if f := x.emitCell(n.content, start+1, closeAt, value, enc, ".quoted.content"); f != nil {
		return start, f
	}
	x.literal(closeAt, closeAt+1, x.buf[closeAt:closeAt+1])
	return closeAt + 1, nil
}

// ---- optional / repeated ----

func (n *optionalNode) exec(x *exec, start, end int) (int, *failure) {
	s, b := x.mark()
	p, f := n.step.exec(x, start, end)
	if f != nil {
		x.reset(s, b)
		return start, nil
	}
	return p, nil
}

func (n *repeatedNode) exec(x *exec, start, end int) (int, *failure) {
	pos := start
	count := 0
	saved := x.suffix
	for count < n.max {
		s, b := x.mark()
		p := pos
		if count > 0 && n.sep != nil {
			var f *failure
			p, f = n.sep.exec(x, p, end)
			if f != nil {
				x.reset(s, b)
				break
			}
		}
		x.suffix = fmt.Sprintf("%s[%d]", saved, count)
		q, f := n.step.exec(x, p, end)
		x.suffix = saved
		if f != nil || q == p {
			x.reset(s, b)
			break
		}
		pos = q
		count++
	}
	if count < n.min {
		return start, fail(pos, ".repeated", "only %d occurrences, min %d", count, n.min)
	}
	return pos, nil
}

// ---- csv ----

func (n *csvNode) exec(x *exec, start, end int) (int, *failure) {
	pos := start
	idx := 0
	for {
		step := fmt.Sprintf(".csv.fields[%d]", idx)
		cellStart := pos
		var value []byte
		enc := ""
		if n.quote != nil && pos < end && x.buf[pos] == *n.quote {
			closeAt := scanQuoted(x.buf, pos+1, end, *n.quote, n.escape)
			if closeAt < 0 {
				return start, fail(pos, step, "unterminated quoted cell")
			}
			value, _ = unescapeQuoted(x.buf[pos+1:closeAt], *n.quote, n.escape)
			enc = "csv-quoted"
			pos = closeAt + 1
			if pos < end && x.buf[pos] != n.delim {
				return start, fail(pos, step, "bytes after closing quote")
			}
		} else {
			i := pos
			for i < end && x.buf[i] != n.delim {
				i++
			}
			value = x.buf[pos:i]
			pos = i
		}
		// declared, extra, or reject
		if idx < len(n.fields) {
			f := n.fields[idx]
			if f.cell != nil {
				if err := x.emitCell(f.cell, cellStart, pos, value, enc, step); err != nil {
					return start, err
				}
			} else if pos > cellStart {
				if enc != "" {
					return start, fail(cellStart, step, "cannot sub-parse a quoted cell")
				}
				p, err := f.parse.exec(x, cellStart, pos)
				if err != nil {
					err.step = step + err.step
					return start, err
				}
				if p != pos {
					return start, fail(p, step, "cell sub-parse did not consume the whole cell")
				}
			}
		} else {
			if n.extra == "reject" {
				return start, fail(cellStart, step, "more cells than declared")
			}
			x.opaque(&cell{Field: fmt.Sprintf("extra.%d", idx)}, cellStart, pos)
		}
		idx++
		if pos >= end {
			break
		}
		x.literal(pos, pos+1, x.buf[pos:pos+1])
		pos++
		if pos >= end {
			// trailing delimiter: one more (empty) cell
			if idx < len(n.fields) {
				idx++
			}
			break
		}
	}
	if idx < len(n.fields) && n.missing == "reject" {
		return start, fail(pos, ".csv", "only %d cells, %d declared", idx, len(n.fields))
	}
	return end, nil
}

// ---- kv ----

func (n *kvNode) exec(x *exec, start, end int) (int, *failure) {
	pos := start
	lastOrder := -1
	orderIdx := map[string]int{}
	for i, k := range n.keyOrder {
		orderIdx[k] = i
	}
	for pos < end {
		if l := delimRun(n.pairSep, x.buf, pos, end); l > 0 {
			x.literal(pos, pos+l, x.buf[pos:pos+l])
			pos += l
			continue
		}
		km := n.keyRe.FindIndex(x.buf[pos:end])
		if km == nil || km[1] == 0 {
			return start, fail(pos, ".kv", "expected a key matching /%s/", n.keyPattern)
		}
		keyEnd := pos + km[1]
		key := string(x.buf[pos:keyEnd])
		if keyEnd >= end || x.buf[keyEnd] != n.kvSep {
			if n.bareKeys && (keyEnd >= end || delimRun(n.pairSep, x.buf, keyEnd, end) > 0) {
				x.literal(pos, keyEnd, x.buf[pos:keyEnd])
				pos = keyEnd
				continue
			}
			return start, fail(pos, ".kv", "expected %q after key %q", string(n.kvSep), key)
		}
		x.literal(pos, keyEnd, x.buf[pos:keyEnd])
		x.literal(keyEnd, keyEnd+1, x.buf[keyEnd:keyEnd+1])
		vpos := keyEnd + 1
		var value []byte
		enc := ""
		vend := vpos
		if n.quote != nil && vpos < end && x.buf[vpos] == *n.quote {
			closeAt := scanQuoted(x.buf, vpos+1, end, *n.quote, n.escape)
			if closeAt < 0 {
				return start, fail(vpos, ".kv", "unterminated quoted value for %q", key)
			}
			value, _ = unescapeQuoted(x.buf[vpos+1:closeAt], *n.quote, n.escape)
			if n.escape != "none" {
				enc = "quoted-" + n.escape
			} else {
				enc = "csv-quoted"
			}
			vend = closeAt + 1
		} else {
			vend = tokenEnd(n.pairSep, x.buf, vpos, end)
			value = x.buf[vpos:vend]
		}
		step := ".kv.keys[" + key + "]"
		if f, ok := n.keys[key]; ok {
			if n.order == "declared" {
				if orderIdx[key] < lastOrder {
					return start, fail(pos, step, "key %q out of declared order", key)
				}
				lastOrder = orderIdx[key]
			}
			if f.cell != nil {
				if err := x.emitCell(f.cell, vpos, vend, value, enc, step); err != nil {
					return start, err
				}
			} else if vend > vpos {
				if enc != "" {
					return start, fail(vpos, step, "cannot sub-parse a quoted value")
				}
				p, err := f.parse.exec(x, vpos, vend)
				if err != nil {
					return start, err
				}
				if p != vend {
					return start, fail(p, step, "value sub-parse did not consume the whole value")
				}
			}
		} else {
			if n.unknown == "reject" {
				return start, fail(pos, ".kv", "unknown key %q", key)
			}
			x.opaque(&cell{Field: "unknown." + key}, vpos, vend)
		}
		pos = vend
	}
	return end, nil
}

var _ = regexp.MustCompile // keep regexp imported for future compile-time use
