// Package dsl compiles a parser spec (contracts/parser-spec.schema.json) into an executable program
// and runs it. Compilation enforces the §2.7 static invariants; execution is deterministic,
// backtracking-free above the regex level, and produces a span map that tiles the input exactly.
//
// Nothing in a spec is executed as code: the spec is data, the compiler builds the program.
package dsl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"ulpf/runtime/internal/spec"
)

// CompilerVersion is folded into parser_hash so that a compiler change changes the hash.
const CompilerVersion = "ulpf-compile-0.2.0" // unchanged by 1.2.0: the json and xml ops are additive, so every existing parser_hash stays what it was

type node interface {
	// consuming ops implement exec; value ops are attached to cells.
	exec(x *exec, start, end int) (int, *failure)
	canon() any
}

type cell struct {
	Field  string
	Kind   string
	Class  string
	Coerce *spec.Coerce
	Decode *decodeOp
	// Nulls are the pack-declared null markers in force for this cell (spec default unless the cell
	// overrides). A value equal to one is a declared null: recorded, not coerced, not class-checked.
	Nulls []string
}

type decodeOp struct {
	Encoding  string
	Then      node
	OnFailure string
}

type seqNode struct{ steps []node }
type literalNode struct{ text []byte }
type regexNode struct {
	pattern  string
	re       *regexp.Regexp
	captures map[string]*cell
	names    []string // subexp names by index
}
type csvCell struct {
	cell  *cell
	parse node
}
type csvNode struct {
	delim   byte
	quote   *byte
	escape  string
	fields  []csvCell
	extra   string
	missing string
}
type kvNode struct {
	pairSep    spec.Delim
	kvSep      byte
	quote      *byte
	escape     string
	keyRe      *regexp.Regexp
	keyPattern string
	keys       map[string]csvCell
	keyOrder   []string
	unknown    string
	order      string
	bareKeys   bool
}
type slot struct {
	cell  *cell
	token node
	step  node
}
type positionalNode struct {
	delim    spec.Delim
	slots    []slot
	leading  string
	trailing string
	tail     *cell
}
type quotedNode struct {
	open, close byte
	escape      string
	content     *cell
	parse       node
}
type optionalNode struct{ step node }
type repeatedNode struct {
	step, sep node
	min, max  int
}

// Program is a compiled spec.
type Program struct {
	SpecID  string
	Bounds  spec.Bounds
	DSLHash string // sha256 of the spec bytes as given
	root    node
	fields  []string
	canon   []byte
}

// Fields returns every field path the program can emit (repeated occurrences excluded).
func (p *Program) Fields() []string { return append([]string(nil), p.fields...) }

// ParserHash is sha256 over the canonical compiled representation (plus the compiler version).
// This is the runtime-defined value the pack's parser_hash must equal.
func (p *Program) ParserHash() string {
	h := sha256.Sum256(p.canon)
	return "sha256:" + hex.EncodeToString(h[:])
}

type compiler struct {
	bounds spec.Bounds
	nulls  []string // spec-level null_values default
	fields map[string]bool
	order  []string
	errs   []string
}

func (c *compiler) fail(path, msg string) { c.errs = append(c.errs, path+": "+msg) }

// Compile parses and compiles spec bytes, returning every static-invariant violation as one error.
func Compile(b []byte) (*Program, error) {
	s, err := spec.Parse(b)
	if err != nil {
		return nil, err
	}
	if s.RegexDialect != "re2" {
		return nil, fmt.Errorf("regex_dialect must be re2")
	}
	c := &compiler{bounds: s.Bounds, nulls: s.NullValues, fields: map[string]bool{}}
	root := c.step(s.Root, 1, "$.root")
	if root == nil && len(c.errs) == 0 {
		c.fail("$.root", "empty")
	}
	if root != nil && !isConsuming(root) {
		c.fail("$.root", "root must begin with a consuming op")
	}
	if len(c.fields) > s.Bounds.MaxFields {
		c.fail("$", fmt.Sprintf("field count %d exceeds bounds.max_fields %d", len(c.fields), s.Bounds.MaxFields))
	}
	if len(c.errs) > 0 {
		return nil, errors.New("compile: " + strings.Join(c.errs, "; "))
	}
	sum := sha256.Sum256(b)
	p := &Program{SpecID: s.SpecID, Bounds: s.Bounds, DSLHash: "sha256:" + hex.EncodeToString(sum[:]), root: root, fields: c.order}
	canon := map[string]any{"compiler": CompilerVersion, "spec_id": s.SpecID, "bounds": s.Bounds, "root": root.canon()}
	p.canon, _ = json.Marshal(canon) // encoding/json sorts map keys: canonical
	return p, nil
}

func isConsuming(n node) bool {
	if sq, ok := n.(*seqNode); ok {
		return len(sq.steps) > 0 && isConsuming(sq.steps[0])
	}
	return true
}

func (c *compiler) step(raw json.RawMessage, depth int, path string) node {
	if depth > c.bounds.MaxNesting {
		c.fail(path, fmt.Sprintf("nesting depth %d exceeds bounds.max_nesting %d", depth, c.bounds.MaxNesting))
		return nil
	}
	op, isSeq, err := spec.OpOf(raw)
	if err != nil {
		c.fail(path, err.Error())
		return nil
	}
	if isSeq {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		sq := &seqNode{}
		for i, it := range items {
			if n := c.step(it, depth, fmt.Sprintf("%s[%d]", path, i)); n != nil {
				sq.steps = append(sq.steps, n)
			}
		}
		return sq
	}
	switch op {
	case "literal":
		var l spec.Literal
		if err := json.Unmarshal(raw, &l); err != nil || l.Text == "" {
			c.fail(path, "invalid literal")
			return nil
		}
		return &literalNode{text: []byte(l.Text)}
	case "regex":
		var r spec.Regex
		if err := json.Unmarshal(raw, &r); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		return c.regex(&r, depth, path)
	case "csv":
		var v spec.CSV
		if err := json.Unmarshal(raw, &v); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		if len(v.Delimiter) != 1 {
			c.fail(path, "csv delimiter must be one byte")
			return nil
		}
		n := &csvNode{delim: v.Delimiter[0], escape: v.Escape, extra: v.ExtraFields, missing: v.MissingFields}
		if v.Quote != nil && len(*v.Quote) == 1 {
			q := (*v.Quote)[0]
			n.quote = &q
		}
		for i, f := range v.Fields {
			n.fields = append(n.fields, c.csvCell(f, depth+1, fmt.Sprintf("%s.fields[%d]", path, i)))
		}
		return n
	case "kv":
		var v spec.KV
		if err := json.Unmarshal(raw, &v); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		if len(v.KeyValueSeparator) != 1 {
			c.fail(path, "key_value_separator must be one byte")
			return nil
		}
		re, err := regexp.Compile("^(?:" + v.KeyPattern + ")")
		if err != nil {
			c.fail(path, "key_pattern does not compile under RE2: "+err.Error())
			return nil
		}
		n := &kvNode{pairSep: v.PairSeparator, kvSep: v.KeyValueSeparator[0], escape: v.Escape, keyRe: re, keyPattern: v.KeyPattern,
			keys: map[string]csvCell{}, unknown: v.UnknownKeys, order: v.Order, bareKeys: v.AllowBareKeys}
		if v.Quote != nil && len(*v.Quote) == 1 {
			q := (*v.Quote)[0]
			n.quote = &q
		}
		for _, k := range sortedKeys(v.Keys) {
			n.keyOrder = append(n.keyOrder, k)
			n.keys[k] = c.csvCell(v.Keys[k], depth+1, fmt.Sprintf("%s.keys[%s]", path, k))
		}
		return n
	case "json": // parser-spec 1.2.0
		return c.jsonOp(raw, depth, path)
	case "xml": // parser-spec 1.2.0
		return c.xmlOp(raw, depth, path)
	case "positional":
		var v spec.Positional
		if err := json.Unmarshal(raw, &v); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		if err := checkDelim(v.Delimiter); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		n := &positionalNode{delim: v.Delimiter, leading: v.LeadingDelimiter, trailing: v.TrailingDelimiter}
		for i, s := range v.Slots {
			p := fmt.Sprintf("%s.slots[%d]", path, i)
			switch {
			case s.Cell != nil:
				n.slots = append(n.slots, slot{cell: c.cell(s.Cell, depth+1, p)})
			case len(s.Token) > 0:
				n.slots = append(n.slots, slot{token: c.step(s.Token, depth+1, p+".token.parse")})
			case len(s.Step) > 0:
				n.slots = append(n.slots, slot{step: c.step(s.Step, depth+1, p+".step")})
			}
		}
		if v.Tail != nil {
			n.tail = c.cell(v.Tail, depth+1, path+".tail")
		}
		return n
	case "quoted":
		var v spec.Quoted
		if err := json.Unmarshal(raw, &v); err != nil || len(v.Open) != 1 || len(v.Close) != 1 {
			c.fail(path, "invalid quoted op")
			return nil
		}
		n := &quotedNode{open: v.Open[0], close: v.Close[0], escape: v.Escape, content: c.cell(&v.Content, depth+1, path+".content")}
		if len(v.Parse) > 0 {
			n.parse = c.step(v.Parse, depth+1, path+".parse")
		}
		return n
	case "optional":
		var v spec.Optional
		if err := json.Unmarshal(raw, &v); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		return &optionalNode{step: c.step(v.Step, depth+1, path+".step")}
	case "repeated":
		var v spec.Repeated
		if err := json.Unmarshal(raw, &v); err != nil {
			c.fail(path, err.Error())
			return nil
		}
		if v.Min > v.Max {
			c.fail(path, "repeated.min > max")
		}
		if v.Max > c.bounds.MaxRepeat {
			c.fail(path, fmt.Sprintf("repeated.max %d exceeds bounds.max_repeat %d", v.Max, c.bounds.MaxRepeat))
		}
		n := &repeatedNode{min: v.Min, max: v.Max, step: c.step(v.Step, depth+1, path+".step")}
		if len(v.Separator) > 0 {
			n.sep = c.step(v.Separator, depth+1, path+".separator")
		}
		return n
	default:
		c.fail(path, fmt.Sprintf("unknown op %q (the op set is closed)", op))
		return nil
	}
}

func checkDelim(d spec.Delim) error {
	n := 0
	if d.WhitespaceRun {
		n++
	}
	if d.Char != "" {
		if len(d.Char) != 1 {
			return errors.New("delimiter char must be one byte")
		}
		n++
	}
	if d.String != "" {
		n++
	}
	if n != 1 {
		return errors.New("exactly one of whitespace_run / char / string")
	}
	return nil
}

func (c *compiler) csvCell(f spec.CsvCell, depth int, path string) csvCell {
	if f.Cell != nil {
		return csvCell{cell: c.cell(f.Cell, depth, path)}
	}
	return csvCell{parse: c.step(f.Parse, depth, path+".parse")}
}

func (c *compiler) cell(sc *spec.Cell, depth int, path string) *cell {
	if sc.Field == "" {
		c.fail(path, "cell without field")
		return &cell{}
	}
	if c.fields[sc.Field] {
		c.fail(path, fmt.Sprintf("duplicate field path %q", sc.Field))
	}
	c.fields[sc.Field] = true
	c.order = append(c.order, sc.Field)
	if sc.Kind == "opaque" && (sc.Class != "" || sc.Coerce != nil || sc.Decode != nil || sc.NullValues != nil) {
		c.fail(path, "opaque cell cannot carry class/coerce/decode/null_values")
	}
	if sc.Class != "" && classRe(sc.Class) == nil {
		c.fail(path, fmt.Sprintf("unknown token class %q", sc.Class))
	}
	nulls := c.nulls
	if sc.NullValues != nil {
		nulls = sc.NullValues // explicit per-cell list, possibly empty (opt-out)
	}
	out := &cell{Field: sc.Field, Kind: sc.Kind, Class: sc.Class, Coerce: sc.Coerce, Nulls: nulls}
	if sc.Coerce != nil {
		if err := checkCoerce(sc.Coerce); err != nil {
			c.fail(path, err.Error())
		}
	}
	if sc.Decode != nil {
		d := &decodeOp{Encoding: sc.Decode.Encoding, OnFailure: sc.Decode.OnFailure}
		if !knownEncoding(d.Encoding) {
			c.fail(path, fmt.Sprintf("unknown decode encoding %q", d.Encoding))
		}
		if len(sc.Decode.Then) > 0 {
			d.Then = c.step(sc.Decode.Then, depth+1, path+".decode.then")
		}
		out.Decode = d
	}
	return out
}

// regex compiles an anchored RE2 pattern and checks the capture contract: every named group is
// listed in captures and vice versa, and named groups do not nest.
func (c *compiler) regex(r *spec.Regex, depth int, path string) node {
	if len(r.Pattern) > 4096 {
		c.fail(path, "pattern too long")
		return nil
	}
	re, err := regexp.Compile("^(?:" + r.Pattern + ")")
	if err != nil {
		c.fail(path, "regex does not compile under RE2: "+err.Error())
		return nil
	}
	names := re.SubexpNames()
	named := map[string]bool{}
	for _, n := range names {
		if n != "" {
			named[n] = true
		}
	}
	if len(named) != len(r.Captures) {
		c.fail(path, fmt.Sprintf("named groups %v != captures %v", sortedSet(named), sortedKeys(r.Captures)))
		return nil
	}
	for n := range r.Captures {
		if !named[n] {
			c.fail(path, fmt.Sprintf("capture %q is not a named group", n))
			return nil
		}
	}
	if err := namedGroupsNest(r.Pattern); err != nil {
		c.fail(path, err.Error())
		return nil
	}
	n := &regexNode{pattern: r.Pattern, re: re, captures: map[string]*cell{}, names: names}
	for _, k := range sortedKeys(r.Captures) {
		cl := r.Captures[k]
		n.captures[k] = c.cell(&cl, depth+1, path+".captures."+k)
	}
	return n
}

// namedGroupsNest scans the pattern for a named group opening inside another named group.
func namedGroupsNest(p string) error {
	type frame struct{ named bool }
	var stack []frame
	inClass := false
	namedDepth := 0
	for i := 0; i < len(p); i++ {
		ch := p[i]
		switch {
		case ch == '\\':
			i++
		case inClass:
			if ch == ']' {
				inClass = false
			}
		case ch == '[':
			inClass = true
		case ch == '(':
			named := strings.HasPrefix(p[i:], "(?P<")
			if named && namedDepth > 0 {
				return errors.New("named groups must not nest")
			}
			if named {
				namedDepth++
			}
			stack = append(stack, frame{named: named})
		case ch == ')':
			if len(stack) > 0 {
				if stack[len(stack)-1].named {
					namedDepth--
				}
				stack = stack[:len(stack)-1]
			}
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortedSet(m map[string]bool) []string { return sortedKeys(m) }

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---- canonical forms (for parser_hash) ----

func (n *seqNode) canon() any {
	out := make([]any, 0, len(n.steps))
	for _, s := range n.steps {
		out = append(out, s.canon())
	}
	return out
}
func (n *literalNode) canon() any { return map[string]any{"op": "literal", "text": string(n.text)} }
func (n *regexNode) canon() any {
	caps := map[string]any{}
	for k, v := range n.captures {
		caps[k] = v.canon()
	}
	return map[string]any{"op": "regex", "pattern": n.pattern, "captures": caps}
}
func (c *cell) canon() any {
	m := map[string]any{"field": c.Field, "kind": c.Kind}
	if c.Class != "" {
		m["class"] = c.Class
	}
	if c.Coerce != nil {
		m["coerce"] = c.Coerce
	}
	if len(c.Nulls) > 0 {
		m["null_values"] = c.Nulls
	}
	if c.Decode != nil {
		d := map[string]any{"encoding": c.Decode.Encoding, "on_failure": c.Decode.OnFailure}
		if c.Decode.Then != nil {
			d["then"] = c.Decode.Then.canon()
		}
		m["decode"] = d
	}
	return m
}
func (f csvCell) canon() any {
	if f.cell != nil {
		return f.cell.canon()
	}
	return map[string]any{"parse": f.parse.canon()}
}
func (n *csvNode) canon() any {
	fs := make([]any, 0, len(n.fields))
	for _, f := range n.fields {
		fs = append(fs, f.canon())
	}
	var q any
	if n.quote != nil {
		q = string(*n.quote)
	}
	return map[string]any{"op": "csv", "delimiter": string(n.delim), "quote": q, "escape": n.escape, "fields": fs, "extra_fields": n.extra, "missing_fields": n.missing}
}
func (n *kvNode) canon() any {
	ks := map[string]any{}
	for k, v := range n.keys {
		ks[k] = v.canon()
	}
	var q any
	if n.quote != nil {
		q = string(*n.quote)
	}
	return map[string]any{"op": "kv", "pair_separator": n.pairSep, "key_value_separator": string(n.kvSep), "quote": q, "escape": n.escape,
		"key_pattern": n.keyPattern, "keys": ks, "unknown_keys": n.unknown, "order": n.order, "allow_bare_keys": n.bareKeys}
}
func (n *positionalNode) canon() any {
	ss := make([]any, 0, len(n.slots))
	for _, s := range n.slots {
		switch {
		case s.cell != nil:
			ss = append(ss, s.cell.canon())
		case s.token != nil:
			ss = append(ss, map[string]any{"token": s.token.canon()})
		default:
			ss = append(ss, map[string]any{"step": s.step.canon()})
		}
	}
	var tail any
	if n.tail != nil {
		tail = n.tail.canon()
	}
	return map[string]any{"op": "positional", "delimiter": n.delim, "slots": ss, "leading_delimiter": n.leading, "trailing_delimiter": n.trailing, "tail": tail}
}
func (n *quotedNode) canon() any {
	m := map[string]any{"op": "quoted", "open": string(n.open), "close": string(n.close), "escape": n.escape, "content": n.content.canon()}
	if n.parse != nil {
		m["parse"] = n.parse.canon()
	}
	return m
}
func (n *optionalNode) canon() any { return map[string]any{"op": "optional", "step": n.step.canon()} }
func (n *repeatedNode) canon() any {
	m := map[string]any{"op": "repeated", "step": n.step.canon(), "min": n.min, "max": n.max}
	if n.sep != nil {
		m["separator"] = n.sep.canon()
	}
	return m
}
