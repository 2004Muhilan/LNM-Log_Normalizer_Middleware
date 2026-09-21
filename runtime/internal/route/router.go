// Package route is the compiled routing decision DAG (architecture §3.4, plan P6): L1 envelope,
// L2 structure detection, L3 anchors, L4 arity/token-class sketch, then the hard cap K=4 and
// quarantine. There is no tiebreaker stage: a secondary discriminator that could be read before
// parsing is an anchor, and one that cannot would require parsing to route (dropped at the P6 boundary). It never executes a parser to find out which one fits
// (invariant 6): every stage reads cheap surface facts of the payload — envelope kind, leading bytes,
// delimiter counts, anchor locators — and only narrows the candidate set. Exactly one survivor routes.
//
// L1 semantics (P6 decision, raised in the report): a family that declares `raw` has no envelope
// requirement — the same payload arrives with or without a relay header, and P5's tests already route
// syslog-wrapped Squid. A family that declares a syslog envelope requires one (either RFC form, since
// relays rewrite 3164 into 5424). Laptop branch: a `raw` family does NOT match a payload that arrived inside an
// APPLICATION envelope (CEF, LEEF) — that envelope names the format; only a relay's syslog header imposes nothing.
// L2 detection collapses `positional`, `template` and `mixed` into one surface class (whitespace tokens); the
// anchors and the L4 sketch separate them.
package route

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/pack"
)

// K is the hard cap on the candidate set after L4. More than one survivor quarantines with the
// candidates named; more than K quarantines as a cap breach — the size is what the stats record.
const K = 4

type Decision struct {
	Pack      *pack.Pack
	Family    *pack.Family
	Signature string // the L1–L4 key the router computed for the event
	// Candidates is the size of the candidate set after L4 — the empirical
	// answer to the K=4 question is the distribution of this number.
	Candidates int
	Stage      string // when Family is nil: routing | routing_ambiguous | routing_cap | routing_drift
	Reason     string
	// Drift marks an anchor whose located value lies outside its declared domain: a drift signal for
	// P8's monitors, kept apart from an unknown signature.
	Drift bool
}

type fam struct {
	pack    *pack.Pack
	family  *pack.Family
	l2      string // detected surface class this family lives in: tokens | csv | kv | json
	anchors map[string]map[string]bool
	arityLo int
	arityHi int
	classes []string // positional only
	lits    map[int]string
}

type anchorRT struct {
	pack *pack.Pack
	a    *pack.Anchor
	re   *regexp.Regexp
	l2s  map[string]bool // surface classes of the pack's families: a slot/key locator reads no other surface
}

type Router struct {
	fams    []*fam
	anchors []*anchorRT
	err     error
}

// New builds the DAG over one or more loaded packs (a mixed stream carries every onboarded source).
func New(packs ...*pack.Pack) *Router {
	r := &Router{}
	for _, p := range packs {
		for i := range p.Anchors {
			a := &p.Anchors[i]
			if a.Status == "retired" {
				continue
			}
			rt := &anchorRT{pack: p, a: a, l2s: map[string]bool{}}
			for _, f := range p.Families {
				rt.l2s[surfaceClass(f.Routing.L2)] = true
			}
			if a.Locator.Kind == "pattern" {
				re, err := regexp.Compile(a.Locator.Pattern)
				if err != nil || re.SubexpIndex("anchor") < 0 {
					r.err = fmt.Errorf("pack %s anchor %s: pattern locator must compile and name a group 'anchor'", p.PackID, a.AnchorID)
					continue
				}
				rt.re = re
			}
			r.anchors = append(r.anchors, rt)
		}
		for i := range p.Families {
			f := &p.Families[i]
			e := &fam{pack: p, family: f, l2: surfaceClass(f.Routing.L2), anchors: map[string]map[string]bool{}, lits: map[int]string{}}
			for _, av := range f.Routing.L3AnchorValues {
				set := map[string]bool{}
				for _, v := range av.Values {
					set[v] = true
				}
				e.anchors[av.AnchorID] = set
			}
			e.arityLo, e.arityHi = bucket(f.Routing.L4.ArityBucket)
			if f.Routing.L2 == "positional" {
				e.classes = f.Routing.L4.TokenClassSequence
				for _, l := range f.Routing.L3StructuralLits {
					e.lits[l.SlotIndex] = l.Text
				}
			}
			r.fams = append(r.fams, e)
		}
	}
	return r
}

// Err reports a pack whose anchors the router could not compile (the pack loader should have refused it).
func (r *Router) Err() error { return r.err }

func surfaceClass(l2 string) string {
	switch l2 {
	case "csv", "kv", "json":
		return l2
	case "xml": // parser-spec 1.2.0
		return "xml"
	default: // positional | template | mixed
		return "tokens"
	}
}

func bucket(b string) (int, int) {
	if b == "" {
		return 0, 1 << 30
	}
	if lo, hi, ok := strings.Cut(b, "-"); ok {
		l, _ := strconv.Atoi(lo)
		h, _ := strconv.Atoi(hi)
		return l, h
	}
	n, _ := strconv.Atoi(b)
	return n, n
}

// ---------------------------------------------------------------- surface facts

var (
	reInt   = regexp.MustCompile(`^-?[0-9]+$`)
	reFloat = regexp.MustCompile(`^-?[0-9]+\.[0-9]+$`)
	reWord  = regexp.MustCompile(`^[A-Za-z0-9_.:\-]+$`)
	reHostP = regexp.MustCompile(`^[A-Za-z0-9.\-]+:[0-9]+$`)
	reKVTok = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*=`)
)

// classify is the cheap per-token structural classifier used for the L4 sketch.
func classify(tok string) string {
	switch {
	case reInt.MatchString(tok):
		return "integer"
	case reFloat.MatchString(tok):
		return "float"
	case strings.Count(tok, ".") == 3 && net.ParseIP(tok) != nil:
		return "ipv4"
	case strings.Contains(tok, "://") || reHostP.MatchString(tok):
		return "url"
	case reWord.MatchString(tok):
		return "word"
	default:
		return "text"
	}
}

// surface is everything L2–L4 read from the payload: computed once per event, never by parsing.
type surface struct {
	l2    string
	toks  []string // whitespace tokens (tokens class)
	cells []string // quote-aware csv cells (csv class)
	pairs map[string]string
	arity int
}

// detectL2 decides the surface class from leading bytes and delimiter counts. Deterministic, ordered:
// json (leading brace/bracket) > kv (the first tokens are key=value) > csv (many commas outside
// quotes) > tokens.
func detectL2(payload []byte) surface {
	s := surface{}
	trimmed := bytes.TrimLeft(payload, " \t")
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		s.l2 = "json"
		return s
	}
	if len(trimmed) > 1 && trimmed[0] == '<' && (trimmed[1] == '?' || trimmed[1] == '!' || trimmed[1] >= 'A' && trimmed[1] <= 'Z' || trimmed[1] >= 'a' && trimmed[1] <= 'z' || trimmed[1] == '_') {
		s.l2 = "xml" // parser-spec 1.2.0: a payload that opens a tag, a declaration or a comment (a syslog <PRI> was unwrapped before this)
		return s
	}
	toks := strings.Fields(string(payload))
	kv := 0
	for i, t := range toks {
		if i >= 6 {
			break
		}
		if reKVTok.MatchString(t) {
			kv++
		}
	}
	if kv >= 3 {
		s.l2 = "kv"
		s.pairs, s.arity = kvPairs(payload)
		return s
	}
	cells := csvCells(payload)
	if len(cells) >= 9 {
		s.l2 = "csv"
		s.cells, s.arity = cells, len(cells)
		return s
	}
	s.l2 = "tokens"
	s.toks, s.arity = toks, len(toks)
	return s
}

// csvCells splits on commas outside double quotes (doubled quotes escape); a surface count, not a parse.
func csvCells(b []byte) []string {
	var cells []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '"':
			if inQ && i+1 < len(b) && b[i+1] == '"' {
				cur.WriteByte('"')
				i++
				continue
			}
			inQ = !inQ
		case c == ',' && !inQ:
			cells = append(cells, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	cells = append(cells, cur.String())
	return cells
}

// kvPairs reads key=value pairs separated by whitespace, values optionally double-quoted (backslash
// escape). First occurrence of a key wins; the count is the number of pairs seen.
func kvPairs(b []byte) (map[string]string, int) {
	out := map[string]string{}
	n := 0
	i := 0
	for i < len(b) {
		for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
			i++
		}
		start := i
		for i < len(b) && b[i] != '=' && b[i] != ' ' && b[i] != '\t' {
			i++
		}
		if i >= len(b) || b[i] != '=' {
			// a bare token: skip it
			for i < len(b) && b[i] != ' ' && b[i] != '\t' {
				i++
			}
			continue
		}
		key := string(b[start:i])
		i++ // '='
		var val string
		if i < len(b) && b[i] == '"' {
			i++
			var sb strings.Builder
			for i < len(b) && b[i] != '"' {
				if b[i] == '\\' && i+1 < len(b) {
					i++
				}
				sb.WriteByte(b[i])
				i++
			}
			i++ // closing quote
			val = sb.String()
		} else {
			vs := i
			for i < len(b) && b[i] != ' ' && b[i] != '\t' {
				i++
			}
			val = string(b[vs:i])
		}
		n++
		if _, seen := out[key]; !seen {
			out[key] = val
		}
	}
	return out, n
}

// locate evaluates one anchor locator against the surface facts; ok=false when the anchor is absent.
func (rt *anchorRT) locate(payload []byte, s surface, env *frame.Envelope) (string, bool) {
	if !rt.l2s[s.l2] && rt.a.Locator.Kind != "envelope_header" {
		return "", false // a PAN-OS cell-4 anchor says nothing about an ASA token line
	}
	switch rt.a.Locator.Kind {
	case "pattern":
		m := rt.re.FindSubmatch(payload)
		if m == nil {
			return "", false
		}
		return string(m[rt.re.SubexpIndex("anchor")]), true
	case "slot":
		i := rt.a.Locator.SlotIndex
		switch s.l2 {
		case "csv":
			if i < len(s.cells) {
				return s.cells[i], true
			}
		case "tokens":
			if i < len(s.toks) {
				return s.toks[i], true
			}
		}
		return "", false
	case "key":
		if s.l2 != "kv" {
			return "", false
		}
		v, ok := s.pairs[rt.a.Locator.Key]
		return v, ok
	case "envelope_header":
		if env == nil {
			return "", false
		}
		switch rt.a.Locator.HeaderField {
		case "hostname":
			return env.Hostname, env.Hostname != ""
		case "app_name":
			return env.AppName, env.AppName != ""
		case "msg_id":
			return env.MsgID, env.MsgID != ""
		case "proc_id":
			return env.ProcID, env.ProcID != ""
		// P7: CEF application-envelope header fields (kind cef)
		case "signature_id":
			return env.SignatureID, env.SignatureID != ""
		case "device_vendor":
			return env.DeviceVendor, env.DeviceVendor != ""
		case "device_product":
			return env.DeviceProduct, env.DeviceProduct != ""
		case "name":
			return env.Name, env.Name != ""
		}
	}
	return "", false
}

// ---------------------------------------------------------------- the DAG

// Route narrows the onboarded families to the one that owns this event, or quarantines with the stage
// and reason. payload is the unwrapped payload; env the envelope it arrived in (nil when none).
func (r *Router) Route(payload []byte, env *frame.Envelope) Decision {
	var ch frame.Chain
	if env != nil && env.Kind != "none" {
		ch.Envelopes = []frame.Envelope{*env}
	}
	return r.RouteChain(payload, ch)
}

// RouteChain routes the innermost payload of a recursively unwrapped message (P7). L1 matches the
// family's declared envelope against every envelope removed: a `raw` family has no requirement; a
// syslog family (rfc3164/rfc5424) needs a syslog envelope somewhere in the chain (either RFC form —
// relays rewrite 3164 as 5424, P6 decision); a `cef` family needs the CEF application envelope.
// Anchors and envelope-sourced fields read the innermost envelope, the device's own header.
func (r *Router) RouteChain(payload []byte, ch frame.Chain) Decision {
	env := ch.Innermost()
	kinds := ch.Kinds()
	l1 := "raw"
	if len(kinds) > 0 {
		l1 = kinds[len(kinds)-1]
	}
	hasSyslog, hasCEF, hasLEEF := false, false, false
	for _, k := range kinds {
		switch k {
		case "rfc3164", "rfc5424":
			hasSyslog = true
		case "cef":
			hasCEF = true
		case "leef":
			hasLEEF = true
		}
	}
	// L2
	s := detectL2(payload)
	var cands []*fam
	for _, f := range r.fams {
		if f.l2 != s.l2 {
			continue
		}
		switch f.family.Routing.L1 {
		case "raw":
			if hasCEF || hasLEEF {
				continue // laptop branch: an APPLICATION envelope (CEF, LEEF) names its format — a bare family does not own what arrived inside one (a relay's syslog header is still no requirement)
			}
		case "cef":
			if !hasCEF {
				continue // the family requires a CEF header and none arrived
			}
		case "leef":
			if !hasLEEF {
				continue // the family requires a LEEF header and none arrived
			}
		default:
			if !hasSyslog {
				continue // the family requires a transport envelope and none arrived
			}
		}
		cands = append(cands, f)
	}
	// L3: evaluate every anchor of every pack still in play, once
	type located struct {
		val      string
		inDomain bool
	}
	found := map[*pack.Pack]map[string]located{}
	var drift []string
	seenPack := map[*pack.Pack]bool{}
	for _, f := range cands {
		seenPack[f.pack] = true
	}
	for _, rt := range r.anchors {
		if !seenPack[rt.pack] {
			continue
		}
		v, ok := rt.locate(payload, s, env)
		if !ok {
			continue
		}
		in := rt.a.InDomain(v)
		if found[rt.pack] == nil {
			found[rt.pack] = map[string]located{}
		}
		found[rt.pack][rt.a.AnchorID] = located{v, in}
		if !in {
			drift = append(drift, fmt.Sprintf("anchor %s located %q outside its declared domain", rt.a.AnchorID, v))
		}
	}
	var anchorKey []string
	var l3 []*fam
	var unowned []string
	for _, f := range cands {
		ok := true
		for id, want := range f.anchors {
			loc, has := found[f.pack][id]
			if !has || !loc.inDomain || !want[loc.val] {
				ok = false
				if has && loc.inDomain && !want[loc.val] {
					unowned = append(unowned, fmt.Sprintf("%s=%s", id, loc.val))
				}
				break
			}
		}
		if ok {
			l3 = append(l3, f)
			for id := range f.anchors {
				anchorKey = append(anchorKey, id+"="+found[f.pack][id].val)
			}
		}
	}
	// L4
	var l4 []*fam
	for _, f := range l3 {
		switch s.l2 {
		case "tokens":
			if f.classes != nil {
				if len(f.classes) != len(s.toks) || !sketchMatches(f, s.toks) {
					continue
				}
			}
		case "csv", "kv":
			if s.arity < f.arityLo || s.arity > f.arityHi {
				continue
			}
		}
		l4 = append(l4, f)
	}
	sort.Strings(anchorKey)
	anchorKey = dedupe(anchorKey)
	sig := fmt.Sprintf("%s|%s|%s|%d", l1, s.l2, strings.Join(anchorKey, ","), s.arity)
	if s.l2 == "tokens" {
		classes := make([]string, len(s.toks))
		for i, t := range s.toks {
			classes[i] = classify(t)
		}
		sig += "|" + strings.Join(classes, ",")
	}
	d := Decision{Signature: sig, Candidates: len(l4)}
	switch {
	case len(l4) == 1:
		d.Pack, d.Family = l4[0].pack, l4[0].family
		return d
	case len(l4) == 0:
		d.Stage, d.Reason = "routing", "unknown signature: no onboarded family matches (quarantined, not guessed)"
		if len(drift) > 0 {
			d.Stage, d.Drift = "routing_drift", true
			d.Reason = "drift signal: " + strings.Join(dedupe(drift), "; ")
		} else if len(unowned) > 0 {
			d.Reason = fmt.Sprintf("anchor value in the declared domain but no onboarded family owns it (%s): family discovery input", strings.Join(dedupe(unowned), ","))
		}
		return d
	case len(l4) > K:
		d.Stage, d.Reason = "routing_cap", fmt.Sprintf("candidate set of %d exceeds K=%d after L4 (quarantined)", len(l4), K)
		return d
	}
	// 2..K candidates: quarantine with the candidates named (no tiebreaker stage — see the package doc)
	ids := make([]string, len(l4))
	for i, f := range l4 {
		ids[i] = f.pack.PackID + "/" + f.family.FamilyID
	}
	d.Stage, d.Reason = "routing_ambiguous", fmt.Sprintf("%d candidates [%s] share the L1–L4 key (quarantined, not guessed)", len(l4), strings.Join(ids, " "))
	return d
}

func dedupe(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func sketchMatches(f *fam, toks []string) bool {
	for i, want := range f.classes {
		if want == "literal" {
			if f.lits[i] != toks[i] {
				return false
			}
			continue
		}
		if want != classify(toks[i]) {
			return false
		}
	}
	return true
}

// Signature computes the interim L1/L2/L4 key for a raw positional event (kept for the P2 tests and
// the golden vectors; the DAG's own key is Decision.Signature).
func Signature(raw []byte) (string, []string, []string) {
	toks := strings.Fields(string(raw))
	classes := make([]string, len(toks))
	for i, t := range toks {
		classes[i] = classify(t)
	}
	return fmt.Sprintf("raw|positional|%d|%s", len(toks), strings.Join(classes, ",")), toks, classes
}
