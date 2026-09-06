// Package contracts loads and validates the four frozen ULPF contracts on the runtime side.
//
// The runtime never trusts the learning plane's validation: every document is checked against
// its JSON Schema and the semantic invariants here, and an unknown schema_version is refused
// before any other processing (fail closed).
package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type Kind string

const (
	ParserSpec  Kind = "parser-spec"
	SpanMap     Kind = "span-map"
	Certificate Kind = "ambiguity-certificate"
	ParserPack  Kind = "parser-pack"
	// NormalizedEvent is the runtime's output envelope (OCSF JSON + _lineage), frozen at P2 exit.
	NormalizedEvent Kind = "normalized-event"
)

var Kinds = []Kind{ParserSpec, SpanMap, Certificate, ParserPack, NormalizedEvent}

// Supported lists the contract versions this runtime build understands.
var Supported = map[Kind][]string{
	ParserSpec: {"1.0.0", "1.1.0"}, SpanMap: {"1.0.0", "1.1.0"}, Certificate: {"1.0.0"}, ParserPack: {"1.0.0", "1.1.0", "1.2.0", "1.3.0"}, NormalizedEvent: {"1.0.0", "1.1.0", "1.2.0"},
}

var ErrUnsupportedVersion = errors.New("unsupported schema_version")

var forbiddenKeys = map[string]bool{"confidence": true, "probability": true, "score": true, "likelihood": true}

type Loader struct {
	schemas    map[Kind]*jsonschema.Schema
	pinned     map[int64]string          // class uid -> table_hash
	leaves     map[int64]map[string]bool // class uid -> leaf attribute paths
	categories map[int64]int64           // class uid -> category uid
}

// CategoryUID returns the OCSF category of a pinned class.
func (l *Loader) CategoryUID(uid int64) (int64, bool) {
	c, ok := l.categories[uid]
	return c, ok
}

// NewLoader compiles the four schemas from contractsDir and, when pinnedIndex exists, loads the
// pinned OCSF class tables used by the subset guard.
func NewLoader(contractsDir, pinnedIndex string) (*Loader, error) {
	l := &Loader{schemas: map[Kind]*jsonschema.Schema{}, pinned: map[int64]string{}, leaves: map[int64]map[string]bool{}, categories: map[int64]int64{}}
	c := jsonschema.NewCompiler()
	for _, k := range Kinds {
		sch, err := c.Compile(filepath.Join(contractsDir, string(k)+".schema.json"))
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", k, err)
		}
		l.schemas[k] = sch
	}
	if pinnedIndex != "" {
		if raw, err := os.ReadFile(pinnedIndex); err == nil {
			var idx struct {
				Classes []struct {
					UID         int64  `json:"uid"`
					CategoryUID int64  `json:"category_uid"`
					TableHash   string `json:"table_hash"`
					File        string `json:"file"`
				} `json:"classes"`
			}
			if err := json.Unmarshal(raw, &idx); err != nil {
				return nil, fmt.Errorf("pinned index: %w", err)
			}
			root := filepath.Dir(filepath.Dir(filepath.Dir(pinnedIndex)))
			for _, cl := range idx.Classes {
				l.pinned[cl.UID] = cl.TableHash
				l.categories[cl.UID] = cl.CategoryUID
				traw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(cl.File)))
				if err != nil {
					return nil, fmt.Errorf("pinned table %s: %w", cl.File, err)
				}
				var t struct {
					LeafPaths []struct {
						Path string `json:"path"`
					} `json:"leaf_paths"`
				}
				if err := json.Unmarshal(traw, &t); err != nil {
					return nil, fmt.Errorf("pinned table %s: %w", cl.File, err)
				}
				set := map[string]bool{}
				for _, lp := range t.LeafPaths {
					set[lp.Path] = true
				}
				l.leaves[cl.UID] = set
			}
		}
	}
	return l, nil
}

// Load reads a contract document from disk and validates it. For packs, files referenced
// relative to the pack directory are checked too.
func (l *Loader) Load(kind Kind, path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	v, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("document is not a JSON object")
	}
	packDir := ""
	if kind == ParserPack {
		packDir = filepath.Dir(path)
	}
	if errs := l.Validate(kind, doc, packDir); len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return doc, nil
}

// Validate checks version, schema and semantic invariants. It returns every problem found.
func (l *Loader) Validate(kind Kind, doc map[string]any, packDir string) []error {
	ver, _ := doc["schema_version"].(string)
	if kind == NormalizedEvent {
		// the version lives inside _lineage for this envelope
		if lin, ok := doc["_lineage"].(map[string]any); ok {
			ver, _ = lin["schema_version"].(string)
		}
	}
	if !contains(Supported[kind], ver) {
		return []error{fmt.Errorf("%w: %q for %s (supported %v) — refused", ErrUnsupportedVersion, ver, kind, Supported[kind])}
	}
	if err := l.schemas[kind].Validate(doc); err != nil {
		return []error{fmt.Errorf("schema: %w", err)}
	}
	switch kind {
	case ParserSpec:
		return checkSpec(doc)
	case SpanMap:
		return checkSpanMap(doc)
	case Certificate:
		return l.checkCertificate(doc)
	case ParserPack:
		return l.checkPack(doc, packDir)
	}
	return nil
}

// ---------------------------------------------------------------- parser spec

var consumingOps = map[string]bool{"literal": true, "regex": true, "csv": true, "kv": true, "positional": true, "quoted": true, "optional": true, "repeated": true}

type specCtx struct {
	errs       []error
	fields     map[string]bool
	maxNesting int64
	maxRepeat  int64
	maxFields  int64
}

func checkSpec(doc map[string]any) []error {
	b := doc["bounds"].(map[string]any)
	ctx := &specCtx{fields: map[string]bool{}, maxNesting: num(b["max_nesting"]), maxRepeat: num(b["max_repeat"]), maxFields: num(b["max_fields"])}
	walkSpec(doc["root"], ctx, 1, "$.root")
	first := doc["root"]
	for {
		arr, ok := first.([]any)
		if !ok || len(arr) == 0 {
			break
		}
		first = arr[0]
	}
	if m, ok := first.(map[string]any); !ok || !consumingOps[str(m["op"])] {
		ctx.errs = append(ctx.errs, errors.New("$.root: root must begin with a consuming op"))
	}
	return ctx.errs
}

func walkSpec(step any, ctx *specCtx, depth int64, path string) {
	if depth > ctx.maxNesting {
		ctx.errs = append(ctx.errs, fmt.Errorf("%s: nesting depth %d exceeds bounds.max_nesting", path, depth))
		return
	}
	if arr, ok := step.([]any); ok {
		for i, s := range arr {
			walkSpec(s, ctx, depth, fmt.Sprintf("%s[%d]", path, i))
		}
		return
	}
	m := step.(map[string]any)
	switch str(m["op"]) {
	case "regex":
		checkRegex(str(m["pattern"]), m["captures"].(map[string]any), ctx, path)
		for name, cell := range m["captures"].(map[string]any) {
			checkCell(cell.(map[string]any), ctx, depth+1, path+".captures."+name)
		}
	case "literal":
	case "csv":
		for i, c := range m["fields"].([]any) {
			checkCsvCell(c.(map[string]any), ctx, depth+1, fmt.Sprintf("%s.fields[%d]", path, i))
		}
	case "kv":
		if _, err := regexp.Compile(str(m["key_pattern"])); err != nil {
			ctx.errs = append(ctx.errs, fmt.Errorf("%s: key_pattern does not compile under RE2: %v", path, err))
		}
		for k, c := range m["keys"].(map[string]any) {
			checkCsvCell(c.(map[string]any), ctx, depth+1, path+".keys["+k+"]")
		}
	case "positional":
		for i, s := range m["slots"].([]any) {
			slot := s.(map[string]any)
			p := fmt.Sprintf("%s.slots[%d]", path, i)
			switch {
			case slot["field"] != nil:
				checkCell(slot, ctx, depth+1, p)
			case slot["token"] != nil:
				walkSpec(slot["token"].(map[string]any)["parse"], ctx, depth+1, p+".token.parse")
			case slot["step"] != nil:
				walkSpec(slot["step"], ctx, depth+1, p+".step")
			}
		}
		if t, ok := m["tail"].(map[string]any); ok {
			checkCell(t, ctx, depth+1, path+".tail")
		}
	case "quoted":
		checkCell(m["content"].(map[string]any), ctx, depth+1, path+".content")
		if p, ok := m["parse"]; ok {
			walkSpec(p, ctx, depth+1, path+".parse")
		}
	case "optional":
		walkSpec(m["step"], ctx, depth+1, path+".step")
	case "repeated":
		if num(m["min"]) > num(m["max"]) {
			ctx.errs = append(ctx.errs, fmt.Errorf("%s: repeated.min > max", path))
		}
		if num(m["max"]) > ctx.maxRepeat {
			ctx.errs = append(ctx.errs, fmt.Errorf("%s: repeated.max exceeds bounds.max_repeat", path))
		}
		walkSpec(m["step"], ctx, depth+1, path+".step")
		if sep, ok := m["separator"]; ok {
			walkSpec(sep, ctx, depth+1, path+".separator")
		}
	default:
		ctx.errs = append(ctx.errs, fmt.Errorf("%s: unknown op %q", path, str(m["op"])))
	}
}

func checkRegex(pattern string, captures map[string]any, ctx *specCtx, path string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		ctx.errs = append(ctx.errs, fmt.Errorf("%s: regex does not compile under RE2 (Go regexp): %v", path, err))
		return
	}
	groups := map[string]bool{}
	for _, n := range re.SubexpNames() {
		if n != "" {
			groups[n] = true
		}
	}
	if len(groups) != len(captures) {
		ctx.errs = append(ctx.errs, fmt.Errorf("%s: named groups %v != captures %v", path, keys(groups), keysAny(captures)))
		return
	}
	for n := range captures {
		if !groups[n] {
			ctx.errs = append(ctx.errs, fmt.Errorf("%s: capture %q is not a named group", path, n))
		}
	}
}

func checkCsvCell(c map[string]any, ctx *specCtx, depth int64, path string) {
	if p, ok := c["parse"]; ok {
		walkSpec(p, ctx, depth, path+".parse")
		return
	}
	checkCell(c, ctx, depth, path)
}

func checkCell(c map[string]any, ctx *specCtx, depth int64, path string) {
	f := str(c["field"])
	if ctx.fields[f] {
		ctx.errs = append(ctx.errs, fmt.Errorf("%s: duplicate field path %q", path, f))
	}
	ctx.fields[f] = true
	if int64(len(ctx.fields)) > ctx.maxFields {
		ctx.errs = append(ctx.errs, fmt.Errorf("%s: field count exceeds bounds.max_fields", path))
	}
	if d, ok := c["decode"].(map[string]any); ok {
		if then, ok := d["then"]; ok {
			walkSpec(then, ctx, depth+1, path+".decode.then")
		}
	}
}

// SpecFields returns the set of field paths a spec produces.
func SpecFields(spec map[string]any) map[string]bool {
	b := spec["bounds"].(map[string]any)
	ctx := &specCtx{fields: map[string]bool{}, maxNesting: 1 << 20, maxRepeat: num(b["max_repeat"]), maxFields: 1 << 20}
	walkSpec(spec["root"], ctx, 1, "$.root")
	return ctx.fields
}

// ---------------------------------------------------------------- span map

type spanRec struct {
	start, end int64
	idx        int
	span       map[string]any
}

func checkSpanMap(doc map[string]any) []error {
	var errs []error
	if str(doc["status"]) != "ok" {
		return nil
	}
	ev := doc["event"].(map[string]any)
	lengths := map[string]int64{}
	for _, b := range doc["buffers"].([]any) {
		bm := b.(map[string]any)
		lengths[str(bm["id"])] = num(bm["length"])
	}
	if _, ok := lengths["raw"]; !ok {
		return []error{errors.New("buffers: no 'raw' buffer")}
	}
	if lengths["raw"] != num(ev["raw_length"]) {
		errs = append(errs, errors.New("buffers[raw].length != event.raw_length"))
	}
	byBuf := map[string][]spanRec{}
	for i, s := range doc["spans"].([]any) {
		sm := s.(map[string]any)
		buf := str(sm["buffer"])
		if _, ok := lengths[buf]; !ok {
			errs = append(errs, fmt.Errorf("spans[%d]: unknown buffer %q", i, buf))
			continue
		}
		if num(sm["start"]) >= num(sm["end"]) {
			errs = append(errs, fmt.Errorf("spans[%d]: start >= end", i))
		}
		byBuf[buf] = append(byBuf[buf], spanRec{num(sm["start"]), num(sm["end"]), i, sm})
	}
	for buf, length := range lengths {
		recs := byBuf[buf]
		sort.Slice(recs, func(a, b int) bool { return recs[a].start < recs[b].start })
		var pos int64
		for _, r := range recs {
			if r.start < pos {
				errs = append(errs, fmt.Errorf("spans[%d]: overlap in buffer %q at %d (expected >= %d)", r.idx, buf, r.start, pos))
			} else if r.start > pos {
				errs = append(errs, fmt.Errorf("spans[%d]: gap in buffer %q [%d:%d)", r.idx, buf, pos, r.start))
			}
			if r.end > pos {
				pos = r.end
			}
			if str(r.span["kind"]) == "literal" {
				if t, ok := r.span["text"].(string); ok && int64(len(t)) != r.end-r.start {
					errs = append(errs, fmt.Errorf("spans[%d]: literal text length != span length", r.idx))
				}
			}
		}
		if pos != length {
			errs = append(errs, fmt.Errorf("buffer %q: spans cover [0:%d) but length is %d", buf, pos, length))
		}
	}
	if b64, ok := ev["raw_base64"].(string); ok {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return append(errs, fmt.Errorf("event.raw_base64: %v", err))
		}
		if int64(len(raw)) != num(ev["raw_length"]) {
			errs = append(errs, errors.New("event.raw_base64 length != raw_length"))
		}
		if sha256Hex(raw) != str(ev["raw_hash"]) {
			errs = append(errs, errors.New("event.raw_base64 sha256 != raw_hash"))
		}
		for _, r := range byBuf["raw"] {
			if r.end > int64(len(raw)) || r.start < 0 {
				continue
			}
			seg := raw[r.start:r.end]
			if str(r.span["kind"]) == "literal" {
				if t, ok := r.span["text"].(string); ok && !bytes.Equal(seg, []byte(t)) {
					errs = append(errs, fmt.Errorf("spans[%d]: literal text does not match raw bytes", r.idx))
				}
			}
			if str(r.span["kind"]) == "semantic" {
				if v, ok := r.span["value"].(string); ok && r.span["encoding"] == nil && !bytes.Equal(seg, []byte(v)) {
					errs = append(errs, fmt.Errorf("spans[%d]: value does not match raw bytes", r.idx))
				}
			}
		}
	}
	return errs
}

// ---------------------------------------------------------------- certificate

func (l *Loader) checkCertificate(doc map[string]any) []error {
	errs := forbidden(doc, "$")
	en := doc["enumeration"].(map[string]any)
	cand := map[string]bool{}
	for _, c := range en["candidates"].([]any) {
		cand[str(c.(map[string]any)["attribute"])] = true
	}
	surv := map[string]bool{}
	for _, s := range en["survivors"].([]any) {
		surv[str(s)] = true
		if !cand[str(s)] {
			errs = append(errs, fmt.Errorf("enumeration.survivors not a subset of candidates: %q", str(s)))
		}
	}
	uid := num(doc["event_class"].(map[string]any)["uid"])
	if leaves, ok := l.leaves[uid]; ok {
		for a := range cand {
			if !leaves[a] {
				errs = append(errs, fmt.Errorf("enumeration.candidates not in the pinned class table: %q", a))
			}
		}
	}
	ranked := doc["ranked_candidates"].([]any)
	seen := map[string]bool{}
	for i, r := range ranked {
		rm := r.(map[string]any)
		a := str(rm["attribute"])
		if seen[a] {
			errs = append(errs, errors.New("ranked_candidates: duplicate attribute"))
		}
		seen[a] = true
		if !surv[a] {
			errs = append(errs, fmt.Errorf("ranked_candidates not a subset of survivors: %q", a))
		}
		if num(rm["rank"]) != int64(i+1) {
			errs = append(errs, errors.New("ranked_candidates: ranks must be 1..n in order"))
		}
	}
	status := str(doc["status"])
	if (status == "ambiguous" || status == "unresolved") && len(surv) < 2 {
		errs = append(errs, fmt.Errorf("status %s requires at least two survivors", status))
	}
	if status == "ambiguous" {
		req := doc["request"].(map[string]any)
		disc := doc["evidence"].(map[string]any)["discriminator"].(map[string]any)
		if str(req["ambiguity_class"]) != str(disc["ambiguity_class"]) {
			errs = append(errs, errors.New("request.ambiguity_class != evidence.discriminator.ambiguity_class"))
		}
		sel := req["selected"].(map[string]any)
		if num(sel["rank"]) != 1 {
			errs = append(errs, errors.New("request.selected must have rank 1"))
		}
		field := str(doc["field"].(map[string]any)["path"])
		found := false
		for _, f := range sel["resolves"].([]any) {
			if str(f) == field {
				found = true
			}
		}
		if !found {
			errs = append(errs, errors.New("request.selected.resolves must include this certificate's field"))
		}
	}
	if status == "resolved" {
		res := doc["resolution"].(map[string]any)
		if !surv[str(res["resolved_to"])] {
			errs = append(errs, errors.New("resolution.resolved_to must be one of enumeration.survivors"))
		}
		ps := res["propagation_scope"].(map[string]any)
		cx := doc["context"].(map[string]any)
		if str(ps["source_id"]) != str(doc["source_id"]) {
			errs = append(errs, errors.New("resolution.propagation_scope.source_id != source_id"))
		}
		for _, k := range []string{"l1_envelope", "l2_structure", "l3_anchors", "slot_index", "token_class"} {
			if !bytes.Equal(canon(ps[k]), canon(cx[k])) {
				errs = append(errs, fmt.Errorf("resolution.propagation_scope.%s != context.%s", k, k))
			}
		}
	}
	return errs
}

// ---------------------------------------------------------------- pack

func (l *Loader) checkPack(doc map[string]any, packDir string) []error {
	errs := forbidden(doc, "$")
	famIDs := map[string]bool{}
	anchorIDs := map[string]bool{}
	for _, a := range doc["anchors"].([]any) {
		anchorIDs[str(a.(map[string]any)["anchor_id"])] = true
	}
	pinnedUIDs := map[int64]bool{}
	for _, c := range doc["ocsf"].(map[string]any)["pinned_classes"].([]any) {
		cm := c.(map[string]any)
		uid := num(cm["uid"])
		pinnedUIDs[uid] = true
		if len(l.pinned) > 0 {
			want, ok := l.pinned[uid]
			if !ok {
				errs = append(errs, fmt.Errorf("ocsf.pinned_classes: class %d is not in the pinned index", uid))
			} else if want != str(cm["table_hash"]) {
				errs = append(errs, fmt.Errorf("ocsf.pinned_classes: table_hash for class %d does not match the pinned (complete) table — subset guard", uid))
			}
		}
	}
	var dslHashes, mappingHashes, parserHashes []string
	allPaths := map[string]bool{}
	srcID := str(doc["source"].(map[string]any)["source_id"])
	for fi, f := range doc["families"].([]any) {
		fam := f.(map[string]any)
		p := fmt.Sprintf("families[%d]", fi)
		id := str(fam["family_id"])
		if famIDs[id] {
			errs = append(errs, errors.New("families: duplicate family_id"))
		}
		famIDs[id] = true
		uid := num(fam["event_class_uid"])
		if !pinnedUIDs[uid] {
			errs = append(errs, fmt.Errorf("%s: event_class_uid not among ocsf.pinned_classes", p))
		}
		for _, aid := range fam["routing_signature"].(map[string]any)["l3_anchor_ids"].([]any) {
			if !anchorIDs[str(aid)] {
				errs = append(errs, fmt.Errorf("%s: l3_anchor_id %q not declared in anchors", p, str(aid)))
			}
		}
		parser := fam["parser"].(map[string]any)
		var specFields map[string]bool
		if packDir != "" {
			specPath := filepath.Join(packDir, filepath.FromSlash(str(parser["spec_ref"])))
			raw, err := os.ReadFile(specPath)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: spec_ref %s not found", p, str(parser["spec_ref"])))
			} else {
				if sha256Hex(raw) != str(parser["dsl_hash"]) {
					errs = append(errs, fmt.Errorf("%s: dsl_hash does not match sha256 of %s", p, str(parser["spec_ref"])))
				}
				v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: spec: invalid JSON: %v", p, err))
				} else if spec, ok := v.(map[string]any); ok {
					sub := l.Validate(ParserSpec, spec, "")
					for _, e := range sub {
						errs = append(errs, fmt.Errorf("%s: spec: %w", p, e))
					}
					if str(spec["spec_id"]) != str(parser["spec_id"]) {
						errs = append(errs, fmt.Errorf("%s: spec_id does not match the referenced spec", p))
					}
					if len(sub) == 0 {
						specFields = SpecFields(spec)
					}
				}
			}
			for _, cid := range fam["certificates"].([]any) {
				if _, err := os.Stat(filepath.Join(packDir, "certificates", str(cid)+".json")); err != nil {
					errs = append(errs, fmt.Errorf("%s: certificate %s not found under certificates/", p, str(cid)))
				}
			}
		}
		dslHashes = append(dslHashes, str(parser["dsl_hash"]))
		parserHashes = append(parserHashes, str(parser["parser_hash"]))
		m := fam["mapping"].(map[string]any)
		if sha256Hex(canon(m["fields"])) != str(m["mapping_hash"]) {
			errs = append(errs, fmt.Errorf("%s: mapping_hash != sha256 of canonical mapping.fields", p))
		}
		mappingHashes = append(mappingHashes, str(m["mapping_hash"]))
		snap := m["acceptance_snapshot"].(map[string]any)
		mandatory := map[string]bool{}
		for _, a := range snap["mandatory_attributes"].([]any) {
			mandatory[str(a)] = true
		}
		mapped := map[string]bool{}
		paths := map[string]bool{}
		leaves := l.leaves[uid]
		for i, fld := range m["fields"].([]any) {
			fm := fld.(map[string]any)
			attr := str(fm["ocsf_attribute"])
			if mapped[attr] {
				errs = append(errs, fmt.Errorf("%s: mapping.fields: an OCSF attribute is mapped more than once", p))
			}
			mapped[attr] = true
			hasPath := fm["path"] != nil
			if hasPath {
				paths[str(fm["path"])] = true
				allPaths[str(fm["path"])] = true
			}
			if leaves != nil && !leaves[attr] {
				errs = append(errs, fmt.Errorf("%s.mapping.fields[%d]: %q is not an attribute of the pinned class table", p, i, attr))
			}
			prov := fm["provenance"].(map[string]any)
			isMandatory, _ := fm["mandatory"].(bool)
			if isMandatory && str(prov["category"]) == "model_proposal" {
				errs = append(errs, fmt.Errorf("%s.mapping.fields[%d]: mandatory field with model_proposal provenance (invariant 4)", p, i))
			}
			if str(prov["category"]) == "structural_determination" {
				es, _ := prov["enumerated_survivors"].([]any)
				if len(es) != 1 || str(es[0]) != attr {
					errs = append(errs, fmt.Errorf("%s.mapping.fields[%d]: structural_determination requires enumerated_survivors == [ocsf_attribute]", p, i))
				}
			}
			if mandatory[attr] && !isMandatory {
				errs = append(errs, fmt.Errorf("%s.mapping.fields[%d]: attribute is in mandatory_attributes but mandatory is false", p, i))
			}
			if hasPath && specFields != nil && !specFields[str(fm["path"])] {
				errs = append(errs, fmt.Errorf("%s.mapping.fields[%d]: path %q is not a field of the spec", p, i, str(fm["path"])))
			}
		}
		for a := range mandatory {
			if !mapped[a] {
				errs = append(errs, fmt.Errorf("%s: mandatory attribute not mapped (critical coverage < 100%%): %q", p, a))
			}
		}
		knownPaths := map[string]bool{}
		for k := range paths {
			knownPaths[k] = true
		}
		for _, u := range m["unmapped"].([]any) {
			knownPaths[str(u.(map[string]any)["path"])] = true
		}
		for i, r := range fam["resolutions"].([]any) {
			rm := r.(map[string]any)
			for _, fp := range rm["fields"].([]any) {
				if !knownPaths[str(fp)] {
					errs = append(errs, fmt.Errorf("%s.resolutions[%d]: field %q is neither a mapped nor an unmapped path", p, i, str(fp)))
				}
			}
			if str(rm["propagation_scope"].(map[string]any)["source_id"]) != srcID {
				errs = append(errs, fmt.Errorf("%s.resolutions[%d]: propagation_scope.source_id != source.source_id", p, i))
			}
		}
		ho := fam["validation"].(map[string]any)["held_out"].(map[string]any)
		if num(ho["passed"]) > num(ho["samples"]) {
			errs = append(errs, fmt.Errorf("%s: held_out.passed > samples", p))
		}
	}
	if tb, ok := doc["tiebreaker_field"].(string); ok && !allPaths[tb] {
		errs = append(errs, errors.New("tiebreaker_field is not a mapped path in any family"))
	}
	h := doc["hashes"].(map[string]any)
	if sha256Hex([]byte(strings.Join(dslHashes, ""))) != str(h["dsl_hash"]) {
		errs = append(errs, errors.New("hashes.dsl_hash != sha256 of concatenated family dsl_hash values"))
	}
	if sha256Hex([]byte(strings.Join(mappingHashes, ""))) != str(h["mapping_hash"]) {
		errs = append(errs, errors.New("hashes.mapping_hash != sha256 of concatenated family mapping_hash values"))
	}
	_ = parserHashes
	return errs
}

// ---------------------------------------------------------------- helpers

func forbidden(v any, path string) []error {
	var errs []error
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if forbiddenKeys[strings.ToLower(k)] {
				errs = append(errs, fmt.Errorf("%s.%s: forbidden key (no numeric confidence in any contract)", path, k))
			}
			errs = append(errs, forbidden(val, path+"."+k)...)
		}
	case []any:
		for i, val := range t {
			errs = append(errs, forbidden(val, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return errs
}

// canon produces the canonical JSON used for mapping_hash: sorted keys, no whitespace, no HTML
// escaping — matching Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
func canon(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func num(v any) int64 {
	switch t := v.(type) {
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			f, _ := t.Float64()
			return int64(f)
		}
		return i
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	}
	return 0
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysAny(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
