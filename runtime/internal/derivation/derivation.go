// Package derivation is Proof of Derivation (laptop branch, 2026-09-27). "Prove it" showed that the raw bytes were
// not altered; this proves the DERIVATION: the exact parser pack that processed those bytes — fetched from the Parser
// Transparency Log, its inclusion proof verified — is re-run on them, and its output must equal the event the SIEM
// holds. Everything is packaged into ONE offline-verifiable bundle: the raw bytes, the segment's index, the Merkle proof
// and the signed checkpoint, the pack and its transparency proof, the engine version, and the expected output.
// ulpf-verify checks it with no network and no ULPF running, and says WHICH part fails: the raw bytes, the pack, or the
// SIEM document.
package derivation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/merkle"
	"ulpf/runtime/internal/normalize"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/route"
	"ulpf/runtime/internal/tlog"
)

const BundleVersion = "ulpf-derivation/1"

// Engine names the deterministic engine that re-runs the pack (the same code the runtime runs).
var Engine = "ulpf-engine normalized-event 1.6.0, parser-spec 1.2.0, parser-pack 1.3.0 (laptop branch 2026-09-27); " + runtime.Version()

// Excluded lists every field left out of the comparison, and why. Kept as short as possible: one field. Everything
// else — including the fields the runtime assigns at ingest (event_id, ingest_time, collector_id, ingest_channel,
// segment_id, offset, length, raw_hash, framing, store_id) — is COMPARED: they are inputs taken from the evidence
// record (itself committed by the signed checkpoint through the segment index's hash), not left out.
var Excluded = map[string]string{
	"_lineage.processing_time": "the wall-clock instant at which the runtime normalized the event: it records WHEN, not WHAT, and no re-run can reproduce it",
}

type Bundle struct {
	BundleVersion string            `json:"bundle_version"`
	EventID       string            `json:"event_id"`
	Engine        string            `json:"engine"`
	Evidence      Evidence          `json:"evidence"`
	Pack          Pack              `json:"pack"`
	Expected      json.RawMessage   `json:"expected_output"` // the event as the SIEM holds it (its _source)
	Excluded      map[string]string `json:"excluded_from_comparison"`
	Reference     map[string]string `json:"reference_data_sha256"` // the contract schemas and the pinned OCSF index the pack is loaded against
	CreatedAt     string            `json:"created_at"`
}

type Evidence struct {
	StoreID       string                 `json:"store_id"`
	Source        string                 `json:"source"` // local buffer | archive
	Record        evidence.Record        `json:"record"`
	Raw           []byte                 `json:"raw"`
	SegmentIndex  []byte                 `json:"segment_index"` // the whole index file: its sha256 is in the signed checkpoint
	Leaf          string                 `json:"leaf"`
	LeafIndex     int                    `json:"leaf_index"`
	Proof         []checkpoint.ProofStep `json:"proof"`
	SegmentRoot   string                 `json:"segment_root"`
	Checkpoint    []byte                 `json:"checkpoint"`
	CheckpointSig string                 `json:"checkpoint_sig"`
}

type Pack struct {
	SHA256    string            `json:"sha256"`
	Files     map[string][]byte `json:"files"` // pack.json, pack.json.sig, the spec files — exactly as logged
	TLogProof []byte            `json:"tlog_proof"`
}

type BuildOptions struct {
	Locator      *evidence.Locator
	CommitDir    string
	TLogDir      string
	EventID      string
	Expected     []byte // the SIEM document
	ContractsDir string
	PinnedIndex  string
}

// Build assembles the bundle for one event.
func Build(o BuildOptions) (*Bundle, error) {
	b := &Bundle{BundleVersion: BundleVersion, EventID: o.EventID, Engine: Engine, Excluded: Excluded, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	var exp map[string]any
	if err := json.Unmarshal(o.Expected, &exp); err != nil {
		return nil, fmt.Errorf("the expected output is not a JSON object: %w", err)
	}
	lin, _ := exp["_lineage"].(map[string]any)
	sha, _ := lin["parser_sha256"].(string)
	if sha == "" {
		return nil, errors.New("the event names no parser_sha256 (normalized-event 1.6.0): it predates Proof of Derivation")
	}
	if id, _ := lin["event_id"].(string); id != o.EventID {
		return nil, fmt.Errorf("the expected output is event %s, not %s", id, o.EventID)
	}
	b.Expected = o.Expected
	tmp, err := os.MkdirTemp("", "ulpf-derivation-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	eb, err := checkpoint.ExportFrom(o.Locator, o.CommitDir, o.EventID, tmp)
	if err != nil {
		return nil, err
	}
	raw, _ := os.ReadFile(filepath.Join(tmp, eb.RawFile))
	ck, _ := os.ReadFile(filepath.Join(tmp, eb.CheckpointFile))
	sig, _ := os.ReadFile(filepath.Join(tmp, eb.CheckpointFile+".sig"))
	idx, _, err := o.Locator.ReadFile(eb.Record.SegmentID, evidence.SuffixIdx)
	if err != nil {
		return nil, err
	}
	b.Evidence = Evidence{StoreID: o.Locator.StoreID, Source: eb.EvidenceSource, Record: eb.Record, Raw: raw, SegmentIndex: idx, Leaf: eb.Leaf, LeafIndex: eb.LeafIndex,
		Proof: eb.Proof, SegmentRoot: eb.SegmentRoot, Checkpoint: ck, CheckpointSig: strings.TrimSpace(string(sig))}
	// the exact pack, from the transparency log's content store, and its inclusion proof
	lg := &tlog.Log{Dir: o.TLogDir}
	i := lg.Find(sha)
	if i < 0 {
		return nil, fmt.Errorf("pack %s is not in the parser transparency log at %s", sha, o.TLogDir)
	}
	proof, err := lg.Prove(i)
	if err != nil {
		return nil, err
	}
	b.Pack = Pack{SHA256: sha, Files: map[string][]byte{}, TLogProof: []byte(proof)}
	store := filepath.Join(o.TLogDir, "packs", strings.TrimPrefix(sha, "sha256:"))
	err = filepath.Walk(store, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(store, p)
		data, err := os.ReadFile(p)
		b.Pack.Files[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		return nil, err
	}
	b.Reference = referenceHashes(o.ContractsDir, o.PinnedIndex)
	return b, nil
}

func referenceHashes(contractsDir, pinnedIndex string) map[string]string {
	out := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(contractsDir, "*.schema.json"))
	files = append(files, pinnedIndex)
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			out[filepath.Base(f)] = evidence.Hash(data)
		}
	}
	return out
}

// Step is one verification step; Part is what it proves: "raw bytes", "pack" or "SIEM document".
type Step struct {
	Part   string `json:"part"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type Report struct {
	OK        bool              `json:"ok"`
	Culprit   string            `json:"culprit,omitempty"` // the first part that failed: raw bytes | pack | SIEM document
	Steps     []Step            `json:"steps"`
	Differing []FieldDiff       `json:"differing_fields,omitempty"`
	Derived   json.RawMessage   `json:"derived_output,omitempty"`
	Excluded  map[string]string `json:"excluded_from_comparison"`
	Engine    string            `json:"engine"`
	TLog      *tlog.Verified    `json:"transparency_log,omitempty"`
}

type FieldDiff struct {
	Field   string `json:"field"`
	Derived any    `json:"derived"`
	SIEM    any    `json:"siem"`
}

type VerifyOptions struct {
	TrustDir, ContractsDir, PinnedIndex string
	MinWitnesses                        int
}

// Verify checks a bundle with no network and no ULPF running.
func Verify(b *Bundle, o VerifyOptions) Report {
	r := Report{Excluded: Excluded, Engine: Engine}
	add := func(part, name string, ok bool, detail string) bool {
		r.Steps = append(r.Steps, Step{part, name, ok, detail})
		if !ok && r.Culprit == "" {
			r.Culprit = part
		}
		return ok
	}
	ev := b.Evidence
	rec := ev.Record
	rec.StoreID = ev.StoreID
	// ---- 1. the raw bytes: unaltered, and committed
	rawHash := evidence.Hash(ev.Raw)
	add("raw bytes", "raw bytes hash to the evidence record", rawHash == rec.RawHash && len(ev.Raw) == rec.Length,
		fmt.Sprintf("%d bytes hash to %s; the record says %s", len(ev.Raw), rawHash, rec.RawHash))
	var ck checkpoint.Checkpoint
	_ = json.Unmarshal(ev.Checkpoint, &ck)
	trust := keys.TrustStore{Dir: o.TrustDir}
	add("raw bytes", "checkpoint signature", trust.Verify(ck.AuthorityID, ev.Checkpoint, ev.CheckpointSig) == nil,
		fmt.Sprintf("checkpoint %s signed by %s (%s)", ck.CheckpointID, ck.AuthorityID, ck.Mode()))
	var sr *checkpoint.SegmentRoot
	for i := range ck.Segments {
		if ck.Segments[i].SegmentID == rec.SegmentID && ck.Segments[i].Root == ev.SegmentRoot {
			sr = &ck.Segments[i]
		}
	}
	add("raw bytes", "the checkpoint commits the segment", sr != nil, fmt.Sprintf("%s root %s", rec.SegmentID, ev.SegmentRoot))
	idxOK := sr != nil && evidence.Hash(ev.SegmentIndex) == sr.IdxSHA256
	inIdx := false
	for _, l := range bytes.Split(bytes.TrimSpace(ev.SegmentIndex), []byte("\n")) {
		var x evidence.Record
		if json.Unmarshal(l, &x) == nil && x.EventID == rec.EventID {
			x.StoreID = rec.StoreID
			inIdx = reflect.DeepEqual(x, rec)
		}
	}
	add("raw bytes", "the evidence record is in the committed segment index", idxOK && inIdx,
		"the index's sha256 is the one the signed checkpoint names, and it holds this record field for field")
	rh, err1 := merkle.Parse(rec.RawHash)
	root, err2 := merkle.Parse(ev.SegmentRoot)
	var steps []merkle.Step
	for _, s := range ev.Proof {
		h, _ := merkle.Parse(s.Sibling)
		steps = append(steps, merkle.Step{Sibling: h, Left: s.Left})
	}
	leaf := merkle.Leaf(rec.SegmentID, rec.Offset, rec.Length, rh)
	add("raw bytes", "Merkle inclusion proof", err1 == nil && err2 == nil && leaf.String() == ev.Leaf && merkle.Verify(leaf, steps, root),
		fmt.Sprintf("leaf %d of %s reaches the committed segment root", ev.LeafIndex, rec.SegmentID))
	// ---- 2. the pack: the logged one, byte for byte
	dir, err := os.MkdirTemp("", "ulpf-derivation-pack-")
	if err != nil {
		add("pack", "unpack", false, err.Error())
		return r
	}
	defer os.RemoveAll(dir)
	for name, data := range b.Pack.Files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, data, 0o644)
	}
	os.WriteFile(filepath.Join(dir, tlog.ProofFile), b.Pack.TLogProof, 0o644)
	sum := sha256.Sum256(b.Pack.Files["pack.json"])
	packSHA := "sha256:" + hex.EncodeToString(sum[:])
	pol, _ := tlog.LoadPolicy(o.TrustDir, o.MinWitnesses)
	var head struct {
		ID      string `json:"pack_id"`
		Version string `json:"pack_version"`
	}
	json.Unmarshal(b.Pack.Files["pack.json"], &head)
	tv, terr := tlog.VerifyProof(b.Pack.TLogProof, packSHA, head.ID, head.Version, pol)
	if terr == nil {
		r.TLog = &tv
		add("pack", "the pack is in the parser transparency log", true, fmt.Sprintf("%s v%s is entry %d of %s (checkpoint size %d; produced by %s, logged %s; witness cosignatures: %d)",
			head.ID, head.Version, tv.Index, tv.Log, tv.Checkpoint.Size, tv.Entry.ProducedBy, tv.Entry.LoggedAt, len(tv.Witnesses)))
	} else {
		add("pack", "the pack is in the parser transparency log", false, terr.Error())
	}
	var exp map[string]any
	_ = json.Unmarshal(b.Expected, &exp)
	lin, _ := exp["_lineage"].(map[string]any)
	named, _ := lin["parser_sha256"].(string)
	add("pack", "the SIEM document names this exact pack", named == packSHA, fmt.Sprintf("parser_sha256 %s; the bundled pack.json is %s", named, packSHA))
	for name, want := range b.Reference {
		var have string
		if name == filepath.Base(o.PinnedIndex) {
			if d, err := os.ReadFile(o.PinnedIndex); err == nil {
				have = evidence.Hash(d)
			}
		} else if d, err := os.ReadFile(filepath.Join(o.ContractsDir, name)); err == nil {
			have = evidence.Hash(d)
		}
		if have != want {
			add("pack", "reference data", false, fmt.Sprintf("%s here hashes to %s, the bundle was built against %s", name, have, want))
		}
	}
	p, lerr := pack.Load(dir, pack.LoadOptions{ContractsDir: o.ContractsDir, PinnedIndex: o.PinnedIndex, TrustDir: o.TrustDir, TLogMinWitnesses: o.MinWitnesses})
	if !add("pack", "the pack loads (signature, transparency log, contract, compiled parsers)", lerr == nil, errString(lerr, "loaded by the same fail-closed loader the runtime uses")) {
		return r
	}
	// ---- 3. the derivation: re-run, then compare with what the SIEM holds
	var pt int64
	if v, ok := lin["processing_time"].(float64); ok {
		pt = int64(v)
	}
	derived, derr := Derive(p, rec, ev.Raw, time.UnixMilli(pt))
	if !add("SIEM document", "the pack re-run on the raw bytes", derr == nil, errString(derr, "routed, parsed and normalized by "+Engine)) {
		return r
	}
	db, _ := json.Marshal(derived)
	r.Derived = db
	var dm map[string]any
	_ = json.Unmarshal(db, &dm)
	r.Differing = diff(dm, exp, "")
	var names []string
	for _, d := range r.Differing {
		names = append(names, d.Field)
	}
	add("SIEM document", "the derivation equals the event the SIEM holds", len(r.Differing) == 0,
		map[bool]string{true: fmt.Sprintf("identical, field for field (%d excluded: %s)", len(Excluded), strings.Join(excludedNames(), ", ")),
			false: "DIFFERS in: " + strings.Join(names, ", ")}[len(r.Differing) == 0])
	r.OK = r.Culprit == ""
	return r
}

// Derive runs exactly what the runtime runs on one frame: unwrap the envelopes, route (only this pack is loaded),
// parse, normalize — with the evidence record as the ingest context.
func Derive(p *pack.Pack, rec evidence.Record, raw []byte, processing time.Time) (map[string]any, error) {
	ch := frame.UnwrapChain(raw)
	payload := raw[ch.PayloadOffset : ch.PayloadOffset+ch.PayloadLength]
	rt := route.New(p)
	if err := rt.Err(); err != nil {
		return nil, err
	}
	d := rt.RouteChain(payload, ch)
	if d.Family == nil {
		return nil, fmt.Errorf("the pack does not route these bytes: %s (%s)", d.Stage, d.Reason)
	}
	m, err := d.Family.Program.Parse(payload, dsl.Env{SourceLocation: d.Pack.Location, IngestTime: time.UnixMilli(rec.IngestTime)})
	if err != nil {
		return nil, err
	}
	m.Event.EventID = rec.EventID
	if m.Status != "ok" {
		return nil, fmt.Errorf("the pack does not parse these bytes: at %d: %s", m.Failure.AtOffset, m.Failure.Reason)
	}
	var chain *frame.Chain
	if ch.Depth() > 1 {
		chain = &ch
	}
	ev, _, err := normalize.Normalize(m, normalize.Context{Pack: d.Pack, Family: d.Family, Record: rec, Signature: d.Signature, ProcessingTime: processing, Envelope: ch.Innermost(), Chain: chain})
	return ev, err
}

func excludedNames() []string {
	var out []string
	for k := range Excluded {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// diff lists the fields (dotted paths) whose values differ, skipping the excluded ones.
func diff(a, b map[string]any, prefix string) []FieldDiff {
	var out []FieldDiff
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var ks []string
	for k := range keys {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if _, skip := Excluded[path]; skip {
			continue
		}
		av, aok := a[k]
		bv, bok := b[k]
		am, amap := av.(map[string]any)
		bm, bmap := bv.(map[string]any)
		switch {
		case aok && bok && amap && bmap:
			out = append(out, diff(am, bm, path)...)
		case !reflect.DeepEqual(av, bv) || aok != bok:
			out = append(out, FieldDiff{Field: path, Derived: av, SIEM: bv})
		}
	}
	return out
}

func errString(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}
