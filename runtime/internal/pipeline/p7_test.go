package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"ulpf/runtime/internal/checkpoint"
	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/gap"
	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/pack"
)

// validateEvents checks every emitted event against contracts/normalized-event.schema.json (1.3.0).
func validateEvents(t *testing.T, jsonl string) int {
	t.Helper()
	sch, err := jsonschema.NewCompiler().Compile(filepath.Join(repoRoot(t), "contracts", "normalized-event.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(jsonl), "\n") {
		if line == "" {
			continue
		}
		v, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(v); err != nil {
			t.Fatalf("event violates the contract: %v\n%s", err, line)
		}
		n++
	}
	return n
}

func lineageOf(t *testing.T, line string) map[string]any {
	t.Helper()
	var ev map[string]any
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatal(err)
	}
	return ev["_lineage"].(map[string]any)
}

// A relay re-wraps the proxy's RFC 3164 lines as RFC 5424: both envelopes come off, the Squid pack
// (declared raw) still owns the payload, lineage carries the innermost envelope as `envelope` and the
// whole chain as relay_chain, the event validates against 1.3.0, and the evidence keeps every byte.
func TestRelayChainIsUnwrappedAndRecorded(t *testing.T) {
	p := loadGoldenPack(t)
	in, _ := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	var wrapped bytes.Buffer
	for _, l := range bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n")) {
		wrapped.WriteString("<134>1 2024-12-19T00:00:00Z relay01 relay - - [meta sequenceId=\"1\"] <134>Dec 19 00:00:00 proxy01 squid[1234]: ")
		wrapped.Write(l)
		wrapped.WriteString("\n")
	}
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	n := 0
	o.NewID = func(time.Time) string { n++; return fmt.Sprintf("ev_%026d", n) } // more than nine records here
	st, err := Run(bytes.NewReader(wrapped.Bytes()), o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frames != 6 || st.Emitted != 6 || st.Enveloped != 6 || st.RelayChains != 6 || st.Quarantined != 0 {
		t.Fatalf("stats: %+v\n%s", st, q.String())
	}
	if validateEvents(t, out.String()) != 6 {
		t.Fatal("six events must validate")
	}
	lin := lineageOf(t, strings.Split(out.String(), "\n")[0])
	if lin["schema_version"] != "1.6.0" || lin["store_id"] == nil { // 1.5.0: the evidence store is named (evidence archive)
		t.Fatalf("lineage version: %v", lin["schema_version"])
	}
	envl := lin["envelope"].(map[string]any)
	if envl["kind"] != "rfc3164" || envl["hostname"] != "proxy01" || envl["level"] != 2.0 {
		t.Fatalf("envelope must be the innermost (device) header: %v", envl)
	}
	chain := lin["relay_chain"].([]any)
	if len(chain) != 2 || chain[0].(map[string]any)["kind"] != "rfc5424" || chain[0].(map[string]any)["hostname"] != "relay01" || chain[1].(map[string]any)["hostname"] != "proxy01" {
		t.Fatalf("relay_chain: %v", chain)
	}
	got, _, _ := evidence.Reconstruct(o.EvidenceDir)
	if !bytes.Equal(got, wrapped.Bytes()) {
		t.Fatal("reconstruction must return the relayed stream byte for byte")
	}
	// the same sequenceId on every message from one peer: a reset each time after the first, recorded
	if st.GapRecords != 5 || st.GapKinds["sequence_reset"] != 5 {
		t.Fatalf("a repeated sequence id is a reset, recorded as a leaf: %+v", st.GapKinds)
	}
}

// cefPack builds, in memory, a one-family pack for a CEF-emitting device: declared envelope cef,
// kv surface (the extension), anchored on the CEF header's signature id, time from `rt`.
func cefPack(t *testing.T) *pack.Pack {
	t.Helper()
	spec := `{"schema_version":"1.0.0","spec_id":"cef-fw-100","regex_dialect":"re2",
 "bounds":{"max_event_bytes":16384,"max_fields":64,"max_nesting":3,"max_repeat":16},
 "root":{"op":"kv","pair_separator":{"whitespace_run":true},"key_value_separator":"=","quote":"\"","escape":"backslash",
  "key_pattern":"[A-Za-z][A-Za-z0-9_]*","unknown_keys":"opaque","order":"any","allow_bare_keys":false,
  "keys":{
   "rt":{"field":"rt","kind":"semantic","class":"integer","coerce":{"op":"coerce","to":"timestamp","on_failure":"reject","format":{"kind":"epoch_auto","timezone":"utc"}}},
   "src":{"field":"src","kind":"semantic","class":"ip","coerce":{"op":"coerce","to":"ip","on_failure":"reject"}},
   "dst":{"field":"dst","kind":"semantic","class":"ip","coerce":{"op":"coerce","to":"ip","on_failure":"reject"}},
   "spt":{"field":"spt","kind":"semantic","class":"integer","coerce":{"op":"coerce","to":"int","on_failure":"reject"}},
   "dpt":{"field":"dpt","kind":"semantic","class":"integer","coerce":{"op":"coerce","to":"int","on_failure":"reject"}},
   "act":{"field":"act","kind":"semantic","class":"word"}}}}`
	prog, err := dsl.Compile([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	p := &pack.Pack{PackID: "cef-test", PackVersion: "1.0"}
	p.Source.SourceID, p.Source.Vendor, p.Source.Product = "cef-fw-01", "Vendor", "Product"
	p.OCSF.Version = "1.3.0"
	p.Time.TimezoneConfidence = "unresolved"
	p.CategoryUIDs = map[int]int64{4001: 4}
	var a pack.Anchor
	a.AnchorID, a.Status = "cef-signature-id", "active"
	a.Locator.Kind, a.Locator.HeaderField = "envelope_header", "signature_id"
	a.Domain.Kind, a.Domain.Values = "enum", []string{"100", "200"}
	p.Anchors = []pack.Anchor{a}
	var f pack.Family
	f.FamilyID, f.EventClassUID = "cef-100", 4001
	f.Routing.L1, f.Routing.L2 = "cef", "kv"
	f.Routing.L3AnchorIDs = []string{"cef-signature-id"}
	f.Routing.L3AnchorValues = []pack.AnchorValues{{AnchorID: "cef-signature-id", Values: []string{"100"}}}
	f.Parser.SpecID, f.Parser.DSLHash, f.Parser.ParserHash = "cef-fw-100", prog.DSLHash, prog.ParserHash()
	f.Program = prog
	prov := json.RawMessage(`{"category":"vendor_schema_or_device_configuration"}`)
	f.Mapping.MappingVersion = "1.0"
	f.Mapping.Fields = []pack.MappingField{
		{Path: "rt", OCSFAttribute: "time", Mandatory: true, Provenance: prov},
		{Path: "src", OCSFAttribute: "src_endpoint.ip", Mandatory: true, Provenance: prov},
		{Path: "dst", OCSFAttribute: "dst_endpoint.ip", Mandatory: true, Provenance: prov},
		{Constant: 2, OCSFAttribute: "action_id", Mandatory: true, Provenance: prov},
	}
	f.Mapping.Acceptance.MandatoryAttributes = []string{"time", "src_endpoint.ip", "dst_endpoint.ip", "action_id"}
	p.Families = []pack.Family{f}
	return p
}

// The syslog-forwarded CEF stream routes to the CEF pack (plan P7 demonstrable outcome): the relay's
// syslog envelope and the CEF application envelope both come off, the anchor reads the CEF header,
// Squid lines on the same stream still route to Squid, and a line with a CEF header in the middle of
// its text is payload — quarantined as unroutable, bytes retained, never a CEF event.
func TestForwardedCEFRoutesToItsPack(t *testing.T) {
	squid := loadGoldenPack(t)
	cef := cefPack(t)
	in := "<13>Jan  5 04:05:06 fw01 cef: CEF:0|Vendor|Product|1.0|100|Blocked|5|rt=1734567890123 src=10.0.0.1 dst=10.0.0.2 spt=1234 dpt=443 act=blocked\n" +
		"CEF:0|Vendor|Product|1.0|100|Blocked|5|rt=1734567890124 src=10.0.0.3 dst=10.0.0.4 spt=1 dpt=2 act=allowed\n" +
		"<134>Dec 19 00:00:00 proxy01 squid[1234]: 1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://x/ - HIER_DIRECT/1.2.3.4 text/html\n" +
		"<13>Jan  5 04:05:06 fw01 cef: note: CEF:0|Vendor|Product|1.0|100|Blocked|5|rt=1 src=10.0.0.1 dst=10.0.0.2\n" +
		"<13>Jan  5 04:05:06 fw01 cef: CEF:0|Vendor|Product|1.0|200|Other|5|rt=1734567890125 src=10.0.0.5 dst=10.0.0.6\n"
	var out, q bytes.Buffer
	o := fixedOpts(t, squid, &out, &q)
	o.Pack, o.Packs, o.SourceID = nil, []*pack.Pack{squid, cef}, "relay-01"
	st, err := Run(strings.NewReader(in), o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frames != 5 || st.Emitted != 3 || st.Quarantined != 2 || st.ByFamily["cef-test/cef-100"] != 2 || st.ByFamily["squid-native/positional-10"] != 1 {
		t.Fatalf("stats: %+v\n%s", st, q.String())
	}
	validateEvents(t, out.String())
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	lin := lineageOf(t, lines[0])
	chain := lin["relay_chain"].([]any)
	if len(chain) != 2 || chain[0].(map[string]any)["kind"] != "rfc3164" || chain[1].(map[string]any)["kind"] != "cef" || lin["envelope"].(map[string]any)["signature_id"] != "100" {
		t.Fatalf("forwarded CEF lineage: %v", lin)
	}
	var ev map[string]any
	json.Unmarshal([]byte(lines[0]), &ev)
	if ev["time"] != 1734567890123.0 || ev["src_endpoint"].(map[string]any)["ip"] != "10.0.0.1" {
		t.Fatalf("cef event: %v", ev)
	}
	// the bare CEF line (no syslog) is a cef-declared family's event too: one envelope, no relay chain
	if lin1 := lineageOf(t, lines[1]); lin1["relay_chain"] != nil || lin1["envelope"].(map[string]any)["kind"] != "cef" {
		t.Fatalf("bare CEF: %v", lin1)
	}
	// the ambiguous line: CEF text inside the payload never became an event; its bytes are evidence
	qs := q.String()
	if !strings.Contains(qs, "routing") {
		t.Fatalf("quarantine: %s", qs)
	}
	got, _, _ := evidence.Reconstruct(o.EvidenceDir)
	if !bytes.Contains(got, []byte("note: CEF:0|")) {
		t.Fatal("the ambiguous line must be retained as evidence")
	}
}

// De-batching end to end: a JSON array of Squid events (as a collector would batch them) becomes N
// evidence records, each hashed on its own bytes, each event carrying the batch hash/index/size, and
// the store reconstructs the batch byte for byte. (The golden pack is positional, so the elements are
// JSON strings holding Squid lines — the pipeline sees the element bytes, quotes included, and the
// router quarantines them as json surface: what this test proves is framing and evidence, not parsing.)
func TestDebatchProducesIndependentlyHashedRecords(t *testing.T) {
	p := loadGoldenPack(t)
	batch := `[{"n":1,"msg":"first"}, {"n":2,"msg":"second"},{"n":3}]` + "\n"
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	st, err := Run(strings.NewReader(batch), o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Received != 1 || st.Frames != 3 || st.BatchElements != 3 || st.Quarantined != 3 {
		t.Fatalf("stats: %+v", st)
	}
	recs, _ := evidence.ReadIndex(o.EvidenceDir, "seg_00000")
	if len(recs) != 3 {
		t.Fatalf("records: %d", len(recs))
	}
	hashes := map[string]bool{}
	for i, r := range recs {
		if r.Framing.Method != "batch_element" || r.Framing.BatchIndex != i || r.Framing.BatchSize != 3 || r.Framing.BatchHash == "" {
			t.Fatalf("record %d: %+v", i, r.Framing)
		}
		hashes[r.RawHash] = true
	}
	if len(hashes) != 3 {
		t.Fatal("elements must be hashed independently")
	}
	if got, _, _ := evidence.Reconstruct(o.EvidenceDir); string(got) != batch {
		t.Fatalf("reconstruction: %q", got)
	}
	// with de-batching off the array is one frame
	var out2, q2 bytes.Buffer
	o2 := fixedOpts(t, p, &out2, &q2)
	o2.NoDebatch = true
	st2, _ := Run(strings.NewReader(batch), o2)
	if st2.Frames != 1 || st2.BatchElements != 0 {
		t.Fatalf("no-debatch: %+v", st2)
	}
}

// Gap records are evidence-log leaves (plan P7, the novelty claim): a peer goes silent; the silence
// record is appended to the same segment as the events; it is hashed, committed under a signed
// checkpoint, exported as a bundle that verifies with only the trust store, listed by the verifier —
// and byte-exact reconstruction of the stream is unaffected. Deleting the record breaks the root.
func TestGapRecordsAreCommittedLeaves(t *testing.T) {
	p := loadGoldenPack(t)
	in, _ := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	lines := bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n"))
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	o.Now = nil // real clock: silence is measured
	o.SilenceAfter = 120 * time.Millisecond
	o.Channel = "tcp:test"
	mk := func(peer string, l []byte) frame.Frame {
		return frame.Frame{Raw: l, Peer: peer, Framing: frame.Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte("\n"), FragmentCount: 1, OriginalMessageLength: len(l), TruncationStatus: "none", FramingConfidence: "high"}}
	}
	var stream bytes.Buffer
	src := func(emit func(frame.Frame) error) error {
		for i, l := range lines[:4] {
			peer := "10.0.0.1:514"
			if i%2 == 1 {
				peer = "10.0.0.2:514"
			}
			stream.Write(l)
			stream.WriteByte('\n')
			if err := emit(mk(peer, l)); err != nil {
				return err
			}
		}
		time.Sleep(400 * time.Millisecond) // both peers silent past the threshold
		stream.Write(lines[4])
		stream.WriteByte('\n')
		return emit(mk("10.0.0.1:514", lines[4])) // peer 1 resumes; peer 2 stays silent
	}
	st, err := RunFrames(src, o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Emitted != 5 || st.GapKinds["silence"] != 2 || st.GapKinds["silence_end"] != 1 || st.GapRecords != 3 || st.Peers != 2 {
		rawAll, _ := os.ReadFile(filepath.Join(o.EvidenceDir, "seg_00000.raw"))
		t.Fatalf("stats: %+v\n%s", st, rawAll)
	}
	// the gap records sit among the event records of the same segment
	recs, _ := evidence.ReadIndex(o.EvidenceDir, "seg_00000")
	var gaps []evidence.Record
	for _, r := range recs {
		if r.Framing.Method == evidence.MethodGapRecord {
			gaps = append(gaps, r)
		}
	}
	if len(recs) != 8 || len(gaps) != 3 || gaps[0].Peer == "" {
		t.Fatalf("records: %d gaps: %d", len(recs), len(gaps))
	}
	raw, _ := os.ReadFile(filepath.Join(o.EvidenceDir, "seg_00000.raw"))
	g0, err := gap.Parse(raw[gaps[0].Offset : gaps[0].Offset+int64(gaps[0].Length)])
	if err != nil || g0.Kind != "silence" || g0.SilenceMS < 120 || g0.Channel != "tcp:test" || g0.SourceID != "squid-proxy-01" {
		t.Fatalf("gap record: %v %+v", err, g0)
	}
	// reconstruction ignores the gap records and returns the stream
	got, all, err := evidence.Reconstruct(o.EvidenceDir)
	if err != nil || !bytes.Equal(got, stream.Bytes()) || len(all) != 8 {
		t.Fatalf("reconstruct: %v %d\n%q", err, len(all), got)
	}
	// commit (the store was closed by RunFrames, so the segment is sealed) and verify
	key, _ := keys.Generate("ulpf-committer-test")
	pretend := func(dir, seg string) string {
		if evidence.SegmentState(dir, seg) == "sealed" {
			return "immutable"
		}
		return evidence.SegmentState(dir, seg)
	}
	rep, err := checkpoint.Commit(o.EvidenceDir, "", key, pretend, time.Now())
	if err != nil || len(rep.Committed) != 1 {
		t.Fatalf("commit: %v %+v", err, rep)
	}
	td := t.TempDir()
	key.PublicOnly().Save(filepath.Join(td, key.AuthorityID+".pub.json"))
	trust := keys.TrustStore{Dir: td}
	entries, err := checkpoint.Gaps(o.EvidenceDir, "", trust)
	if err != nil || len(entries) != 3 {
		t.Fatalf("gaps: %v %d", err, len(entries))
	}
	for _, e := range entries {
		if !e.Committed || !e.RootVerified || !e.SignatureOK || e.Problem != "" || e.CheckpointID != "ckpt_000001" {
			t.Fatalf("entry: %+v", e)
		}
	}
	// export the silence record as a bundle: the witness verifies it with nothing but the public key
	bdir := t.TempDir()
	b, err := checkpoint.Export(o.EvidenceDir, "", gaps[0].EventID, bdir)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := checkpoint.VerifyBundle(bdir, trust); err != nil || len(f) != 0 {
		t.Fatalf("bundle: %v %v", err, f)
	}
	if b.Record.Framing.Method != evidence.MethodGapRecord {
		t.Fatal("the bundle carries the gap record's framing")
	}
	// tamper: remove the silence record from the index -> the committed root no longer recomputes
	idxPath := filepath.Join(o.EvidenceDir, "seg_00000.idx.jsonl")
	os.Chmod(idxPath, 0o644)
	idx, _ := os.ReadFile(idxPath)
	var kept [][]byte
	for _, l := range bytes.Split(bytes.TrimRight(idx, "\n"), []byte("\n")) {
		if !bytes.Contains(l, []byte(gaps[0].EventID)) {
			kept = append(kept, l)
		}
	}
	os.WriteFile(idxPath, append(bytes.Join(kept, []byte("\n")), '\n'), 0o644)
	findings, _, _ := checkpoint.VerifyAll(o.EvidenceDir, "", trust)
	if len(findings) == 0 {
		t.Fatal("removing a gap record must break the committed segment root")
	}
	if entries, _ := checkpoint.Gaps(o.EvidenceDir, "", trust); len(entries) != 2 || entries[0].RootVerified {
		t.Fatalf("after tamper: %+v", entries)
	}
}

// A sequence gap in RFC 5424 structured data becomes a sequence_gap leaf naming the missing count.
func TestSequenceGapFromStructuredData(t *testing.T) {
	p := loadGoldenPack(t)
	in, _ := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	lines := bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n"))
	var wrapped bytes.Buffer
	for i, seq := range []int{1, 2, 5, 6} {
		fmt.Fprintf(&wrapped, "<134>1 2024-12-19T00:00:00Z proxy01 squid 1234 - [meta sequenceId=\"%d\"] %s\n", seq, lines[i])
	}
	// commit per event: the leaf directly follows the message that revealed it; group commit (the default): the
	// message is interpreted only once its batch is durable, so the leaf follows that batch — after the message,
	// in the same segment, naming the last message before the gap
	for _, c := range []struct{ events, at int }{{1, 4}, {0, 5}} {
		var out, q bytes.Buffer
		o := fixedOpts(t, p, &out, &q)
		o.CommitEvents = c.events
		st, err := Run(bytes.NewReader(wrapped.Bytes()), o)
		if err != nil {
			t.Fatal(err)
		}
		if st.Emitted != 4 || st.GapRecords != 1 || st.GapKinds["sequence_gap"] != 1 {
			t.Fatalf("stats: %+v", st)
		}
		recs, _ := evidence.ReadIndex(o.EvidenceDir, "seg_00000")
		raw, _ := os.ReadFile(filepath.Join(o.EvidenceDir, "seg_00000.raw"))
		for _, r := range recs {
			if r.Framing.Method == evidence.MethodGapRecord {
				g, _ := gap.Parse(raw[r.Offset : r.Offset+int64(r.Length)])
				if g.Kind != "sequence_gap" || g.Expected != 3 || g.Observed != 5 || g.Missing != 2 || g.LastEventID != recs[1].EventID {
					t.Fatalf("gap: %+v", g)
				}
				if r.Sequence != int64(c.at) {
					t.Fatalf("commit-events %d: gap record position %d, want %d: %+v", c.events, r.Sequence, c.at, r)
				}
			}
		}
	}
}

// A TCP peer that disconnects mid-frame leaves a low-confidence partial frame in the evidence and a
// connection_lost gap record next to it.
func TestTCPPartialFrameBecomesEvidenceAndGapRecord(t *testing.T) {
	p := loadGoldenPack(t)
	in, _ := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	lines := bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n"))
	tc := &frame.TCP{Addr: "127.0.0.1:0", MaxEventBytes: 4096, MaxConns: 4, IdleTimeout: 2 * time.Second, Framing: "octet", MaxFrames: 3}
	ln, err := tc.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		for _, l := range lines[:2] {
			msg := append([]byte("<134>Dec 19 00:00:01 proxy01 squid[1]: "), l...)
			fmt.Fprintf(c, "%d %s", len(msg), msg)
		}
		fmt.Fprintf(c, "500 <134>Dec 19 00:00:01 proxy01 squid[1]: cut off here") // declares more than it sends
		c.Close()
	}()
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	o.Channel = "tcp:test"
	st, err := RunFramesWith(func(emit func(frame.Frame) error) error { return tc.Serve(t.Context(), ln, emit) }, o, func(pl *Pipeline) { tc.OnClose = pl.Lost })
	if err != nil {
		t.Fatal(err)
	}
	if st.Frames != 3 || st.Emitted != 2 || st.Truncated != 1 || st.LowConfidence != 1 || st.GapKinds["connection_lost"] != 1 {
		t.Fatalf("stats: %+v\n%s", st, q.String())
	}
	recs, _ := evidence.ReadIndex(o.EvidenceDir, "seg_00000")
	if len(recs) != 4 || recs[2].Framing.TruncationStatus != "truncated" || recs[3].Framing.Method != evidence.MethodGapRecord || recs[3].Peer != recs[2].Peer {
		t.Fatalf("records: %+v", recs)
	}
}
