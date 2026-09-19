package pipeline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/lake"
	"ulpf/runtime/internal/pack"
)

func sha(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// correctedPack is the golden Squid pack at version 1.1 with ONE mapping corrected: the reply-size slot,
// which v1.0 maps to traffic.bytes_out, is re-mapped to traffic.bytes_in — the shape of the real
// correction (a retained request/response-role certificate resolved the other way). The pack struct is
// copied deeply enough that the v1.0 pack the first run used is untouched.
func correctedPack(t *testing.T, p *pack.Pack) *pack.Pack {
	t.Helper()
	c := *p
	c.PackVersion = "1.1"
	c.Families = append([]pack.Family(nil), p.Families...)
	f := c.Families[0]
	f.Mapping.Fields = append([]pack.MappingField(nil), f.Mapping.Fields...)
	n := 0
	for i := range f.Mapping.Fields {
		if f.Mapping.Fields[i].OCSFAttribute == "traffic.bytes_out" {
			f.Mapping.Fields[i].OCSFAttribute = "traffic.bytes_in"
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the golden pack must map exactly one field to traffic.bytes_out, found %d", n)
	}
	c.Families[0] = f
	return &c
}

// Invariant 8, end to end: after a correction v1 is byte-identical and retrievable; v2 carries
// derived_from and the corrected value, keeps the event's identity, and validates against the contract;
// there is no write path to v1; a correction is refused when the evidence it derives from was altered.
func TestCorrectionEmitsV2AndNeverTouchesV1(t *testing.T) {
	p := loadGoldenPack(t)
	in, err := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	lakeDir := t.TempDir()
	w, err := lake.Create(lakeDir, 1, 0, "ingest", time.UnixMilli(1734567890481))
	if err != nil {
		t.Fatal(err)
	}
	var q bytes.Buffer
	var out bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	o.Out = w
	st, err := Run(bytes.NewReader(in), o)
	if err != nil || st.Emitted != 6 {
		t.Fatalf("v1 run: %v %+v", err, st)
	}
	m1, err := w.Close()
	if err != nil || m1.Events != 6 {
		t.Fatalf("seal v1: %v %+v", err, m1)
	}
	v1File := filepath.Join(lakeDir, m1.File)
	before := sha(t, v1File)
	v1Bytes, _ := os.ReadFile(v1File)

	// --- the correction
	fixed := time.UnixMilli(1734599999000).UTC()
	rs, err := Renormalize(RenormOptions{Packs: []*pack.Pack{correctedPack(t, p)}, EvidenceDir: o.EvidenceDir, LakeDir: lakeDir,
		Reason: "test: reply-size slot re-mapped to traffic.bytes_in (pack 1.1)", Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	if rs.From != 1 || rs.To != 2 || rs.Read != 6 || rs.Corrected != 6 || rs.Unchanged != 0 || rs.NotApplicable != 0 {
		t.Fatalf("correction stats: %+v", rs)
	}
	// 1. v1 is byte-identical and retrievable
	after, _ := os.ReadFile(v1File)
	if sha(t, v1File) != before || !bytes.Equal(after, v1Bytes) || "sha256:"+before != m1.SHA256 {
		t.Fatal("v1 changed during the correction")
	}
	if _, findings := lake.Verify(lakeDir); len(findings) != 0 {
		t.Fatalf("lake does not verify after the correction: %+v", findings)
	}
	// 2. v2 carries derived_from, the corrected value, the same identity; validates against the contract
	sch, err := jsonschema.NewCompiler().Compile(filepath.Join(repoRoot(t), "contracts", "normalized-event.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	v1 := map[string]map[string]any{}
	if err := lake.Read(lakeDir, 1, func(line []byte) error {
		var e map[string]any
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		v1[e["_lineage"].(map[string]any)["event_id"].(string)] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	n := 0
	err = lake.Read(lakeDir, 2, func(line []byte) error {
		n++
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
		if err != nil {
			return err
		}
		if err := sch.Validate(doc); err != nil {
			t.Fatalf("v2 event violates normalized-event: %v\n%s", err, line)
		}
		var e map[string]any
		json.Unmarshal(line, &e)
		l2 := e["_lineage"].(map[string]any)
		old, ok := v1[l2["event_id"].(string)]
		if !ok {
			t.Fatalf("v2 event %v has no v1", l2["event_id"])
		}
		l1 := old["_lineage"].(map[string]any)
		if l2["normalization_version"] != float64(2) || l2["derived_from"] != float64(1) || l1["normalization_version"] != float64(1) {
			t.Fatalf("versions: v1 %v, v2 %v derived_from %v", l1["normalization_version"], l2["normalization_version"], l2["derived_from"])
		}
		if _, has := l1["derived_from"]; has {
			t.Fatal("v1 must not carry derived_from")
		}
		for _, k := range []string{"event_id", "raw_hash", "segment_id", "offset", "length", "ingest_time", "source_id", "family_id"} {
			if l1[k] != l2[k] {
				t.Fatalf("identity field %s differs: %v vs %v", k, l1[k], l2[k])
			}
		}
		if l1["parser_version"] != "1.0" || l2["parser_version"] != "1.1" || l2["processing_time"] != float64(fixed.UnixMilli()) {
			t.Fatalf("parser/processing: v1 %v v2 %v at %v", l1["parser_version"], l2["parser_version"], l2["processing_time"])
		}
		t1, t2 := old["traffic"].(map[string]any), e["traffic"].(map[string]any)
		if t1["bytes_out"] == nil || t2["bytes_in"] != t1["bytes_out"] || t2["bytes_out"] != nil {
			t.Fatalf("the corrected value: v1 traffic %v, v2 traffic %v", t1, t2)
		}
		return nil
	})
	if err != nil || n != 6 {
		t.Fatalf("v2: %d events, err %v", n, err)
	}
	both, err := lake.Get(lakeDir, "ev_"+strings.Repeat("0", 25)+"3")
	if err != nil || len(both) != 2 {
		t.Fatalf("both versions of an event must be retrievable: %d %v", len(both), err)
	}
	// 3. no write path to v1: the store refuses, by API, to open it again (the lake package's own tests cover the rest)
	if _, err := lake.Create(lakeDir, 1, 0, "rewrite", time.Now()); err == nil {
		t.Fatal("lake.Create on v1 must fail")
	}
	// 4. the same correction again changes nothing: no empty v3
	rs2, err := Renormalize(RenormOptions{Packs: []*pack.Pack{correctedPack(t, p)}, EvidenceDir: o.EvidenceDir, LakeDir: lakeDir, Reason: "again"})
	if err != nil || rs2.Corrected != 0 || rs2.Unchanged != 6 || len(lake.Versions(lakeDir)) != 2 {
		t.Fatalf("idempotent correction: %v %+v versions %v", err, rs2, lake.Versions(lakeDir))
	}
	// 5. a correction derives from EVIDENCE: alter one raw byte and it is refused, and nothing is sealed
	seg := filepath.Join(o.EvidenceDir, evidence.Segments(o.EvidenceDir)[0]+".raw")
	os.Chmod(seg, 0o644)
	raw, _ := os.ReadFile(seg)
	raw[3] ^= 1
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatalf("cannot alter the sealed segment to set up the tamper case (%v) — failing rather than skipping: a skipped refusal test is a masked one", err)
	}
	third := correctedPack(t, p)
	third.PackVersion = "1.2"
	third.Families[0].Mapping.Fields = append([]pack.MappingField(nil), third.Families[0].Mapping.Fields...)
	for i := range third.Families[0].Mapping.Fields {
		if third.Families[0].Mapping.Fields[i].OCSFAttribute == "traffic.bytes_in" {
			third.Families[0].Mapping.Fields[i].OCSFAttribute = "traffic.bytes"
		}
	}
	if _, err := Renormalize(RenormOptions{Packs: []*pack.Pack{third}, EvidenceDir: o.EvidenceDir, LakeDir: lakeDir, Reason: "from altered evidence"}); err == nil || !strings.Contains(err.Error(), "evidence was altered") {
		t.Fatalf("a correction over altered evidence must be refused: %v", err)
	}
	if vs := lake.Versions(lakeDir); len(vs) != 2 {
		t.Fatalf("a refused correction must seal nothing: %v", vs)
	}
}
