package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/lake"
	"ulpf/runtime/internal/normalize"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/route"
)

// RenormOptions: a correction (invariant 8). The packs are the CORRECTED packs; the lake holds the
// versions emitted so far; the evidence store holds the raw bytes every version is derived from.
type RenormOptions struct {
	Packs       []*pack.Pack
	EvidenceDir string
	LakeDir     string
	Reason      string
	Now         func() time.Time
}

type RenormStats struct {
	From          int            `json:"derived_from"`
	To            int            `json:"normalization_version"`
	Read          int            `json:"events_read"`
	Corrected     int            `json:"events_corrected"`
	Unchanged     int            `json:"events_unchanged"`      // same normalized content under the corrected packs: no new version for them
	NotApplicable int            `json:"events_not_applicable"` // no longer route/parse under the corrected packs: the prior version stands
	ByFamily      map[string]int `json:"corrected_by_family"`
	Manifest      lake.Manifest  `json:"manifest"`
}

// Renormalize emits normalization@v(N+1) for every event of the latest version vN whose normalized
// content changes under the corrected packs. It never touches vN: it READS vN for the event list and
// lineage, re-reads each event's RAW BYTES from the evidence store (checking them against the lineage's
// raw_hash — a correction is derived from evidence, not from the previous interpretation), and runs the
// same unwrap -> route -> parse -> normalize path the live pipeline runs, with normalization_version N+1
// and derived_from N. The event keeps its identity: event_id, raw_hash, segment, offset, ingest_time.
func Renormalize(o RenormOptions) (RenormStats, error) {
	st := RenormStats{ByFamily: map[string]int{}}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	vs := lake.Versions(o.LakeDir)
	if len(vs) == 0 {
		return st, fmt.Errorf("renormalize: the lake at %s has no version to correct", o.LakeDir)
	}
	if _, findings := lake.Verify(o.LakeDir); len(findings) > 0 {
		return st, fmt.Errorf("renormalize: the lake does not verify (%d finding(s), first: v%d %s) — refusing to derive from it", len(findings), findings[0].Version, findings[0].Problem)
	}
	st.From, st.To = vs[len(vs)-1], vs[len(vs)-1]+1
	router := route.New(o.Packs...)
	if err := router.Err(); err != nil {
		return st, err
	}
	// the latest version of every event is the one a correction derives from: walk all versions, last wins
	latest := map[string]json.RawMessage{}
	var order []string
	for _, v := range vs {
		err := lake.Read(o.LakeDir, v, func(line []byte) error {
			id, err := eventID(line)
			if err != nil {
				return err
			}
			if _, seen := latest[id]; !seen {
				order = append(order, id)
			}
			latest[id] = line
			return nil
		})
		if err != nil {
			return st, err
		}
	}
	records := map[string]evidence.Record{}
	for _, seg := range evidence.Segments(o.EvidenceDir) {
		recs, err := evidence.ReadIndex(o.EvidenceDir, seg)
		if err != nil {
			return st, err
		}
		for _, r := range recs {
			records[r.EventID] = r
		}
	}
	raws := map[string][]byte{}
	var corrected [][]byte // sealed only if there is something to correct: no empty versions
	packsUsed := map[string]bool{}
	var err error
	for _, id := range order {
		st.Read++
		prev := latest[id]
		rec, ok := records[id]
		if !ok {
			return st, fmt.Errorf("renormalize: event %s is in the lake but not in the evidence index", id)
		}
		seg, ok := raws[rec.SegmentID]
		if !ok {
			if seg, err = os.ReadFile(filepath.Join(o.EvidenceDir, rec.SegmentID+".raw")); err != nil {
				return st, err
			}
			raws[rec.SegmentID] = seg
		}
		if rec.Offset+int64(rec.Length) > int64(len(seg)) {
			return st, fmt.Errorf("renormalize: event %s addresses bytes beyond segment %s", id, rec.SegmentID)
		}
		raw := seg[rec.Offset : rec.Offset+int64(rec.Length)]
		if evidence.Hash(raw) != rec.RawHash {
			return st, fmt.Errorf("renormalize: raw bytes of %s do not match raw_hash — the evidence was altered; refusing to derive a correction from it", id)
		}
		ch := frame.UnwrapChain(raw)
		payload := raw[ch.PayloadOffset : ch.PayloadOffset+ch.PayloadLength]
		d := router.RouteChain(payload, ch)
		if d.Family == nil {
			st.NotApplicable++
			continue
		}
		m, perr := d.Family.Program.Parse(payload, dsl.Env{SourceLocation: d.Pack.Location, IngestTime: time.UnixMilli(rec.IngestTime)})
		if perr != nil || m.Status != "ok" {
			st.NotApplicable++
			continue
		}
		m.Event.EventID = rec.EventID
		var chainPtr *frame.Chain
		if ch.Depth() > 1 {
			chainPtr = &ch
		}
		ev, _, nerr := normalize.Normalize(m, normalize.Context{Pack: d.Pack, Family: d.Family, Record: rec, Signature: d.Signature, ProcessingTime: now(),
			Envelope: ch.Innermost(), Chain: chainPtr, NormalizationVersion: st.To, DerivedFrom: st.From})
		if nerr != nil {
			st.NotApplicable++
			continue
		}
		same, err := sameContent(prev, ev)
		if err != nil {
			return st, err
		}
		if same {
			st.Unchanged++
			continue
		}
		b, _ := json.Marshal(ev)
		corrected = append(corrected, append(b, '\n'))
		packsUsed[d.Pack.PackID+"@"+d.Pack.PackVersion] = true
		st.Corrected++
		st.ByFamily[d.Pack.PackID+"/"+d.Family.FamilyID]++
	}
	if len(corrected) == 0 {
		st.To = st.From // nothing changes under these packs: no new version
		return st, nil
	}
	w, err := lake.Create(o.LakeDir, st.To, st.From, o.Reason, now())
	if err != nil {
		return st, err
	}
	for p := range packsUsed {
		w.AddPack(p)
	}
	for _, b := range corrected {
		if _, err := w.Write(b); err != nil {
			return st, err
		}
	}
	st.Manifest, err = w.Close()
	return st, err
}

func eventID(line []byte) (string, error) {
	var probe struct {
		L struct {
			EventID string `json:"event_id"`
		} `json:"_lineage"`
	}
	if err := json.Unmarshal(line, &probe); err != nil || probe.L.EventID == "" {
		return "", fmt.Errorf("lake line without _lineage.event_id")
	}
	return probe.L.EventID, nil
}

// sameContent compares what the event SAYS — every OCSF attribute and `unmapped` — ignoring _lineage
// (which always differs: version, processing time, parser version).
func sameContent(prev json.RawMessage, next map[string]any) (bool, error) {
	var a map[string]any
	if err := json.Unmarshal(prev, &a); err != nil {
		return false, err
	}
	nb, _ := json.Marshal(next)
	var b map[string]any
	if err := json.Unmarshal(nb, &b); err != nil {
		return false, err
	}
	delete(a, "_lineage")
	delete(b, "_lineage")
	ab, _ := json.Marshal(a) // encoding/json sorts map keys: a canonical form
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb), nil
}
