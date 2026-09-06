// Package pipeline wires framing -> raw evidence write -> route -> parse -> normalize -> emit, in
// exactly that order (architecture §2.5). Raw bytes are hashed and durably written before any
// interpretation (invariant 3); routing never tries parsers (invariant 6); a parse or tiling failure
// quarantines the event rather than emitting a guess (invariant 5).
package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/mlfeat"
	"ulpf/runtime/internal/normalize"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/route"
)

type Options struct {
	Pack  *pack.Pack   // single pack (P2–P5 callers)
	Packs []*pack.Pack // P6: every onboarded pack of a mixed stream; Pack is appended when set
	// SourceID is what the evidence record carries as the ingest source. Routing happens AFTER the raw
	// write, so the record cannot name the routed pack; for a single pack it defaults to that pack's
	// source_id, for a mixed stream it must be given (the channel's declared source) — raised in P6.
	SourceID    string
	ML          io.Writer // ML feature records, JSONL (requirement h); nil disables
	EvidenceDir string
	Collector   string
	Channel     string
	Out         io.Writer // normalized events, JSONL
	Quarantine  io.Writer // quarantined events, JSONL
	Now         func() time.Time
	NewID       func(time.Time) string
	Limits      evidence.Limits
	// FailAfterRawWrite > 0 makes the process exit hard right after the Nth event's raw write has
	// been fsynced and before it is parsed — the kill-test hook (invariant 3).
	FailAfterRawWrite int
	MaxEventBytes     int
}

// Stats. Usable counts emitted events whose every mandatory attribute is mapped by the pack —
// present, or absent for a stated cause. An event is unusable only when a mandatory attribute is not
// mapped at all, which a valid pack cannot produce (the acceptance gate blocks it), so
// usable == emitted is the expected state; the informative numbers are the absence causes.
type Stats struct {
	Frames            int            `json:"frames"`
	Emitted           int            `json:"emitted"`
	Usable            int            `json:"usable"`
	UnmappedMandatory int            `json:"unmapped_mandatory_events"`
	AbsentStructural  int            `json:"events_with_structural_absence"`
	AbsentUncoercible int            `json:"events_with_uncoercible_absence"`
	AbsentDeclared    int            `json:"events_with_declared_null"`
	Quarantined       int            `json:"quarantined"`
	Enveloped         int            `json:"enveloped"` // frames whose outer syslog envelope was unwrapped
	Reasons           map[string]int `json:"quarantine_reasons"`
	// CandidateSets is the distribution of the routing DAG's candidate-set size after L4 (key: size),
	// over every routed or routing-quarantined frame — the empirical answer to the K=4 question.
	CandidateSets map[string]int `json:"candidate_set_sizes"`
	DriftSignals  int            `json:"drift_signals"` // anchor values outside their declared domain
	MLRecords     int            `json:"ml_records"`
	ByFamily      map[string]int `json:"emitted_by_family"`
}

type quarantined struct {
	EventID   string `json:"event_id"`
	RawHash   string `json:"raw_hash"`
	SegmentID string `json:"segment_id"`
	Offset    int64  `json:"offset"`
	Length    int    `json:"length"`
	Signature string `json:"routing_signature"`
	Stage     string `json:"stage"`
	Reason    string `json:"reason"`
}

// Source delivers frames in arrival order to emit until exhausted (a newline-framed stream to EOF, a
// UDP listener until stopped).
type Source func(emit func(frame.Frame) error) error

// Run processes one newline-framed input stream to EOF.
func Run(in io.Reader, o Options) (Stats, error) {
	maxBytes := o.MaxEventBytes
	if maxBytes == 0 {
		maxBytes = 65536
	}
	return RunFrames(func(emit func(frame.Frame) error) error { return frame.Newline{MaxEventBytes: maxBytes}.Scan(in, emit) }, o)
}

// RunFrames processes frames from any source. Per frame, in this order: raw evidence write of the
// complete received bytes; envelope unwrap (one level: the parser sees the payload, the evidence keeps
// the envelope); route on the payload; parse; normalize with the envelope recorded in lineage.
func RunFrames(source Source, o Options) (Stats, error) {
	st := Stats{Reasons: map[string]int{}, CandidateSets: map[string]int{}, ByFamily: map[string]int{}}
	packs := o.Packs
	if o.Pack != nil {
		packs = append([]*pack.Pack{o.Pack}, packs...)
	}
	if len(packs) == 0 {
		return st, fmt.Errorf("no packs")
	}
	sourceID := o.SourceID
	if sourceID == "" {
		if len(packs) != 1 {
			return st, fmt.Errorf("a mixed stream needs an explicit --source-id for the evidence record")
		}
		sourceID = packs[0].Source.SourceID
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	store, err := evidence.Open(o.EvidenceDir, evidence.Options{Limits: o.Limits, Now: now, NewID: o.NewID})
	if err != nil {
		return st, err
	}
	defer store.Close()
	router := route.New(packs...)
	if err := router.Err(); err != nil {
		return st, err
	}
	out := bufio.NewWriter(o.Out)
	defer out.Flush()
	var q, ml *bufio.Writer
	if o.Quarantine != nil {
		q = bufio.NewWriter(o.Quarantine)
		defer q.Flush()
	}
	if o.ML != nil {
		ml = bufio.NewWriter(o.ML)
		defer ml.Flush()
	}
	quarantine := func(rec evidence.Record, sig, stage, reason string) {
		st.Quarantined++
		st.Reasons[stage]++
		if q != nil {
			b, _ := json.Marshal(quarantined{rec.EventID, rec.RawHash, rec.SegmentID, rec.Offset, rec.Length, sig, stage, reason})
			q.Write(append(b, '\n'))
		}
	}
	err = source(func(fr frame.Frame) error {
		st.Frames++
		// 1. raw evidence write — durable before anything else looks at the bytes
		rec, err := store.Append(fr.Raw, fr.Framing, sourceID, o.Collector, o.Channel)
		if err != nil {
			return err
		}
		if o.FailAfterRawWrite > 0 && st.Frames == o.FailAfterRawWrite {
			out.Flush()
			os.Exit(137) // kill-test: die after the raw write, before parsing
		}
		if fr.Framing.TruncationStatus != "none" {
			quarantine(rec, "", "framing", "truncated or continuation frame retained as evidence, not parsed")
			return nil
		}
		// 2. envelope: unwrap one level; the evidence keeps every received byte, the parser sees the payload
		envl := frame.Unwrap(fr.Raw)
		payload := fr.Raw[envl.PayloadOffset : envl.PayloadOffset+envl.PayloadLength]
		if envl.Kind != "none" {
			st.Enveloped++
		}
		var envPtr *frame.Envelope
		if envl.Kind != "none" {
			envPtr = &envl
		}
		// 3. route: the decision DAG narrows to one family or quarantines; no parser runs here
		d := router.Route(payload, envPtr)
		st.CandidateSets[fmt.Sprint(d.Candidates)]++
		if d.Drift {
			st.DriftSignals++
		}
		if d.Family == nil {
			quarantine(rec, d.Signature, d.Stage, d.Reason)
			return nil
		}
		env := dsl.Env{SourceLocation: d.Pack.Location, IngestTime: time.UnixMilli(rec.IngestTime)}
		// 4. parse — the one parser the router chose, once
		m, perr := d.Family.Program.Parse(payload, env)
		if perr != nil {
			quarantine(rec, d.Signature, "tiling", perr.Error())
			return nil
		}
		m.Event.EventID = rec.EventID
		if m.Status != "ok" {
			quarantine(rec, d.Signature, "parse", fmt.Sprintf("at %d: %s", m.Failure.AtOffset, m.Failure.Reason))
			return nil
		}
		// 5. normalize
		ev, res, nerr := normalize.Normalize(m, normalize.Context{Pack: d.Pack, Family: d.Family, Record: rec, Signature: d.Signature, ProcessingTime: now(), Envelope: envPtr})
		if nerr != nil {
			quarantine(rec, d.Signature, "normalize", nerr.Error())
			return nil
		}
		if len(res.Unmapped) == 0 {
			st.Usable++
		} else {
			st.UnmappedMandatory++
		}
		structural, uncoercible, declared := false, false, false
		for _, a := range res.Absent {
			structural = structural || a.Cause == "structural"
			uncoercible = uncoercible || a.Cause == "uncoercible"
			declared = declared || a.Cause == "declared_null"
		}
		if structural {
			st.AbsentStructural++
		}
		if uncoercible {
			st.AbsentUncoercible++
		}
		if declared {
			st.AbsentDeclared++
		}
		b, _ := json.Marshal(ev)
		if _, err := out.Write(append(b, '\n')); err != nil {
			return err
		}
		st.Emitted++
		st.ByFamily[d.Pack.PackID+"/"+d.Family.FamilyID]++
		if ml != nil {
			// 6. ML feature tuple (requirement h): a projection of the event just emitted
			fb, _ := json.Marshal(mlfeat.Build(d.Pack, d.Family, m, ev, envPtr, rec.EventID))
			if _, err := ml.Write(append(fb, '\n')); err != nil {
				return err
			}
			st.MLRecords++
		}
		return nil
	})
	return st, err
}
