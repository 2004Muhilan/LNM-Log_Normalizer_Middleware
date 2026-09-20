// Package pipeline wires framing -> raw evidence write -> route -> parse -> normalize -> emit, in
// exactly that order (architecture §2.5). Raw bytes are hashed and durably written before any
// interpretation (invariant 3); routing never tries parsers (invariant 6); a parse or tiling failure
// quarantines the event rather than emitting a guess (invariant 5).
//
// P7 additions, in pipeline order: de-batching (a frame that is a JSON array becomes N frames BEFORE
// the raw write, so every element is its own evidence record); recursive envelope unwrap (relay chain
// and the CEF application envelope) after the raw write; continuity accounting per peer, whose gap
// records are appended to the same evidence store as leaves.
package pipeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/egress"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/gap"
	"ulpf/runtime/internal/mlfeat"
	"ulpf/runtime/internal/normalize"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/route"
)

// EgressSink is one downstream delivery (P8): a sink URL and where its cursor is persisted.
type EgressSink struct {
	URL        string
	CursorPath string
}

type Options struct {
	// P8 egress. SpoolPath is the FILE the Out writer writes (the delivery spool the forwarders read); with any
	// Egress sink the pipeline flushes Out after every event, reports a sink that stops accepting as an
	// `egress_stalled` gap record in the evidence log (and `egress_resumed` when it catches up), and drains the
	// forwarders for EgressDrain before it returns. Ingestion never waits for a sink; nothing is dropped.
	Egress           []EgressSink
	SpoolPath        string
	EgressStallAfter time.Duration
	EgressDrain      time.Duration
	EgressTimeout    time.Duration

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
	// P7. Debatch (default on unless NoDebatch) explodes JSON-array frames into element frames.
	NoDebatch bool
	// SilenceAfter > 0 turns on silence detection per peer, swept every SilenceAfter/2 while the
	// source runs (listener sources); sequence-gap detection is always on where a sequence exists.
	SilenceAfter time.Duration
	// GapSource is the channel/peer of transport-level gap events (connection lost mid-frame); the
	// transport calls it back through Pipeline.Lost.
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
	Enveloped         int            `json:"enveloped"` // frames with at least one envelope unwrapped
	Reasons           map[string]int `json:"quarantine_reasons"`
	// CandidateSets is the distribution of the routing DAG's candidate-set size after L4 (key: size),
	// over every routed or routing-quarantined frame — the empirical answer to the K=4 question.
	CandidateSets map[string]int `json:"candidate_set_sizes"`
	DriftSignals  int            `json:"drift_signals"` // anchor values outside their declared domain
	MLRecords     int            `json:"ml_records"`
	ByFamily      map[string]int `json:"emitted_by_family"`
	// P7
	Received      int            `json:"received_frames"`  // frames as the transport delivered them (before de-batching)
	BatchElements int            `json:"batch_elements"`   // frames produced by de-batching
	RelayChains   int            `json:"relay_chains"`     // frames whose unwrap removed more than one envelope
	Truncated     int            `json:"truncated_frames"` // frames retained as evidence because a bound was hit (never parsed)
	LowConfidence int            `json:"low_confidence_frames"`
	GapRecords    int            `json:"gap_records"`
	GapKinds      map[string]int `json:"gap_kinds"`
	Peers         int            `json:"peers"`
	Egress        []egress.Stats `json:"egress,omitempty"` // P8: per sink — delivered, retries, stalls, undelivered bytes
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

// Pipeline is the running state a transport may call back into (P7): Lost records a connection
// that ended mid-frame as a gap record. Obtained through RunFramesWith.
type Pipeline struct {
	mu      sync.Mutex
	router  *route.Router
	active  map[string]string // pack_id -> "version sha256" of what is loaded now
	store   *evidence.Store
	tracker *gap.Tracker
	st      *Stats
	o       Options
	source  string
	now     func() time.Time
	err     error
}

// Lost appends a connection_lost gap record for peer (called by a transport's OnClose).
func (p *Pipeline) Lost(peer, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.appendGap(p.tracker.Lost(peer, p.source, p.o.Channel, reason, p.now()), peer)
}

// Reload swaps the set of loaded packs between two frames (SIGHUP in the CLI). The packs arrive already loaded
// by the same fail-closed loader as at start (schema, static invariants, signature); a router that does not
// build leaves the old one in place. Every pack whose version or bytes changed — and every pack added or
// removed — becomes a `pack_activated` / `pack_deactivated` record in the EVIDENCE LOG, a leaf like a gap record:
// from that leaf on, events are interpreted differently, and that is provable from the log alone.
func (p *Pipeline) Reload(packs []*pack.Pack, reason string) error {
	if len(packs) == 0 {
		return fmt.Errorf("reload refused: no packs (a runtime with nothing loaded quarantines everything; stop it instead)")
	}
	r := route.New(packs...)
	if err := r.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	next := map[string]string{}
	for _, pk := range packs {
		next[pk.PackID] = pk.PackVersion + " " + pk.FileSHA256
	}
	for id, v := range next {
		if prev, ok := p.active[id]; !ok || prev != v {
			was := "not loaded"
			if ok {
				was = "v" + prev
			}
			p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "pack_activated", SourceID: p.source, Channel: "control:reload", Peer: "pack:" + id, DetectedAt: p.now().UnixMilli(),
				Detail: fmt.Sprintf("pack %s v%s activated without a restart (was: %s); %s", id, v, was, reason)}, "pack:"+id)
		}
	}
	for id, prev := range p.active {
		if _, ok := next[id]; !ok {
			p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "pack_deactivated", SourceID: p.source, Channel: "control:reload", Peer: "pack:" + id, DetectedAt: p.now().UnixMilli(),
				Detail: fmt.Sprintf("pack %s v%s no longer loaded; %s", id, prev, reason)}, "pack:"+id)
		}
	}
	p.router, p.active = r, next
	return nil
}

func (p *Pipeline) appendGap(r gap.Record, peer string) {
	b := gap.Canonical(r)
	fr := frame.Framing{Method: evidence.MethodGapRecord, RawPrefix: []byte{}, RawSuffix: []byte{}, FragmentCount: 1, OriginalMessageLength: len(b), TruncationStatus: "none", FramingConfidence: "high"}
	if _, err := p.store.AppendFrom(b, fr, p.source, p.o.Collector, p.o.Channel, peer); err != nil {
		if p.err == nil {
			p.err = err
		}
		return
	}
	p.st.GapRecords++
	p.st.GapKinds[r.Kind]++
}

// RunFrames processes frames from any source. Per frame, in this order: de-batch (a JSON array
// becomes its elements); raw evidence write of the complete received bytes; recursive envelope
// unwrap (the parser sees the innermost payload, the evidence keeps every byte); continuity
// accounting; route on the payload; parse; normalize with the envelope chain recorded in lineage.
func RunFrames(source Source, o Options) (Stats, error) {
	return RunFramesWith(source, o, nil)
}

// RunFramesWith is RunFrames with a hook that receives the running Pipeline before the source starts
// (transports register their OnClose through it).
func RunFramesWith(source Source, o Options, ready func(*Pipeline)) (Stats, error) {
	st := Stats{Reasons: map[string]int{}, CandidateSets: map[string]int{}, ByFamily: map[string]int{}, GapKinds: map[string]int{}}
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
	p := &Pipeline{store: store, tracker: gap.New(o.SilenceAfter), st: &st, o: o, source: sourceID, now: now, router: router, active: map[string]string{}}
	for _, pk := range packs {
		p.active[pk.PackID] = pk.PackVersion + " " + pk.FileSHA256
	}
	if ready != nil {
		ready(p)
	}
	// egress: one forwarder per sink over the spool; an interruption of DELIVERY becomes an evidence leaf like an
	// interruption of ARRIVAL does
	var forwarders []*egress.Forwarder
	reported := map[string]bool{}
	if len(o.Egress) > 0 {
		if o.SpoolPath == "" {
			return st, fmt.Errorf("egress needs the normalized output in a file (--out FILE): the file is the delivery spool")
		}
		timeout := o.EgressTimeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		for _, e := range o.Egress {
			sink, err := egress.Open(e.URL, timeout)
			if err != nil {
				return st, err
			}
			name := sink.Name()
			f := &egress.Forwarder{Spool: o.SpoolPath, CursorPath: e.CursorPath, Sink: sink, StallAfter: o.EgressStallAfter,
				OnStall: func(s egress.Stall) {
					p.mu.Lock()
					defer p.mu.Unlock()
					reported[name] = true
					p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "egress_stalled", SourceID: sourceID, Channel: "egress:" + name, Peer: name, DetectedAt: now().UnixMilli(),
						LastSeenAt: s.Since.UnixMilli(), LastEventID: s.LastEventID, SilenceMS: s.Duration.Milliseconds(), Missing: s.LagBytes,
						Detail: "sink not accepting: " + s.Err + "; events are spooled, none dropped; delivery resumes from the last acknowledged event"}, name)
				},
				OnResume: func(s egress.Stall) {
					p.mu.Lock()
					defer p.mu.Unlock()
					p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "egress_resumed", SourceID: sourceID, Channel: "egress:" + name, Peer: name, DetectedAt: now().UnixMilli(),
						LastSeenAt: s.Since.UnixMilli(), LastEventID: s.LastEventID, SilenceMS: s.Duration.Milliseconds(), Missing: s.LagEvents,
						Detail: fmt.Sprintf("sink accepting again: %d event(s) delivered late, none dropped", s.LagEvents)}, name)
				}}
			if err := f.Start(true); err != nil { // the run has just created the spool: the cursor starts at zero
				return st, err
			}
			forwarders = append(forwarders, f)
		}
	}
	// silence sweeps while a listener source runs (a file source ends before any sweep matters)
	stopSweep := make(chan struct{})
	var sweepWG sync.WaitGroup
	if o.SilenceAfter > 0 {
		interval := o.SilenceAfter / 2
		if interval < 20*time.Millisecond {
			interval = 20 * time.Millisecond
		}
		sweepWG.Add(1)
		go func() {
			defer sweepWG.Done()
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-stopSweep:
					return
				case <-t.C:
					p.mu.Lock()
					for _, r := range p.tracker.Sweep(now()) {
						p.appendGap(r, r.Peer)
					}
					p.mu.Unlock()
				}
			}
		}()
	}
	one := func(fr frame.Frame) error {
		st.Frames++
		// 1. raw evidence write — durable before anything else looks at the bytes
		channel := o.Channel
		if fr.Channel != "" {
			channel = fr.Channel
		}
		rec, err := store.AppendFrom(fr.Raw, fr.Framing, sourceID, o.Collector, channel, fr.Peer)
		if err != nil {
			return err
		}
		if o.FailAfterRawWrite > 0 && st.Frames == o.FailAfterRawWrite {
			out.Flush()
			os.Exit(137) // kill-test: die after the raw write, before parsing
		}
		if fr.Framing.FramingConfidence == "low" {
			st.LowConfidence++
		}
		if fr.Framing.TruncationStatus != "none" {
			st.Truncated++
			quarantine(rec, "", "framing", "truncated or continuation frame retained as evidence, not parsed")
			return nil
		}
		// 2. envelope: recursive unwrap; the evidence keeps every received byte, the parser sees the
		//    innermost payload; the whole chain is recorded in lineage
		ch := frame.UnwrapChain(fr.Raw)
		payload := fr.Raw[ch.PayloadOffset : ch.PayloadOffset+ch.PayloadLength]
		if ch.Depth() > 0 {
			st.Enveloped++
		}
		if ch.Depth() > 1 {
			st.RelayChains++
		}
		envPtr := ch.Innermost()
		// 3. continuity: per-peer counters and sequence gaps; records become leaves next to this one
		var seq *int64
		for i := range ch.Envelopes {
			if v, ok := gap.SequenceID(ch.Envelopes[i].StructuredData); ok {
				seq = &v
				break
			}
		}
		for _, g := range p.tracker.Observe(fr.Peer, sourceID, channel, rec.EventID, seq, now()) {
			p.appendGap(g, fr.Peer)
		}
		// 4. route: the decision DAG narrows to one family or quarantines; no parser runs here
		d := p.router.RouteChain(payload, ch) // p.mu is held: Reload swaps the router between two frames, never inside one
		st.CandidateSets[fmt.Sprint(d.Candidates)]++
		if d.Drift {
			st.DriftSignals++
		}
		if d.Family == nil {
			quarantine(rec, d.Signature, d.Stage, d.Reason)
			return nil
		}
		env := dsl.Env{SourceLocation: d.Pack.Location, IngestTime: time.UnixMilli(rec.IngestTime)}
		// 5. parse — the one parser the router chose, once
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
		// 6. normalize
		var chainPtr *frame.Chain
		if ch.Depth() > 1 {
			chainPtr = &ch
		}
		ev, res, nerr := normalize.Normalize(m, normalize.Context{Pack: d.Pack, Family: d.Family, Record: rec, Signature: d.Signature, ProcessingTime: now(), Envelope: envPtr, Chain: chainPtr})
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
		if len(forwarders) > 0 {
			if err := out.Flush(); err != nil { // the spool is read by the forwarders: an event is deliverable as soon as it is emitted
				return err
			}
		}
		st.Emitted++
		st.ByFamily[d.Pack.PackID+"/"+d.Family.FamilyID]++
		if ml != nil {
			// 7. ML feature tuple (requirement h): a projection of the event just emitted
			fb, _ := json.Marshal(mlfeat.Build(d.Pack, d.Family, m, ev, envPtr, rec.EventID))
			if _, err := ml.Write(append(fb, '\n')); err != nil {
				return err
			}
			st.MLRecords++
		}
		return nil
	}
	err = source(func(fr frame.Frame) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.err != nil {
			return p.err
		}
		st.Received++
		// 0. de-batch: a JSON array is N independently framed, independently hashed events
		if !o.NoDebatch && fr.Framing.TruncationStatus == "none" {
			if elems, ok := frame.Debatch(fr, 0); ok {
				st.BatchElements += len(elems)
				for _, e := range elems {
					if err := one(e); err != nil {
						return err
					}
				}
				return nil
			}
		}
		return one(fr)
	})
	close(stopSweep)
	sweepWG.Wait()
	if len(forwarders) > 0 {
		out.Flush()
		drain := o.EgressDrain
		if drain == 0 {
			drain = 10 * time.Second
		}
		for _, f := range forwarders { // p.mu is NOT held here: a resume during the drain still becomes a leaf
			es := f.Drain(drain)
			if es.Undelivered > 0 {
				p.mu.Lock()
				if !reported[es.Sink] { // an outage shorter than the stall threshold, still open at shutdown, is recorded too
					p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "egress_stalled", SourceID: sourceID, Channel: "egress:" + es.Sink, Peer: es.Sink, DetectedAt: now().UnixMilli(),
						Missing: es.Undelivered, Detail: "undelivered at shutdown: " + es.LastError + "; the cursor is persisted, `ulpf-runtime forward` resumes from it"}, es.Sink)
				}
				p.mu.Unlock()
			}
			st.Egress = append(st.Egress, es)
		}
	}
	p.mu.Lock()
	st.Peers = p.tracker.Peers()
	if err == nil {
		err = p.err
	}
	p.mu.Unlock()
	return st, err
}
