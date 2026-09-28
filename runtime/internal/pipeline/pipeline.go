// Package pipeline wires framing -> raw evidence write -> route -> parse -> normalize -> emit, in
// exactly that order (architecture §2.5). Invariant 3 (group commit): no event is parsed or delivered
// until the batch containing its raw bytes is durable on disk — frames are hashed and staged, a batch is
// committed (one write, one fsync of the segment and one of the index) when it reaches CommitEvents or its
// oldest frame has waited CommitWait, and only then are its frames interpreted, in arrival order. Routing
// never tries parsers (invariant 6); a parse or tiling failure quarantines the event rather than emitting a
// guess (invariant 5).
//
// P7 additions, in pipeline order: de-batching (a frame that is a JSON array becomes N frames BEFORE
// the raw write, so every element is its own evidence record); recursive envelope unwrap (relay chain
// and the CEF application envelope) after the raw write; continuity accounting per peer, whose gap
// records are appended to the same evidence store as leaves.
package pipeline

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ulpf/runtime/internal/archive"
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
	Egress    []EgressSink
	SpoolPath string
	// Laptop branch: a BOUNDED, segmented spool (egress.Spool) instead of SpoolPath. Retention follows the slowest
	// destination; above SpoolCap the destinations still inside the oldest segment are moved past it, each move an
	// `egress_skipped` evidence record; above SpoolWarn (default 80 % of the cap) a destination's lag is an
	// `egress_lagging` record first. The run resumes the spool and every destination's cursor (SpoolFresh starts over).
	SpoolDir         string
	SpoolCap         int64
	SpoolSegment     int64
	SpoolWarn        float64
	SpoolFresh       bool
	SpoolTick        time.Duration // retention check interval (default 250 ms; tests shorten it)
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
	// FailAfterRawWrite > 0 makes the process exit hard right after the batch holding the Nth event has
	// been committed (fsynced) and before any event of that batch is parsed — the kill-test hook (invariant 3).
	FailAfterRawWrite int
	// Group commit (invariant 3): a batch is committed at CommitEvents staged frames or when its oldest frame
	// has waited CommitWait, whichever comes first (defaults 256 and 10 ms; CommitEvents 1 is an fsync per
	// event, as before 2026-09-27). The wait is measured on the wall clock, never on Now (a fixed golden clock
	// must not hold a batch forever). A crash loses only frames received and not yet committed — never
	// parsed, never delivered.
	CommitEvents int
	CommitWait   time.Duration
	// Evidence archive (laptop branch, 2026-09-27): the local evidence directory is a bounded buffer. Buffer deletes
	// shipped segments when every deletion condition holds (internal/archive), swept every BufferTick (default 1 s).
	// BufferCap bounds the local bytes: above BufferWarn of it (default 0.8) one `evidence_buffer_high` record; at the
	// cap, intake STOPS and one `evidence_buffer_full` record is committed — no older evidence is deleted to make room;
	// below the warning mark again, one `evidence_buffer_resumed` record. While full: a TCP connection or a file is not
	// read (the sender waits or drops on its side), HTTP is answered 503 (Admit), a UDP datagram is counted and
	// discarded — never parsed, never delivered; strict deployments relay UDP through TCP. The cap can be exceeded by
	// what arrives within one tick. Done ends a wait (shutdown).
	Buffer        *archive.Buffer
	BufferCap     int64
	BufferWarn    float64
	BufferTick    time.Duration
	Done          <-chan struct{}
	StoreID       string // golden outputs: the store id of a new evidence directory
	MaxEventBytes int
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
	Commits       int64          `json:"evidence_commits"` // group commit: batches made durable (one write + two fsyncs each)
	StoreID       string         `json:"store_id"`
	Recovered     int            `json:"recovered_after_crash,omitempty"` // frames committed by a previous run and interpreted at this start
	// the evidence archive: DISABLED (development override) or the local buffer's accounting
	EvidenceArchive string       `json:"evidence_archive,omitempty"`
	EvidenceBuffer  *BufferStats `json:"evidence_buffer,omitempty"`
}

// BufferStats is the local evidence buffer's accounting for a run.
type BufferStats struct {
	LocalBytes       int64  `json:"local_bytes"`
	LocalSegments    int    `json:"local_segments"`
	PeakLocalBytes   int64  `json:"peak_local_bytes"`
	Cap              int64  `json:"cap"`
	DeletedSegments  int    `json:"deleted_segments"`
	FullEpisodes     int    `json:"full_episodes"`
	DiscardedFrames  int64  `json:"udp_discarded_frames"` // UDP datagrams discarded while the buffer was full
	DiscardedBytes   int64  `json:"udp_discarded_bytes"`
	RefusedHTTP      int64  `json:"http_refused_requests"`
	FullNow          bool   `json:"full_now"`
	LastBlockedCause string `json:"last_blocked,omitempty"` // why the oldest local segment stays (one example)
}

// ErrEvidenceBufferFull is returned to a transport while the local evidence buffer is at its cap.
var ErrEvidenceBufferFull = errors.New("the local evidence buffer is at its cap (the evidence archive is not taking segments): intake stopped, nothing older deleted")

// Admit is called by the HTTP receiver before it accepts a request: ErrEvidenceBufferFull while the buffer is at its cap.
func (p *Pipeline) Admit() error {
	if p.full.Load() {
		p.refusedHTTP.Add(1)
		return ErrEvidenceBufferFull
	}
	return nil
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
	// group commit: frames staged in the evidence store, not yet durable, not yet interpreted
	pending []staged
	since   time.Time // wall clock: when the oldest pending frame was staged
	commit  func() error
	// the evidence buffer at its cap
	full                  atomic.Bool
	discarded, discardedB atomic.Int64
	refusedHTTP           atomic.Int64
}

type staged struct {
	fr      frame.Frame
	rec     evidence.Record
	channel string
	n       int // frame number (st.Frames when staged)
}

// Commit makes every staged frame durable and interprets it (the HTTP receiver calls it before it answers
// 202: an accepted request is on disk).
func (p *Pipeline) Commit() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.commitLocked()
}

func (p *Pipeline) commitLocked() error {
	if p.commit == nil || len(p.pending) == 0 {
		return p.err
	}
	if err := p.commit(); err != nil && p.err == nil {
		p.err = err
	}
	return p.err
}

// Lost appends a connection_lost gap record for peer (called by a transport's OnClose).
func (p *Pipeline) Lost(peer, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.commitLocked() // the peer's last frames are interpreted before the record that says it went away
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
	// frames received before the reload are interpreted by the packs they arrived under, before the
	// pack_activated leaf: "from that leaf on" stays true under group commit
	if err := p.commitLocked(); err != nil {
		return err
	}
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

// Refused records a pack the runtime REFUSED to load on a hot reload (parser transparency log, signature, contract):
// a `pack_refused` leaf in the evidence log — the attempt is provable from the log alone, like an activation.
func (p *Pipeline) Refused(what, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.commitLocked()
	p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "pack_refused", SourceID: p.source, Channel: "control:reload", Peer: "pack:" + what, DetectedAt: p.now().UnixMilli(),
		Detail: "a pack was pushed to this runtime and REFUSED; the running packs stay loaded: " + reason}, "pack:"+what)
}

// retention keeps the segmented spool bounded (laptop branch). Every tick: closed segments every destination has passed
// are removed (the slowest destination governs retention); a destination whose lag passes the warning mark gets one
// `egress_lagging` record (re-armed below half of it); when the retained bytes pass the cap, every destination still
// inside the oldest closed segment is asked to move past it — the forwarder records the move as `egress_skipped` — and
// the segment is removed on a later tick, once no cursor points into it. The disk can exceed the cap by about one
// segment plus what arrives between two ticks; the cap must be at least two segments.
func (p *Pipeline) retention(spool *egress.Spool, fw []*egress.Forwarder, o Options, sourceID string, now func() time.Time, stop chan struct{}) {
	capB := o.SpoolCap
	if capB <= 0 {
		capB = 1 << 30
	}
	warn := o.SpoolWarn
	if warn <= 0 || warn >= 1 {
		warn = 0.8
	}
	warned := make([]bool, len(fw))
	tick := o.SpoolTick
	if tick <= 0 {
		tick = 250 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		segs := egress.ListSegments(spool.Dir)
		if len(segs) == 0 {
			continue
		}
		head, open := spool.Head(), spool.OpenBase()
		minCur := head
		for i, f := range fw {
			c := f.Offset()
			if c < minCur {
				minCur = c
			}
			lag := head - c
			switch {
			case !warned[i] && float64(lag) > warn*float64(capB):
				warned[i] = true
				cur := f.Cursor()
				p.mu.Lock()
				p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "egress_lagging", SourceID: sourceID, Channel: "egress:" + cur.Sink, Peer: cur.Sink, DetectedAt: now().UnixMilli(),
					LastEventID: cur.LastEventID, Missing: lag, Expected: capB,
					Detail: fmt.Sprintf("this destination is %d bytes behind, past %.0f%% of the spool cap (%d bytes): if it does not recover, the oldest events it has not received will be skipped for it — nothing has been skipped yet", lag, warn*100, capB)}, cur.Sink)
				p.mu.Unlock()
			case warned[i] && float64(lag) < warn*float64(capB)/2:
				warned[i] = false
			}
		}
		for _, sg := range segs {
			if sg.Base != open && sg.End() <= minCur {
				spool.Remove(sg)
			}
		}
		segs = egress.ListSegments(spool.Dir)
		if len(segs) > 1 && head-segs[0].Base > capB && segs[0].Base != open {
			for _, f := range fw {
				if f.Offset() < segs[0].End() {
					f.RequestSkip(segs[0].End())
				}
			}
		}
	}
}

// bufferLoop keeps the local evidence directory a bounded buffer (evidence archive): every tick, the segments every
// deletion condition allows are deleted (archive.Buffer), the local bytes are measured, and the cap is enforced —
// one `evidence_buffer_high` record above the warning mark (re-armed below half of it), one `evidence_buffer_full`
// record when intake stops at the cap, one `evidence_buffer_resumed` record when the buffer is below the mark again.
// Nothing is deleted to make room: only shipped, receipted, covered segments ever leave.
func (p *Pipeline) bufferLoop(store *evidence.Store, o Options, st *Stats, sourceID string, now func() time.Time, stop chan struct{}) {
	tick := o.BufferTick
	if tick <= 0 {
		tick = time.Second
	}
	warn := o.BufferWarn
	if warn <= 0 || warn >= 1 {
		warn = 0.8
	}
	capB := o.BufferCap
	warned := false
	var fullSince time.Time
	var discarded0, discardedB0, refused0 int64
	t := time.NewTicker(tick)
	defer t.Stop()
	record := func(kind string, usage int64, missing int64, detail string) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: kind, SourceID: sourceID, Channel: "evidence:buffer", Peer: "evidence-archive", DetectedAt: now().UnixMilli(),
			Observed: usage, Expected: capB, Missing: missing, Detail: detail}, "evidence-archive")
	}
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		rep := o.Buffer.Sweep(store.OpenSegment())
		usage := rep.LocalBytes
		p.mu.Lock()
		b := st.EvidenceBuffer
		b.LocalBytes, b.LocalSegments = usage, rep.LocalSegments
		b.DeletedSegments += len(rep.Deleted)
		if usage > b.PeakLocalBytes {
			b.PeakLocalBytes = usage
		}
		b.LastBlockedCause = ""
		for _, seg := range evidence.Segments(o.EvidenceDir) {
			if why, ok := rep.Blocked[seg]; ok {
				b.LastBlockedCause = seg + " stays: " + why
				break
			}
		}
		p.mu.Unlock()
		if capB <= 0 {
			continue
		}
		mark := int64(warn * float64(capB))
		switch {
		case !warned && usage > mark:
			warned = true
			record("evidence_buffer_high", usage, 0, fmt.Sprintf("the local evidence buffer holds %d bytes, past %.0f%% of its cap (%d bytes): segments are not leaving — the evidence archive is not taking them, or the committer is not running. Nothing has been refused yet; at the cap intake stops, and no older evidence is deleted to make room", usage, warn*100, capB))
		case warned && usage < mark/2:
			warned = false
		}
		if !p.full.Load() && usage >= capB {
			p.full.Store(true)
			fullSince = time.Now()
			discarded0, discardedB0, refused0 = p.discarded.Load(), p.discardedB.Load(), p.refusedHTTP.Load()
			p.mu.Lock()
			st.EvidenceBuffer.FullEpisodes++
			p.mu.Unlock()
			record("evidence_buffer_full", usage, 0, fmt.Sprintf("the local evidence buffer reached its cap (%d of %d bytes) with the evidence archive not taking segments: intake STOPPED — TCP connections and files are not read (the sender waits, or drops on its side), HTTP is answered 503, UDP datagrams are counted and discarded (never parsed, never delivered). No older evidence is deleted to make room. Size the cap as ingest rate x bytes per event x tolerated archive outage", usage, capB))
		} else if p.full.Load() && usage < mark {
			p.full.Store(false)
			d, db, r := p.discarded.Load()-discarded0, p.discardedB.Load()-discardedB0, p.refusedHTTP.Load()-refused0
			record("evidence_buffer_resumed", usage, d, fmt.Sprintf("intake resumed after %s at the cap: the buffer is back to %d bytes (below %.0f%% of %d). While stopped: %d UDP datagram(s), %d bytes, discarded unread; %d HTTP request(s) answered 503 (the senders keep them); TCP and file input waited",
				time.Since(fullSince).Round(time.Millisecond), usage, warn*100, capB, d, db, r))
		}
	}
}

// recover interprets the evidence records committed after the spool's last event (see RunFramesWith).
func (p *Pipeline) recover(store *evidence.Store, spool *egress.Spool, interpret func(frame.Frame, evidence.Record, string) error) (int, error) {
	last := egress.LastLine(spool.Dir)
	if last == nil {
		return 0, nil
	}
	var ev struct {
		L struct {
			SegmentID string `json:"segment_id"`
			Offset    int64  `json:"offset"`
			StoreID   string `json:"store_id"`
		} `json:"_lineage"`
	}
	if json.Unmarshal(last, &ev) != nil || ev.L.SegmentID == "" || (ev.L.StoreID != "" && ev.L.StoreID != store.ID()) {
		return 0, nil
	}
	dir := p.o.EvidenceDir
	n := 0
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, seg := range evidence.Segments(dir) {
		if seg < ev.L.SegmentID {
			continue
		}
		recs, err := evidence.ReadIndex(dir, seg)
		if err != nil {
			continue // the segment this run just opened: no index lines yet
		}
		raw, err := os.ReadFile(filepath.Join(dir, seg+evidence.SuffixRaw))
		if err != nil {
			return n, err
		}
		for _, r := range recs {
			if (seg == ev.L.SegmentID && r.Offset <= ev.L.Offset) || r.Framing.Method == evidence.MethodGapRecord || r.Offset+int64(r.Length) > int64(len(raw)) {
				continue
			}
			r.StoreID = store.ID()
			b := raw[r.Offset : r.Offset+int64(r.Length)]
			if err := interpret(frame.Frame{Raw: b, Framing: r.Framing, Peer: r.Peer, Channel: r.Channel}, r, r.Channel); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
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
	store, err := evidence.Open(o.EvidenceDir, evidence.Options{Limits: o.Limits, Now: now, NewID: o.NewID, StoreID: o.StoreID})
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
	var spool *egress.Spool
	if o.SpoolDir != "" && len(o.Egress) > 0 {
		var trunc *egress.Truncation
		var err error
		if spool, trunc, err = egress.OpenSpool(o.SpoolDir, o.SpoolSegment, o.SpoolFresh); err != nil {
			return st, err
		}
		defer spool.Close()
		if trunc != nil {
			p.mu.Lock()
			p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "spool_truncated", SourceID: sourceID, Channel: "egress:spool", Peer: trunc.Segment, DetectedAt: now().UnixMilli(),
				Missing: trunc.Bytes, Observed: trunc.At,
				Detail: fmt.Sprintf("a half-written line at the end of spool segment %s (%d bytes) was cut on restart: the event it held is not delivered from the spool; its raw bytes are in the evidence log", trunc.Segment, trunc.Bytes)}, "spool")
			p.mu.Unlock()
		}
	}
	if len(o.Egress) > 0 {
		if o.SpoolPath == "" && spool == nil {
			return st, fmt.Errorf("egress needs the normalized output in a file (--out FILE): the file is the delivery spool")
		}
		timeout := o.EgressTimeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		for _, e := range o.Egress {
			url, batch := egress.SplitBatch(e.URL) // ?batch=N: events per batch for this destination (default 100)
			sink, err := egress.Open(url, timeout)
			if err != nil {
				return st, err
			}
			name := sink.Name()
			f := &egress.Forwarder{Spool: o.SpoolPath, Seg: spool, CursorPath: e.CursorPath, Sink: sink, StallAfter: o.EgressStallAfter, BatchLines: batch, BatchBytes: egress.BatchBytesFor(batch),
				OnSkip: func(s egress.Skip) {
					p.mu.Lock()
					defer p.mu.Unlock()
					what := fmt.Sprintf("%d event(s), %s … %s", s.Count, s.FirstID, s.LastID)
					if s.Count < 0 {
						what = "a range already removed from the spool (this destination's cursor was older than the retained spool)"
					}
					p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "egress_skipped", SourceID: sourceID, Channel: "egress:" + name, Peer: name, DetectedAt: now().UnixMilli(),
						LastEventID: s.LastID, Missing: s.Count, Expected: s.From, Observed: s.To,
						Detail: fmt.Sprintf("spool cap reached while this destination was the slowest: %s (spool bytes %d–%d) will not be delivered to it; this destination only — every other destination is unaffected. The raw bytes remain in the evidence log, so the range is recoverable by re-deriving from it; no re-delivery tool is built", what, s.From, s.To)}, name)
				},
				OnReject: func(r egress.Reject) {
					p.mu.Lock()
					defer p.mu.Unlock()
					p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "egress_rejected", SourceID: sourceID, Channel: "egress:" + name, Peer: name, DetectedAt: now().UnixMilli(),
						LastEventID: r.EventID, Missing: 1,
						Detail: fmt.Sprintf("the destination refused event %s permanently (%s: %s); passed over for this destination. The event stays in the evidence log and in every destination that accepted it — a rejection usually means the destination's index template is wrong", r.EventID, r.Type, r.Reason)}, name)
				},
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
			if err := f.Start(spool == nil || o.SpoolFresh); err != nil { // a single-file spool was just created by this run: the cursor starts at zero; a segmented spool resumes
				return st, err
			}
			forwarders = append(forwarders, f)
		}
	}
	stopRetention := make(chan struct{})
	retentionDone := make(chan struct{})
	if spool != nil {
		go func() {
			defer close(retentionDone)
			p.retention(spool, forwarders, o, sourceID, now, stopRetention)
		}()
	} else {
		close(retentionDone)
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
					p.commitLocked() // frames already received count as heard before silence is judged
					for _, r := range p.tracker.Sweep(now()) {
						p.appendGap(r, r.Peer)
					}
					p.mu.Unlock()
				}
			}
		}()
	}
	commitEvents, commitWait := o.CommitEvents, o.CommitWait
	if commitEvents <= 0 {
		commitEvents = 256
	}
	if commitWait <= 0 {
		commitWait = 10 * time.Millisecond
	}
	var interpret func(fr frame.Frame, rec evidence.Record, channel string) error
	// 1. raw evidence write: hashed and staged here; nothing looks at the bytes until the batch is durable
	one := func(fr frame.Frame) error {
		st.Frames++
		channel := o.Channel
		if fr.Channel != "" {
			channel = fr.Channel
		}
		rec, err := store.AppendBuffered(fr.Raw, fr.Framing, sourceID, o.Collector, channel, fr.Peer)
		if err != nil {
			return err
		}
		if len(p.pending) == 0 {
			p.since = time.Now()
		}
		p.pending = append(p.pending, staged{fr, rec, channel, st.Frames})
		if len(p.pending) >= commitEvents || time.Since(p.since) >= commitWait {
			return p.commitLocked()
		}
		return nil
	}
	// the commit: one write and two fsyncs for the batch, THEN its frames are interpreted in arrival order
	p.commit = func() error {
		batch := p.pending
		p.pending = nil
		if err := store.Sync(); err != nil {
			return err
		}
		if o.FailAfterRawWrite > 0 && batch[0].n <= o.FailAfterRawWrite && o.FailAfterRawWrite <= batch[len(batch)-1].n {
			out.Flush()
			os.Exit(137) // kill-test: die after the batch holding the Nth frame is durable, before any of it is parsed
		}
		for _, s := range batch {
			if err := interpret(s.fr, s.rec, s.channel); err != nil {
				return err
			}
		}
		return nil
	}
	// a batch that stops growing (a listener gone quiet) is committed by the clock, not left waiting
	stopCommit := make(chan struct{})
	commitDone := make(chan struct{})
	go func() {
		defer close(commitDone)
		t := time.NewTicker(commitWait / 2)
		defer t.Stop()
		for {
			select {
			case <-stopCommit:
				return
			case <-t.C:
				p.mu.Lock()
				if len(p.pending) > 0 && time.Since(p.since) >= commitWait {
					p.commitLocked()
				}
				p.mu.Unlock()
			}
		}
	}()
	interpret = func(fr frame.Frame, rec evidence.Record, channel string) error {
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
		if spool != nil {
			if err := spool.Append(append(b, '\n')); err != nil {
				return err
			}
		}
		if len(forwarders) > 0 {
			// the single-file spool is read by the forwarders; with a segmented spool, --out is still read live (the
			// drift monitor, the demo console): in both cases an emitted event is a complete line at once, as before
			if err := out.Flush(); err != nil {
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
	// crash recovery (scale-out, 2026-09-27): a batch is durable BEFORE it is interpreted (invariant 3), so a crash can
	// fall between the two — committed frames, never parsed, never delivered. With a resumed spool, every evidence record
	// committed after the last event the spool holds is interpreted now, before anything new is accepted, with its
	// original event id (destinations stay exactly-once). One `interpretation_recovered` record says how many.
	if spool != nil && !o.SpoolFresh {
		if n, err := p.recover(store, spool, interpret); err != nil {
			return st, err
		} else if n > 0 {
			st.Recovered = n
			p.mu.Lock()
			p.appendGap(gap.Record{RecordVersion: gap.RecordVersion, Kind: "interpretation_recovered", SourceID: sourceID, Channel: "control:restart", Peer: "restart", DetectedAt: now().UnixMilli(),
				Missing: int64(n), Detail: fmt.Sprintf("%d frame(s) were committed to the evidence log by the previous run and never interpreted (it stopped between the commit and the interpretation): interpreted now, before new intake, with their original event ids", n)}, "restart")
			p.mu.Unlock()
		}
	}
	// the local evidence buffer: shipped segments deleted when every condition holds; the cap stops intake
	stopBuffer := make(chan struct{})
	bufferDone := make(chan struct{})
	if o.Buffer != nil {
		st.EvidenceBuffer = &BufferStats{Cap: o.BufferCap}
		go func() {
			defer close(bufferDone)
			p.bufferLoop(store, o, &st, sourceID, now, stopBuffer)
		}()
	} else {
		close(bufferDone)
	}
	udp := func(fr frame.Frame) bool {
		ch := fr.Channel
		if ch == "" {
			ch = o.Channel
		}
		return strings.HasPrefix(ch, "udp:") || fr.Framing.Method == "udp_datagram"
	}
	err = source(func(fr frame.Frame) error {
		// the buffer at its cap: nothing is accepted that is not written, and nothing older is deleted to make room
		for p.full.Load() {
			if udp(fr) { // a datagram cannot be refused: counted, discarded — never parsed, never delivered
				p.discarded.Add(1)
				p.discardedB.Add(int64(len(fr.Raw)))
				return nil
			}
			select { // TCP, file, pull: not read until the buffer drains (the sender waits, or drops on its side)
			case <-o.Done:
				return ErrEvidenceBufferFull
			case <-time.After(20 * time.Millisecond):
			}
		}
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
	close(stopCommit)
	<-commitDone
	p.mu.Lock()
	if cerr := p.commitLocked(); err == nil { // the last batch: whatever arrived is committed and interpreted
		err = cerr
	}
	p.mu.Unlock()
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
	close(stopRetention) // after the drain: a destination still lagging while the others drain is still bounded
	<-retentionDone
	close(stopBuffer)
	<-bufferDone
	p.mu.Lock()
	st.Peers = p.tracker.Peers()
	st.Commits = store.Syncs()
	st.StoreID = store.ID()
	if st.EvidenceBuffer != nil {
		st.EvidenceBuffer.DiscardedFrames, st.EvidenceBuffer.DiscardedBytes, st.EvidenceBuffer.RefusedHTTP = p.discarded.Load(), p.discardedB.Load(), p.refusedHTTP.Load()
		st.EvidenceBuffer.FullNow = p.full.Load()
	}
	if err == nil {
		err = p.err
	}
	p.mu.Unlock()
	return st, err
}
