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
	"ulpf/runtime/internal/normalize"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/route"
)

type Options struct {
	Pack        *pack.Pack
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

type Stats struct {
	Frames      int            `json:"frames"`
	Emitted     int            `json:"emitted"`
	Usable      int            `json:"usable"`
	Quarantined int            `json:"quarantined"`
	Reasons     map[string]int `json:"quarantine_reasons"`
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

// Run processes one input stream to EOF.
func Run(in io.Reader, o Options) (Stats, error) {
	st := Stats{Reasons: map[string]int{}}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	store, err := evidence.Open(o.EvidenceDir, evidence.Options{Limits: o.Limits, Now: now, NewID: o.NewID})
	if err != nil {
		return st, err
	}
	defer store.Close()
	router := route.New(o.Pack)
	out := bufio.NewWriter(o.Out)
	defer out.Flush()
	var q *bufio.Writer
	if o.Quarantine != nil {
		q = bufio.NewWriter(o.Quarantine)
		defer q.Flush()
	}
	maxBytes := o.MaxEventBytes
	if maxBytes == 0 {
		maxBytes = 65536
	}
	env := dsl.Env{SourceLocation: o.Pack.Location}
	quarantine := func(rec evidence.Record, sig, stage, reason string) {
		st.Quarantined++
		st.Reasons[stage]++
		if q != nil {
			b, _ := json.Marshal(quarantined{rec.EventID, rec.RawHash, rec.SegmentID, rec.Offset, rec.Length, sig, stage, reason})
			q.Write(append(b, '\n'))
		}
	}
	err = frame.Newline{MaxEventBytes: maxBytes}.Scan(in, func(fr frame.Frame) error {
		st.Frames++
		// 1. raw evidence write — durable before anything else looks at the bytes
		rec, err := store.Append(fr.Raw, fr.Framing, o.Pack.Source.SourceID, o.Collector, o.Channel)
		if err != nil {
			return err
		}
		if o.FailAfterRawWrite > 0 && st.Frames == o.FailAfterRawWrite {
			out.Flush()
			os.Exit(137) // kill-test: die after the raw write, before parsing
		}
		env.IngestTime = time.UnixMilli(rec.IngestTime)
		if fr.Framing.TruncationStatus != "none" {
			quarantine(rec, "", "framing", "truncated or continuation frame retained as evidence, not parsed")
			return nil
		}
		// 2. route: exact signature match or quarantine
		d := router.Route(fr.Raw)
		if d.Family == nil {
			quarantine(rec, d.Signature, "routing", d.Reason)
			return nil
		}
		// 3. parse
		m, perr := d.Family.Program.Parse(fr.Raw, env)
		if perr != nil {
			quarantine(rec, d.Signature, "tiling", perr.Error())
			return nil
		}
		m.Event.EventID = rec.EventID
		if m.Status != "ok" {
			quarantine(rec, d.Signature, "parse", fmt.Sprintf("at %d: %s", m.Failure.AtOffset, m.Failure.Reason))
			return nil
		}
		// 4. normalize
		ev, missing, nerr := normalize.Normalize(m, normalize.Context{Pack: o.Pack, Family: d.Family, Record: rec, Signature: d.Signature, ProcessingTime: now()})
		if nerr != nil {
			quarantine(rec, d.Signature, "normalize", nerr.Error())
			return nil
		}
		if len(missing) == 0 {
			st.Usable++
		}
		b, _ := json.Marshal(ev)
		if _, err := out.Write(append(b, '\n')); err != nil {
			return err
		}
		st.Emitted++
		return nil
	})
	return st, err
}
