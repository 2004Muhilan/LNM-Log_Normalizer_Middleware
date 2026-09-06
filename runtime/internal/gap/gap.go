// Package gap is continuity accounting (plan P7): per-peer counters, sequence-gap detection where the
// transport carries a sequence, silence detection, and connection loss mid-frame — each producing a
// gap record. A gap record is appended to the evidence store as a record of its own (framing method
// gap_record, see evidence.MethodGapRecord): it is hashed, sits in the segment's Merkle tree next to
// the events around it, is committed and signed with them, can be exported as a bundle and verified
// by the external witness with nothing but the trust store. Absence therefore becomes tamper-evident
// in the same structure as presence: removing a gap record breaks the committed root exactly as
// removing an event would.
//
// What is detected, and what is not claimed:
//   - sequence_gap: the peer's messages carry RFC 5424 structured data `[meta sequenceId="N"]` (RFC
//     5424 §7.3.1) and N jumps by more than one. Missing = observed - expected. A sequence that goes
//     BACKWARDS is recorded as a sequence_reset (a restart, not a loss). No sequence, no claim.
//   - silence: a peer that has been heard from stops for longer than SilenceAfter. Recorded once when
//     detected; the next message from that peer closes it (silence_end, with the measured duration).
//   - connection_lost: a stream peer went away with a partial frame pending (the partial frame itself
//     is retained as a low-confidence evidence record; this record says the boundary was not seen).
//
// Records are canonical JSON (sorted keys, no whitespace) so the same detection yields the same bytes
// and the same hash on any machine.
package gap

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"time"
)

const RecordVersion = "gap-record 1.0.0"

// Record is one detected discontinuity. All times are epoch milliseconds.
type Record struct {
	RecordVersion string `json:"record_version"`
	Kind          string `json:"kind"` // sequence_gap | sequence_reset | silence | silence_end | connection_lost
	SourceID      string `json:"source_id"`
	Channel       string `json:"channel"`
	Peer          string `json:"peer"`
	DetectedAt    int64  `json:"detected_at"`
	LastSeenAt    int64  `json:"last_seen_at,omitempty"`
	LastEventID   string `json:"last_event_id,omitempty"`
	Expected      int64  `json:"expected_sequence,omitempty"`
	Observed      int64  `json:"observed_sequence,omitempty"`
	Missing       int64  `json:"missing,omitempty"`
	SilenceMS     int64  `json:"silence_ms,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// Canonical is the record's bytes as stored: JSON with sorted keys and no insignificant whitespace.
func Canonical(r Record) []byte {
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		out = append(out, kb...)
		out = append(out, ':')
		out = append(out, vb...)
	}
	return append(out, '}')
}

// Parse reads a stored gap record.
func Parse(b []byte) (Record, error) {
	var r Record
	err := json.Unmarshal(b, &r)
	return r, err
}

var reSeq = regexp.MustCompile(`\[meta(?: [^\]]*?)? sequenceId="([0-9]{1,18})"`)

// SequenceID extracts RFC 5424 `[meta sequenceId="N"]` from a structured-data string.
func SequenceID(structuredData string) (int64, bool) {
	m := reSeq.FindStringSubmatch(structuredData)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseInt(m[1], 10, 64)
	return v, err == nil
}

type peerState struct {
	sourceID, channel string
	lastSeen          time.Time
	lastEventID       string
	lastSeq           int64
	hasSeq            bool
	count             int64
	silent            bool
	silentSince       time.Time
}

// Tracker keeps per-peer continuity state. Not safe for concurrent use; the pipeline serialises.
type Tracker struct {
	SilenceAfter time.Duration
	peers        map[string]*peerState
}

func New(silenceAfter time.Duration) *Tracker {
	return &Tracker{SilenceAfter: silenceAfter, peers: map[string]*peerState{}}
}

// Observe records one received frame from peer and returns the gap records it closes or opens:
// silence_end if the peer had been declared silent, sequence_gap / sequence_reset if seq is present
// and discontinuous.
func (t *Tracker) Observe(peer, sourceID, channel, eventID string, seq *int64, now time.Time) []Record {
	var out []Record
	p := t.peers[peer]
	if p == nil {
		p = &peerState{sourceID: sourceID, channel: channel}
		t.peers[peer] = p
	}
	if p.silent {
		out = append(out, Record{RecordVersion: RecordVersion, Kind: "silence_end", SourceID: sourceID, Channel: channel, Peer: peer,
			DetectedAt: now.UnixMilli(), LastSeenAt: p.lastSeen.UnixMilli(), LastEventID: p.lastEventID, SilenceMS: now.Sub(p.lastSeen).Milliseconds()})
		p.silent = false
	}
	if seq != nil {
		if p.hasSeq {
			switch {
			case *seq == p.lastSeq+1:
			case *seq > p.lastSeq+1:
				out = append(out, Record{RecordVersion: RecordVersion, Kind: "sequence_gap", SourceID: sourceID, Channel: channel, Peer: peer,
					DetectedAt: now.UnixMilli(), LastSeenAt: p.lastSeen.UnixMilli(), LastEventID: p.lastEventID,
					Expected: p.lastSeq + 1, Observed: *seq, Missing: *seq - p.lastSeq - 1})
			default:
				out = append(out, Record{RecordVersion: RecordVersion, Kind: "sequence_reset", SourceID: sourceID, Channel: channel, Peer: peer,
					DetectedAt: now.UnixMilli(), LastSeenAt: p.lastSeen.UnixMilli(), LastEventID: p.lastEventID,
					Expected: p.lastSeq + 1, Observed: *seq, Detail: "sequence went backwards: sender restart, not a loss"})
			}
		}
		p.lastSeq, p.hasSeq = *seq, true
	}
	p.lastSeen, p.lastEventID = now, eventID
	p.count++
	return out
}

// Sweep declares silent every peer not heard from for longer than SilenceAfter (once per silence).
func (t *Tracker) Sweep(now time.Time) []Record {
	if t.SilenceAfter <= 0 {
		return nil
	}
	var out []Record
	peers := make([]string, 0, len(t.peers))
	for k := range t.peers {
		peers = append(peers, k)
	}
	sort.Strings(peers)
	for _, k := range peers {
		p := t.peers[k]
		if p.silent || now.Sub(p.lastSeen) < t.SilenceAfter {
			continue
		}
		p.silent, p.silentSince = true, now
		out = append(out, Record{RecordVersion: RecordVersion, Kind: "silence", SourceID: p.sourceID, Channel: p.channel, Peer: k,
			DetectedAt: now.UnixMilli(), LastSeenAt: p.lastSeen.UnixMilli(), LastEventID: p.lastEventID, SilenceMS: now.Sub(p.lastSeen).Milliseconds(),
			Detail: "no message from this peer for longer than the silence threshold"})
	}
	return out
}

// Lost records that a stream peer went away with a partial frame pending.
func (t *Tracker) Lost(peer, sourceID, channel, detail string, now time.Time) Record {
	p := t.peers[peer]
	r := Record{RecordVersion: RecordVersion, Kind: "connection_lost", SourceID: sourceID, Channel: channel, Peer: peer, DetectedAt: now.UnixMilli(), Detail: detail}
	if p != nil {
		r.LastSeenAt, r.LastEventID = p.lastSeen.UnixMilli(), p.lastEventID
	}
	return r
}

// Peers reports how many peers have been seen.
func (t *Tracker) Peers() int { return len(t.peers) }
