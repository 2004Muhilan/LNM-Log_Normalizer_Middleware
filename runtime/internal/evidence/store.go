// Package evidence is the raw evidence store: append-only segments of raw event bytes with a
// sidecar index carrying, per event, the framing record needed for byte-exact reconstruction.
// Lifecycle: OPEN (appending) -> SEALED (no further appends) -> IMMUTABLE (write-protected).
// Merkle commitment over IMMUTABLE segments is P5; nothing here depends on it.
//
// Invariant 3: Append fsyncs both the segment and the index before returning, and the pipeline
// parses an event only after Append has returned.
package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ulpf/runtime/internal/frame"
)

type Record struct {
	EventID    string        `json:"event_id"`
	RawHash    string        `json:"raw_hash"`
	SegmentID  string        `json:"segment_id"`
	Offset     int64         `json:"offset"`
	Length     int           `json:"length"`
	Framing    frame.Framing `json:"framing"`
	IngestTime int64         `json:"ingest_time"` // epoch ms
	SourceID   string        `json:"source_id"`
	Collector  string        `json:"collector_id"`
	Channel    string        `json:"ingest_channel"`
	Sequence   int64         `json:"ingest_sequence"`
}

type Limits struct {
	MaxEvents int
	MaxBytes  int64
	MaxAge    time.Duration
}

// DefaultLimits are the architecture's segment-close thresholds (§3.7).
var DefaultLimits = Limits{MaxEvents: 50000, MaxBytes: 32 << 20, MaxAge: 2 * time.Second}

// Options configure a store. Now and NewID are injectable so golden outputs are deterministic.
type Options struct {
	Limits Limits
	Now    func() time.Time
	NewID  func(time.Time) string
}

type Store struct {
	newID  func(time.Time) string
	dir    string
	limits Limits
	now    func() time.Time
	mu     sync.Mutex
	seq    int64
	segN   int
	seg    *os.File
	idx    *os.File
	segID  string
	segLen int64
	segEv  int
	opened time.Time
	states map[string]string
}

func Open(dir string, opts Options) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	newID := opts.NewID
	if newID == nil {
		newID = newEventID
	}
	limits := opts.Limits
	if limits.MaxEvents == 0 {
		limits = DefaultLimits
	}
	s := &Store{dir: dir, limits: limits, now: now, newID: newID, states: map[string]string{}}
	entries, _ := filepath.Glob(filepath.Join(dir, "seg_*.raw"))
	sort.Strings(entries)
	for _, e := range entries {
		var n int
		fmt.Sscanf(filepath.Base(e), "seg_%05d.raw", &n)
		if n >= s.segN {
			s.segN = n + 1
		}
		s.states[strings.TrimSuffix(filepath.Base(e), ".raw")] = "immutable"
	}
	return s, nil
}

func (s *Store) openSegment() error {
	s.segID = fmt.Sprintf("seg_%05d", s.segN)
	s.segN++
	var err error
	s.seg, err = os.OpenFile(filepath.Join(s.dir, s.segID+".raw"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	s.idx, err = os.OpenFile(filepath.Join(s.dir, s.segID+".idx.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	s.segLen, s.segEv, s.opened = 0, 0, s.now()
	s.states[s.segID] = "open"
	return nil
}

// Seal closes the current segment: SEALED, then IMMUTABLE (read-only mode plus chattr +i where the
// filesystem allows it; the privilege boundary itself is P5).
func (s *Store) Seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealLocked()
}

func (s *Store) sealLocked() error {
	if s.seg == nil {
		return nil
	}
	for _, f := range []*os.File{s.seg, s.idx} {
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	s.states[s.segID] = "sealed"
	for _, p := range []string{filepath.Join(s.dir, s.segID+".raw"), filepath.Join(s.dir, s.segID+".idx.jsonl")} {
		_ = os.Chmod(p, 0o444)
		_ = exec.Command("chattr", "+i", p).Run()
	}
	s.states[s.segID] = "immutable"
	s.seg, s.idx = nil, nil
	return nil
}

// Append writes raw bytes and the index record, fsyncs both, and returns the record. It seals and
// rotates when the open segment has reached any limit.
func (s *Store) Append(raw []byte, fr frame.Framing, sourceID, collector, channel string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seg != nil && (s.segEv >= s.limits.MaxEvents || s.segLen+int64(len(raw)) > s.limits.MaxBytes || s.now().Sub(s.opened) >= s.limits.MaxAge) {
		if err := s.sealLocked(); err != nil {
			return Record{}, err
		}
	}
	if s.seg == nil {
		if err := s.openSegment(); err != nil {
			return Record{}, err
		}
	}
	s.seq++
	rec := Record{
		EventID: s.newID(s.now()), RawHash: Hash(raw), SegmentID: s.segID, Offset: s.segLen, Length: len(raw),
		Framing: fr, IngestTime: s.now().UnixMilli(), SourceID: sourceID, Collector: collector, Channel: channel, Sequence: s.seq,
	}
	if _, err := s.seg.Write(raw); err != nil {
		return Record{}, err
	}
	line, _ := json.Marshal(rec)
	if _, err := s.idx.Write(append(line, '\n')); err != nil {
		return Record{}, err
	}
	if err := s.seg.Sync(); err != nil {
		return Record{}, err
	}
	if err := s.idx.Sync(); err != nil {
		return Record{}, err
	}
	s.segLen += int64(len(raw))
	s.segEv++
	return rec, nil
}

func (s *Store) Close() error { return s.Seal() }

// State returns the lifecycle state of a segment: open | sealed | immutable.
func (s *Store) State(segID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[segID]
}

// Reconstruct replays every segment in order and returns prefix + raw + suffix for every event —
// the byte-exact original stream (the P2 kill-test criterion).
func Reconstruct(dir string) ([]byte, []Record, error) {
	idxs, _ := filepath.Glob(filepath.Join(dir, "seg_*.idx.jsonl"))
	sort.Strings(idxs)
	var out []byte
	var recs []Record
	for _, ip := range idxs {
		segID := strings.TrimSuffix(filepath.Base(ip), ".idx.jsonl")
		raw, err := os.ReadFile(filepath.Join(dir, segID+".raw"))
		if err != nil {
			return nil, nil, err
		}
		data, err := os.ReadFile(ip)
		if err != nil {
			return nil, nil, err
		}
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if line == "" {
				continue
			}
			var r Record
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", ip, err)
			}
			if r.Offset+int64(r.Length) > int64(len(raw)) {
				return nil, nil, fmt.Errorf("%s: record %s exceeds segment", segID, r.EventID)
			}
			ev := raw[r.Offset : r.Offset+int64(r.Length)]
			if Hash(ev) != r.RawHash {
				return nil, nil, fmt.Errorf("%s: raw_hash mismatch for %s", segID, r.EventID)
			}
			out = append(out, r.Framing.RawPrefix...)
			out = append(out, ev...)
			out = append(out, r.Framing.RawSuffix...)
			recs = append(recs, r)
		}
	}
	return out, recs, nil
}

func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// newEventID: "ev_" + 26 Crockford base32 chars — 48-bit millisecond timestamp + 80 random bits.
func newEventID(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:])
	return "ev_" + crockford.EncodeToString(b[:])
}
