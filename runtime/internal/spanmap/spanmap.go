// Package spanmap is the runtime's typed form of contracts/span-map.schema.json, plus the tiling
// invariant: for every buffer, spans sorted by start tile [0, length) exactly.
package spanmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const SchemaVersion = "1.1.0" // the engine always emits the current span-map contract version

type Buffer struct {
	ID          string `json:"id"`
	Length      int    `json:"length"`
	DerivedFrom string `json:"derived_from,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
}

type Coerced struct {
	To                string `json:"to"`
	Value             any    `json:"value"`
	FormatSelected    *int   `json:"format_selected,omitempty"`
	PrecisionSelected string `json:"precision_selected,omitempty"`
}

type Span struct {
	Buffer       string   `json:"buffer"`
	Start        int      `json:"start"`
	End          int      `json:"end"`
	Kind         string   `json:"kind"` // semantic | literal | opaque
	Path         string   `json:"path,omitempty"`
	Text         string   `json:"text,omitempty"`
	Value        *string  `json:"value,omitempty"`
	Class        string   `json:"class,omitempty"`
	Encoding     string   `json:"encoding,omitempty"`
	DecodeStatus string   `json:"decode_status,omitempty"`
	DeclaredNull bool     `json:"declared_null,omitempty"`
	Coerced      *Coerced `json:"coerced,omitempty"`
}

type Event struct {
	EventID   string `json:"event_id,omitempty"`
	RawHash   string `json:"raw_hash"`
	RawLength int    `json:"raw_length"`
	RawBase64 string `json:"raw_base64,omitempty"`
}

type Failure struct {
	AtOffset int    `json:"at_offset"`
	Reason   string `json:"reason"`
	Step     string `json:"step,omitempty"`
}

type SpanMap struct {
	SchemaVersion string   `json:"schema_version"`
	SpecID        string   `json:"spec_id"`
	DSLHash       string   `json:"dsl_hash,omitempty"`
	Event         Event    `json:"event"`
	Status        string   `json:"status"` // ok | failed
	Failure       *Failure `json:"failure,omitempty"`
	Buffers       []Buffer `json:"buffers"`
	Spans         []Span   `json:"spans"`
}

func RawHash(raw []byte) string {
	s := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(s[:])
}

// New starts an ok span map over raw with the single raw buffer.
func New(specID string, raw []byte) *SpanMap {
	return &SpanMap{
		SchemaVersion: SchemaVersion, SpecID: specID,
		Event:   Event{RawHash: RawHash(raw), RawLength: len(raw)},
		Status:  "ok",
		Buffers: []Buffer{{ID: "raw", Length: len(raw)}},
		Spans:   []Span{},
	}
}

// Sort orders spans by buffer (raw first) then start — the canonical order.
func (m *SpanMap) Sort() {
	sort.SliceStable(m.Spans, func(i, j int) bool {
		a, b := m.Spans[i], m.Spans[j]
		if a.Buffer != b.Buffer {
			if a.Buffer == "raw" {
				return true
			}
			if b.Buffer == "raw" {
				return false
			}
			return a.Buffer < b.Buffer
		}
		return a.Start < b.Start
	})
}

// CheckTiling enforces the invariant. The parser runs it on every event it emits: a span map that
// fails it is a parser bug and the event is quarantined rather than emitted.
func (m *SpanMap) CheckTiling() error {
	if m.Status != "ok" {
		return nil
	}
	lengths := map[string]int{}
	for _, b := range m.Buffers {
		lengths[b.ID] = b.Length
	}
	if lengths["raw"] != m.Event.RawLength {
		return fmt.Errorf("buffers[raw].length %d != event.raw_length %d", lengths["raw"], m.Event.RawLength)
	}
	byBuf := map[string][]Span{}
	for i, s := range m.Spans {
		if _, ok := lengths[s.Buffer]; !ok {
			return fmt.Errorf("spans[%d]: unknown buffer %q", i, s.Buffer)
		}
		if s.Start >= s.End {
			return fmt.Errorf("spans[%d]: start >= end", i)
		}
		byBuf[s.Buffer] = append(byBuf[s.Buffer], s)
	}
	for buf, length := range lengths {
		spans := byBuf[buf]
		sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
		pos := 0
		for _, s := range spans {
			if s.Start < pos {
				return fmt.Errorf("buffer %q: overlap at %d (expected >= %d)", buf, s.Start, pos)
			}
			if s.Start > pos {
				return fmt.Errorf("buffer %q: gap [%d:%d)", buf, pos, s.Start)
			}
			pos = s.End
		}
		if pos != length {
			return fmt.Errorf("buffer %q: spans cover [0:%d) but length is %d", buf, pos, length)
		}
	}
	return nil
}

func (m *SpanMap) JSON() ([]byte, error) {
	m.Sort()
	return json.MarshalIndent(m, "", "  ")
}
