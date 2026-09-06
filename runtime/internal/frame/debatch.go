package frame

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Debatch explodes a frame whose raw bytes are a JSON array into one frame per element (plan P7:
// "N independently framed, independently hashed events"). Every element frame's raw bytes are the
// element's ORIGINAL bytes (not re-serialised), so each is hashed as received; the array syntax
// around them (`[`, separators, `]`, whitespace) goes into the first element's raw_prefix, the
// inter-element prefixes and the last element's raw_suffix, together with the enclosing frame's own
// prefix and suffix — so prefix + raw + suffix over the elements in order reproduces the batch byte
// for byte and the reconstruction property survives de-batching. Every element carries the batch's
// hash, its index and the batch size (framing.batch_*), so the batch is provable from any element.
//
// A frame that is not a JSON array, or an array that does not parse to its end (malformed batch), is
// returned unchanged: the whole received payload stays one frame, retained as evidence, and the
// router will quarantine it — never a partial explode that loses bytes. An empty array is one
// (unroutable) frame for the same reason. max bounds the number of elements; a larger batch is not
// exploded (it is retained whole and flagged low confidence by the caller's own bound).
func Debatch(fr Frame, max int) ([]Frame, bool) {
	raw := fr.Raw
	if max <= 0 {
		max = 100000
	}
	start := 0
	for start < len(raw) && (raw[start] == ' ' || raw[start] == '\t' || raw[start] == '\r' || raw[start] == '\n') {
		start++
	}
	if start >= len(raw) || raw[start] != '[' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw[start:]))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, false
	}
	type span struct{ a, b int }
	var spans []span
	prevEnd := start + int(dec.InputOffset()) // just after '['
	for dec.More() {
		if len(spans) >= max {
			return nil, false
		}
		// the element starts at the first non-separator byte after the previous element
		a := prevEnd
		for a < len(raw) && (raw[a] == ' ' || raw[a] == '\t' || raw[a] == '\r' || raw[a] == '\n' || raw[a] == ',') {
			a++
		}
		var rm json.RawMessage
		if err := dec.Decode(&rm); err != nil {
			return nil, false
		}
		b := start + int(dec.InputOffset())
		spans = append(spans, span{a, b})
		prevEnd = b
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, false // no closing bracket: malformed, keep whole
	}
	end := start + int(dec.InputOffset())
	if rest := bytes.TrimSpace(raw[end:]); len(rest) != 0 {
		return nil, false // trailing bytes after the array: not a batch, keep whole
	}
	if len(spans) == 0 {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	batchHash := "sha256:" + hex.EncodeToString(sum[:])
	out := make([]Frame, 0, len(spans))
	for i, s := range spans {
		var prefix, suffix []byte
		if i == 0 {
			prefix = append(append([]byte{}, fr.Framing.RawPrefix...), raw[:s.a]...)
		} else {
			prefix = append([]byte{}, raw[spans[i-1].b:s.a]...)
		}
		if i == len(spans)-1 {
			suffix = append(append([]byte{}, raw[s.b:]...), fr.Framing.RawSuffix...)
		} else {
			suffix = []byte{}
		}
		elem := append([]byte{}, raw[s.a:s.b]...)
		out = append(out, Frame{Raw: elem, Peer: fr.Peer, Framing: Framing{Method: "batch_element", RawPrefix: prefix, RawSuffix: suffix, FragmentCount: 1,
			OriginalMessageLength: len(elem), TruncationStatus: "none", FramingConfidence: fr.Framing.FramingConfidence,
			BatchHash: batchHash, BatchIndex: i, BatchSize: len(spans)}})
	}
	return out, true
}
