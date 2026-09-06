package frame

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func newlineFrame(raw string) Frame {
	return Frame{Raw: []byte(raw), Peer: "p", Framing: Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte("\n"), FragmentCount: 1, OriginalMessageLength: len(raw), TruncationStatus: "none", FramingConfidence: "high"}}
}

// One JSON array becomes N frames whose raw bytes are the elements' original bytes; the array syntax
// goes into prefixes and suffixes so the batch (and the enclosing frame) rebuilds byte for byte; each
// element names the batch by hash, index and size.
func TestDebatchElementsAreOriginalBytesAndReconstruct(t *testing.T) {
	raw := ` [ {"a": 1,  "b": "x"} ,{"a":2},
  [1,2,3],"str", 42 ]  `
	fr := newlineFrame(raw)
	elems, ok := Debatch(fr, 0)
	if !ok || len(elems) != 5 {
		t.Fatalf("debatch: ok=%v n=%d", ok, len(elems))
	}
	want := []string{`{"a": 1,  "b": "x"}`, `{"a":2}`, `[1,2,3]`, `"str"`, `42`}
	for i, e := range elems {
		if string(e.Raw) != want[i] || e.Framing.Method != "batch_element" || e.Framing.BatchIndex != i || e.Framing.BatchSize != 5 || e.Peer != "p" {
			t.Fatalf("element %d: %q %+v", i, e.Raw, e.Framing)
		}
	}
	if got := rebuild(elems); !bytes.Equal(got, append([]byte(raw), '\n')) {
		t.Fatalf("reconstruction:\n%q\n%q", got, raw+"\n")
	}
	sum := sha256.Sum256([]byte(raw))
	if elems[0].Framing.BatchHash != "sha256:"+hex.EncodeToString(sum[:]) || elems[4].Framing.BatchHash != elems[0].Framing.BatchHash {
		t.Fatal("batch hash must be the hash of the whole received batch on every element")
	}
}

// Malformed or non-batch input is left whole: nothing is exploded partially, nothing is lost.
func TestDebatchLeavesMalformedWhole(t *testing.T) {
	for _, s := range []string{`[{"a":1},{"a":2}`, `[{"a":1}, oops]`, `{"a":1}`, `[]`, `[1] trailing`, `not json`, `[1,2]x`} {
		if elems, ok := Debatch(newlineFrame(s), 0); ok {
			t.Fatalf("%q must stay one frame, got %d elements", s, len(elems))
		}
	}
	if _, ok := Debatch(newlineFrame(`[1,2,3,4,5]`), 3); ok {
		t.Fatal("a batch over the element bound must stay whole")
	}
}
