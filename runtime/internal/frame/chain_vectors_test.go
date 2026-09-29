package frame

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The learning plane unwraps with a Python twin of UnwrapChain (learning/ulpf_learn/envelope.py: chain), so that
// onboarding drafts from exactly the payload routing routes. Both sides are held to ONE file of vectors — real
// FortiGate lines from the lab device in every syslog format, relay chains, LEEF, CEF, and the lines that must NOT
// unwrap — so the twin cannot drift from the runtime unnoticed (2026-09-30; before it, FortiGate JSON was drafted as
// CSV and CEF as positional text). ULPF_UPDATE_VECTORS=1 rewrites the expectations from this, the reference side.
func TestChainVectorsSharedWithTheLearningPlane(t *testing.T) {
	path := filepath.Join("..", "..", "..", "learning", "tests", "envelope_vectors.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no shared vectors file: " + err.Error())
	}
	var vs []map[string]any
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	update := os.Getenv("ULPF_UPDATE_VECTORS") == "1"
	for _, v := range vs {
		raw := []byte(v["raw"].(string))
		c := UnwrapChain(raw)
		kinds := c.Kinds()
		if update {
			v["kinds"], v["payload_offset"], v["payload_length"] = kinds, c.PayloadOffset, c.PayloadLength
			continue
		}
		var want []string
		for _, k := range v["kinds"].([]any) {
			want = append(want, k.(string))
		}
		if len(want) == 0 {
			want = []string{}
		}
		if len(kinds) == 0 {
			kinds = []string{}
		}
		if !reflect.DeepEqual(kinds, want) || c.PayloadOffset != int(v["payload_offset"].(float64)) || c.PayloadLength != int(v["payload_length"].(float64)) {
			t.Errorf("%s: kinds %v payload %d+%d, the vectors say %v %v+%v", v["name"], kinds, c.PayloadOffset, c.PayloadLength, want, v["payload_offset"], v["payload_length"])
		}
	}
	if update {
		out, _ := json.MarshalIndent(vs, "", " ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("vectors updated from the runtime")
	}
}
