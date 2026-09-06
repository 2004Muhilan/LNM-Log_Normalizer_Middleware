package frame

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// A Java-style stack trace: the event starts at a timestamp line; lines that do not match join the
// open event and keep their terminators inside it; a line before any start line is its own event
// flagged low; the line bound forces a split flagged low. The stream rebuilds byte for byte.
func TestMultilineJoinsAndReconstructs(t *testing.T) {
	in := "stray continuation first\n" +
		"2024-01-05 04:05:06 ERROR boom\n\tat a.b.C(C.java:1)\n\tat d.e.F(F.java:2)\r\n" +
		"2024-01-05 04:05:07 INFO fine\n" +
		"2024-01-05 04:05:08 WARN x\n"
	start := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} `)
	var out []Frame
	j := Multiline{Start: start, MaxLines: 3}.Joiner(func(fr Frame) error { out = append(out, fr); return nil })
	if err := (Newline{}).Scan(strings.NewReader(in), j.Feed); err != nil {
		t.Fatal(err)
	}
	if err := j.Flush(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuild(out), []byte(in)) {
		t.Fatalf("reconstruction:\n%q", rebuild(out))
	}
	if len(out) != 4 {
		t.Fatalf("frames: %d %+v", len(out), out)
	}
	if string(out[0].Raw) != "stray continuation first" || out[0].Framing.FramingConfidence != "low" || out[0].Framing.Method != "multiline" {
		t.Fatalf("an event that did not begin with a start line is flagged: %+v", out[0])
	}
	if string(out[1].Raw) != "2024-01-05 04:05:06 ERROR boom\n\tat a.b.C(C.java:1)\n\tat d.e.F(F.java:2)" || string(out[1].Framing.RawSuffix) != "\r\n" || out[1].Framing.FragmentCount != 3 || out[1].Framing.FramingConfidence != "low" {
		t.Fatalf("joined event at the line bound: %q %+v", out[1].Raw, out[1].Framing)
	}
	if string(out[2].Raw) != "2024-01-05 04:05:07 INFO fine" || out[2].Framing.FragmentCount != 1 || out[2].Framing.FramingConfidence != "high" {
		t.Fatalf("single-line event: %+v", out[2])
	}
	if string(out[3].Raw) != "2024-01-05 04:05:08 WARN x" {
		t.Fatalf("last: %+v", out[3])
	}
	// a continuation that arrives while an event is open joins it, terminator included
	out = nil
	j = Multiline{Start: start}.Joiner(func(fr Frame) error { out = append(out, fr); return nil })
	_ = (Newline{}).Scan(strings.NewReader("2024-01-05 04:05:07 INFO fine\nmore\n"), j.Feed)
	_ = j.Flush()
	if len(out) != 1 || string(out[0].Raw) != "2024-01-05 04:05:07 INFO fine\nmore" || out[0].Framing.FragmentCount != 2 {
		t.Fatalf("join: %+v", out)
	}
}
