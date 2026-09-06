package frame

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func collectFrames(t *testing.T, scan func(emit func(Frame) error) error) []Frame {
	t.Helper()
	var out []Frame
	if err := scan(func(fr Frame) error { out = append(out, fr); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func rebuild(frs []Frame) []byte {
	var b []byte
	for _, f := range frs {
		b = append(b, f.Framing.RawPrefix...)
		b = append(b, f.Raw...)
		b = append(b, f.Framing.RawSuffix...)
	}
	return b
}

// RFC 6587 octet counting, non-transparent fallback per frame, and malformed headers — every byte in
// exactly one frame, the stream rebuilt byte for byte.
func TestOctetCountFramesAndFallback(t *testing.T) {
	m1 := "<13>1 2024-01-05T04:05:06Z h app - - - one"
	m2 := "<13>Jan  5 04:05:06 h app: two"
	in := "" +
		itoa(len(m1)) + " " + m1 + // counted
		"<13>Jan  5 04:05:06 h app: non-transparent line\n" + // LF-terminated
		itoa(len(m2)) + " " + m2 + // counted, with an embedded newline inside the count below
		"6 a\nb\ncd" + // counted message containing newlines: the count wins, not the LF
		"12x not a count header\n" + // digits not followed by SP: non-transparent
		"tail without terminator" // EOF mid-line
	frs := collectFrames(t, func(emit func(Frame) error) error {
		return OctetCount{MaxEventBytes: 1024}.Scan(strings.NewReader(in), emit)
	})
	if !bytes.Equal(rebuild(frs), []byte(in)) {
		t.Fatalf("reconstruction failed:\n%q\n%q", rebuild(frs), in)
	}
	want := []struct {
		raw, method, status, conf string
	}{
		{m1, "octet_count", "none", "high"},
		{"<13>Jan  5 04:05:06 h app: non-transparent line", "newline", "none", "high"},
		{m2, "octet_count", "none", "high"},
		{"a\nb\ncd", "octet_count", "none", "high"},
		{"12x not a count header", "newline", "none", "high"},
		{"tail without terminator", "newline", "none", "low"},
	}
	if len(frs) != len(want) {
		t.Fatalf("got %d frames: %+v", len(frs), frs)
	}
	for i, w := range want {
		f := frs[i]
		if string(f.Raw) != w.raw || f.Framing.Method != w.method || f.Framing.TruncationStatus != w.status || f.Framing.FramingConfidence != w.conf {
			t.Fatalf("frame %d: %q %s %s %s; want %+v", i, f.Raw, f.Framing.Method, f.Framing.TruncationStatus, f.Framing.FramingConfidence, w)
		}
	}
	if string(frs[0].Framing.RawPrefix) != itoa(len(m1))+" " {
		t.Fatalf("the count header is the prefix: %q", frs[0].Framing.RawPrefix)
	}
}

// An oversized counted message arrives in bounded pieces; a count the peer never fills is retained
// as a truncated, low-confidence frame (invariant 7).
func TestOctetCountBoundedAndUnfilled(t *testing.T) {
	big := strings.Repeat("x", 250)
	in := "250 " + big + "999 only twenty bytes"
	frs := collectFrames(t, func(emit func(Frame) error) error {
		return OctetCount{MaxEventBytes: 100}.Scan(strings.NewReader(in), emit)
	})
	if !bytes.Equal(rebuild(frs), []byte(in)) {
		t.Fatal("reconstruction failed")
	}
	if len(frs) != 4 {
		t.Fatalf("frames: %d", len(frs))
	}
	if frs[0].Framing.TruncationStatus != "truncated" || len(frs[0].Raw) != 100 || frs[0].Framing.OriginalMessageLength != 250 ||
		frs[1].Framing.TruncationStatus != "truncated" || frs[2].Framing.TruncationStatus != "continuation" || len(frs[2].Raw) != 50 {
		t.Fatalf("pieces: %+v", frs[:3])
	}
	last := frs[3]
	if last.Framing.TruncationStatus != "truncated" || last.Framing.FramingConfidence != "low" || string(last.Raw) != "only twenty bytes" || last.Framing.OriginalMessageLength != 999 {
		t.Fatalf("unfilled count: %+v", last)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
