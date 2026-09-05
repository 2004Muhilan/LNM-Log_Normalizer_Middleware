package frame

import (
	"bytes"
	"math/rand"
	"testing"
)

func collect(t *testing.T, in []byte, max int) []Frame {
	t.Helper()
	var out []Frame
	if err := (Newline{MaxEventBytes: max}).Scan(bytes.NewReader(in), func(f Frame) error { out = append(out, f); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func reassemble(fs []Frame) []byte {
	var b []byte
	for _, f := range fs {
		b = append(b, f.Framing.RawPrefix...)
		b = append(b, f.Raw...)
		b = append(b, f.Framing.RawSuffix...)
	}
	return b
}

func TestTerminators(t *testing.T) {
	fs := collect(t, []byte("a\nb\r\n\nc"), 0)
	want := []struct{ raw, suffix, status, conf string }{
		{"a", "\n", "none", "high"}, {"b", "\r\n", "none", "high"}, {"", "\n", "none", "high"}, {"c", "", "none", "low"},
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d frames", len(fs))
	}
	for i, w := range want {
		f := fs[i]
		if string(f.Raw) != w.raw || string(f.Framing.RawSuffix) != w.suffix || f.Framing.TruncationStatus != w.status || f.Framing.FramingConfidence != w.conf {
			t.Fatalf("frame %d: %+v", i, f)
		}
	}
}

// Invariant 7: a line longer than the cap never buffers unboundedly; it is emitted in bounded
// pieces, flagged, and the stream still reconstructs byte for byte.
func TestBoundedLongLine(t *testing.T) {
	in := []byte("abcdefghij\nk\n")
	fs := collect(t, in, 4)
	if len(fs) != 4 {
		t.Fatalf("got %d frames", len(fs))
	}
	for i, f := range fs {
		if len(f.Raw) > 4 {
			t.Fatalf("frame %d exceeds cap: %d bytes", i, len(f.Raw))
		}
	}
	if fs[0].Framing.TruncationStatus != "truncated" || fs[1].Framing.TruncationStatus != "truncated" || fs[2].Framing.TruncationStatus != "continuation" || fs[3].Framing.TruncationStatus != "none" {
		t.Fatalf("statuses: %s %s %s %s", fs[0].Framing.TruncationStatus, fs[1].Framing.TruncationStatus, fs[2].Framing.TruncationStatus, fs[3].Framing.TruncationStatus)
	}
	if !bytes.Equal(reassemble(fs), in) {
		t.Fatal("reconstruction differs")
	}
}

func TestReconstructionProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("ab\n\r\x00 ")
	for iter := 0; iter < 500; iter++ {
		n := rng.Intn(64)
		in := make([]byte, n)
		for i := range in {
			in[i] = alphabet[rng.Intn(len(alphabet))]
		}
		fs := collect(t, in, 1+rng.Intn(8))
		if got := reassemble(fs); !bytes.Equal(got, in) {
			t.Fatalf("iter %d: reconstruction differs\n in=%q\nout=%q", iter, in, got)
		}
	}
}
