package pipeline

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ulpf/runtime/internal/archive"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/keys"
)

// capOpts: small segments, a small cap, a fast sweep, and an evidence archive that is DOWN (the path does not exist:
// nothing is ever receipted, so nothing may leave the local buffer).
func capOpts(t *testing.T, channel string, out *bytes.Buffer) Options {
	o := fixedOpts(t, loadGoldenPack(t), out, nil)
	o.Quarantine = nil
	o.Channel = channel
	o.Limits = evidence.Limits{MaxEvents: 8, MaxBytes: 1 << 20, MaxAge: time.Hour}
	o.Buffer = &archive.Buffer{Dir: o.EvidenceDir, Archive: filepath.Join(t.TempDir(), "unreachable-archive"), Trust: keys.TrustStore{Dir: t.TempDir()}}
	o.BufferCap, o.BufferTick = 12<<10, 5*time.Millisecond
	return o
}

func pacedSquid(t *testing.T, n int) [][]byte {
	in, _ := os.ReadFile(filepath.Join(loadGoldenPack(t).Dir, "samples", "access.log"))
	lines := bytes.SplitAfter(bytes.TrimRight(in, "\n"), []byte("\n"))
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, bytes.TrimRight(lines[i%len(lines)], "\n"))
	}
	return out
}

func frameOf(b []byte, channel string) frame.Frame {
	return frame.Frame{Raw: b, Channel: channel, Peer: "127.0.0.1:5514", Framing: frame.Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte("\n"), FragmentCount: 1,
		OriginalMessageLength: len(b), TruncationStatus: "none", FramingConfidence: "high"}}
}

// Archive down -> the buffer reaches its cap -> new events are refused (UDP: counted and discarded, never parsed or
// delivered), one evidence_buffer_full record is COMMITTED to the evidence log, and no older evidence is deleted.
func TestArchiveDownCapRefusesNewEventsAndDeletesNothing(t *testing.T) {
	var out bytes.Buffer
	o := capOpts(t, "udp:127.0.0.1:5514", &out)
	lines := pacedSquid(t, 300)
	st, err := RunFrames(func(emit func(frame.Frame) error) error {
		for _, l := range lines {
			if err := emit(frameOf(l, "udp:127.0.0.1:5514")); err != nil {
				return err
			}
			time.Sleep(time.Millisecond)
		}
		return nil
	}, o)
	if err != nil {
		t.Fatal(err)
	}
	b := st.EvidenceBuffer
	if b == nil || b.FullEpisodes != 1 || b.DiscardedFrames == 0 || b.DeletedSegments != 0 {
		t.Fatalf("the cap must stop intake once, discard datagrams and delete nothing: %+v", b)
	}
	if int64(st.Received)+b.DiscardedFrames != int64(len(lines)) {
		t.Fatalf("every datagram is either received (evidence first) or counted as discarded: %d + %d != %d", st.Received, b.DiscardedFrames, len(lines))
	}
	if st.GapKinds["evidence_buffer_high"] != 1 || st.GapKinds["evidence_buffer_full"] != 1 {
		t.Fatalf("one high-water record, then one full record: %v", st.GapKinds)
	}
	// the full record is committed evidence: it is in the evidence log, durable, like any leaf
	found := false
	loc := evidence.NewLocator(o.EvidenceDir, "")
	for _, seg := range loc.Segments() {
		recs, _ := loc.ReadIndex(seg)
		raw, _, _ := loc.ReadFile(seg, evidence.SuffixRaw)
		for _, r := range recs {
			if r.Framing.Method == evidence.MethodGapRecord && bytes.Contains(raw[r.Offset:r.Offset+int64(r.Length)], []byte(`"kind":"evidence_buffer_full"`)) {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("the evidence_buffer_full record must be in the evidence log")
	}
	// nothing older deleted: every segment the store ever opened is still local, no catalogue, no deletion log
	if n, segs := evidence.NextSegmentNumber(o.EvidenceDir), len(evidence.Segments(o.EvidenceDir)); n != segs || segs < 3 {
		t.Fatalf("segments opened %d, still local %d", n, segs)
	}
	if _, err := os.Stat(filepath.Join(o.EvidenceDir, "deleted.jsonl")); err == nil {
		t.Fatal("nothing may be deleted while the archive is down")
	}
	// and nothing was parsed without evidence: every emitted event's bytes are in the local evidence
	if st.Emitted == 0 || st.Emitted > st.Received {
		t.Fatalf("emitted %d of %d received", st.Emitted, st.Received)
	}
}

// For a stream that can wait (TCP, a file): intake blocks at the cap — the frame is not read — and HTTP is refused
// (Admit). Shutdown (Done) ends the wait with ErrEvidenceBufferFull; the frames not taken were never received.
func TestArchiveDownCapBlocksAStreamAndRefusesHTTP(t *testing.T) {
	var out bytes.Buffer
	o := capOpts(t, "tcp:127.0.0.1:6514", &out)
	done := make(chan struct{})
	o.Done = done
	lines := pacedSquid(t, 1000)
	ready := make(chan *Pipeline, 1)
	admitted := make(chan error, 1)
	sent := 0
	go func() {
		pl := <-ready
		for !pl.full.Load() {
			time.Sleep(5 * time.Millisecond)
		}
		admitted <- pl.Admit()
		time.Sleep(100 * time.Millisecond) // blocked: nothing is read while full
		close(done)
	}()
	st, err := RunFramesWith(func(emit func(frame.Frame) error) error {
		for _, l := range lines {
			if err := emit(frameOf(l, "tcp:127.0.0.1:6514")); err != nil {
				return err
			}
			sent++
			time.Sleep(time.Millisecond)
		}
		return nil
	}, o, func(p *Pipeline) { ready <- p })
	if !errors.Is(err, ErrEvidenceBufferFull) {
		t.Fatalf("a stream blocked at the cap ends with ErrEvidenceBufferFull at shutdown, got %v", err)
	}
	if a := <-admitted; !errors.Is(a, ErrEvidenceBufferFull) {
		t.Fatalf("HTTP must be refused while full: %v", a)
	}
	if sent >= len(lines) || st.Received != sent || st.EvidenceBuffer.DiscardedFrames != 0 || st.EvidenceBuffer.RefusedHTTP != 1 {
		t.Fatalf("sent %d of %d, received %d, %+v", sent, len(lines), st.Received, st.EvidenceBuffer)
	}
	if st.GapKinds["evidence_buffer_full"] != 1 || st.EvidenceBuffer.DeletedSegments != 0 {
		t.Fatalf("%v %+v", st.GapKinds, st.EvidenceBuffer)
	}
}
