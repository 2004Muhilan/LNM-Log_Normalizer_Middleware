// Package frame turns a byte stream into events. Every byte of the stream ends up in exactly one
// of: an event's raw bytes, its raw_prefix, or its raw_suffix — so the stream is reconstructible
// byte for byte as prefix + raw + suffix over the events in order. Buffers are bounded: a line
// longer than MaxEventBytes is emitted in bounded pieces flagged truncated / continuation.
package frame

import (
	"bufio"
	"bytes"
	"io"
)

// Framing is the structured framing record (architecture §4.9; P1 boundary decision 2). Prefix and
// suffix are the literal bytes stripped around the event; a method name alone cannot tell LF from CRLF.
type Framing struct {
	Method                string `json:"method"`
	RawPrefix             []byte `json:"raw_prefix"`
	RawSuffix             []byte `json:"raw_suffix"`
	FragmentCount         int    `json:"fragment_count"`
	OriginalMessageLength int    `json:"original_message_length"`
	TruncationStatus      string `json:"truncation_status"`  // none | truncated | continuation
	FramingConfidence     string `json:"framing_confidence"` // high | low
	// P7 de-batching: set on batch_element frames — the hash of the whole received batch, the
	// element's index in it and the batch size, so the batch is provable from any one element.
	BatchHash  string `json:"batch_hash,omitempty"`
	BatchIndex int    `json:"batch_index,omitempty"`
	BatchSize  int    `json:"batch_size,omitempty"`
}

type Frame struct {
	Raw     []byte
	Framing Framing
	// Peer identifies where the frame came from within a channel: the remote address of a TCP/HTTP
	// connection or UDP sender, the file name for a pull-directory drop. Continuity and gap
	// accounting (P7) are kept per peer; empty for a single file stream.
	Peer string
	// Channel names the ingest connector the frame arrived on when one runtime serves several at once
	// (`--listen` repeated); empty means the run's single channel (Options.Channel).
	Channel string
}

// Newline frames on LF, preserving CRLF in raw_suffix, with a hard per-event byte cap.
type Newline struct {
	MaxEventBytes int
}

// Scan reads r to EOF and calls emit for every frame in stream order. A final line without a
// terminator is emitted with an empty suffix and low framing confidence.
func (n Newline) Scan(r io.Reader, emit func(Frame) error) error {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		if err := n.scanOne(br, emit); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// scanOne frames exactly one line (or the bounded pieces of one over-long line) from br. Returns
// io.EOF when the reader is exhausted with nothing pending. On any other read error the bytes read so
// far are emitted first, flagged low confidence: a connection reset or idle timeout mid-line loses
// nothing — the partial frame is evidence (P7, invariant 7).
func (n Newline) scanOne(br *bufio.Reader, emit func(Frame) error) error {
	max := n.MaxEventBytes
	if max <= 0 {
		max = 65536
	}
	mk := func(raw, suffix []byte, status, conf string) Frame {
		return Frame{Raw: raw, Framing: Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: suffix,
			FragmentCount: 1, OriginalMessageLength: len(raw), TruncationStatus: status, FramingConfidence: conf}}
	}
	chunk := make([]byte, 0, 256)
	continuation := false
	for {
		b, err := br.ReadByte()
		if err != nil {
			if len(chunk) == 0 {
				return err
			}
			status := "none"
			if continuation {
				status = "continuation"
			}
			if eerr := emit(mk(chunk, []byte{}, status, "low")); eerr != nil {
				return eerr
			}
			return err
		}
		if b == '\n' {
			raw, suffix := chunk, []byte{'\n'}
			if bytes.HasSuffix(raw, []byte{'\r'}) {
				raw, suffix = raw[:len(raw)-1], []byte{'\r', '\n'}
			}
			status := "none"
			if continuation {
				status = "continuation"
			}
			return emit(mk(raw, suffix, status, "high"))
		}
		chunk = append(chunk, b)
		if len(chunk) >= max {
			// Bound reached: emit what we have, flagged; the rest of the line continues as new frames.
			// Convention (P2, kept by the octet-count framer in P7): every full-size piece is
			// "truncated", the final partial piece (with the terminator) is "continuation".
			if err := emit(mk(chunk, []byte{}, "truncated", "low")); err != nil {
				return err
			}
			chunk, continuation = make([]byte, 0, 256), true
		}
	}
}
