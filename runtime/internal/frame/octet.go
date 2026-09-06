package frame

import (
	"bufio"
	"io"
	"strconv"
)

// OctetCount frames a syslog-over-TCP stream per RFC 6587: octet counting (`MSG-LEN SP MSG`, §3.4.1)
// when a frame starts with a decimal length, else non-transparent framing (LF-terminated, §3.4.2) for
// that frame — decided per frame, so a stream that mixes both, or a peer that sends garbage, is still
// framed and every byte still lands in exactly one frame (prefix holds the `MSG-LEN SP` header; suffix
// holds the LF of a non-transparent frame). Bounded like Newline: a counted message longer than
// MaxEventBytes is emitted in pieces flagged truncated / continuation; a count the peer never fills
// (EOF or reset first) is emitted with what arrived, flagged truncated and low confidence — retained,
// never dropped.
type OctetCount struct {
	MaxEventBytes int
}

const maxCountDigits = 10 // 10 decimal digits: nothing sane declares a 10 GB syslog message

func (o OctetCount) Scan(r io.Reader, emit func(Frame) error) error {
	br := bufio.NewReaderSize(r, 64*1024)
	max := o.MaxEventBytes
	if max <= 0 {
		max = 65536
	}
	nl := Newline{MaxEventBytes: max}
	for {
		head, err := br.Peek(maxCountDigits + 1)
		if err != nil && len(head) == 0 {
			if err == io.EOF {
				return nil
			}
			return err
		}
		n, hdr := countHeader(head)
		if hdr == 0 {
			// non-transparent framing for this frame: read to LF through the newline framer's rules
			if err := nl.scanOne(br, emit); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			continue
		}
		prefix := make([]byte, hdr)
		if _, err := io.ReadFull(br, prefix); err != nil {
			return err
		}
		remaining, first := n, true
		for remaining > 0 {
			want := remaining
			status := "none"
			if n > max { // bounded pieces, P2 convention: full pieces "truncated", the partial tail "continuation"
				status = "truncated"
				if remaining < max {
					status = "continuation"
				}
			}
			if want > max {
				want = max
			}
			buf := make([]byte, want)
			got, rerr := io.ReadFull(br, buf)
			buf = buf[:got]
			pfx := []byte{}
			if first {
				pfx = prefix
			}
			conf := "high"
			if rerr != nil { // EOF or reset before the declared count was filled
				status, conf = "truncated", "low"
			}
			if err := emit(Frame{Raw: buf, Framing: Framing{Method: "octet_count", RawPrefix: pfx, RawSuffix: []byte{}, FragmentCount: 1,
				OriginalMessageLength: n, TruncationStatus: status, FramingConfidence: conf}}); err != nil {
				return err
			}
			if rerr != nil {
				if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
					return nil
				}
				return rerr
			}
			remaining -= got
			first = false
		}
	}
}

// countHeader parses `MSG-LEN SP` at the start of head; hdr is the header length (0 when absent).
func countHeader(head []byte) (n int, hdr int) {
	i := 0
	for i < len(head) && i < maxCountDigits && head[i] >= '0' && head[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(head) || head[i] != ' ' {
		return 0, 0
	}
	v, err := strconv.Atoi(string(head[:i]))
	if err != nil || v <= 0 {
		return 0, 0
	}
	return v, i + 1
}
