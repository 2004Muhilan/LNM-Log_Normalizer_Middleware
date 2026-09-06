package frame

import (
	"regexp"
)

// Multiline is the one multiline mechanism (plan P7): a new event starts at a line matching Start;
// lines that do not match are appended to the open event, keeping their terminators INSIDE the raw
// bytes (the event's raw_suffix is the last line's terminator), so reconstruction is unchanged.
// Bounded by MaxLines and MaxBytes: an event that reaches either bound is flushed as it stands and
// flagged low confidence (a continuation line that follows starts a new, likewise-flagged event);
// nothing waits on a timer here — a streaming source flushes on its own idle timeout or close by
// calling Flush, which is how "max wait" is bounded.
type Multiline struct {
	Start    *regexp.Regexp
	MaxLines int
	MaxBytes int
}

// Joiner accumulates line frames from any framer and emits multiline frames.
type Joiner struct {
	m     Multiline
	emit  func(Frame) error
	buf   Frame
	lines int
	open  bool
	bound bool
}

func (m Multiline) Joiner(emit func(Frame) error) *Joiner {
	if m.MaxLines <= 0 {
		m.MaxLines = 512
	}
	if m.MaxBytes <= 0 {
		m.MaxBytes = 1 << 20
	}
	return &Joiner{m: m, emit: emit}
}

// Feed takes one line frame. Truncated or continuation pieces pass through untouched (they are already
// evidence of a bound being hit); they close any open event first so order is preserved.
func (j *Joiner) Feed(fr Frame) error {
	if fr.Framing.TruncationStatus != "none" {
		if err := j.Flush(); err != nil {
			return err
		}
		return j.emit(fr)
	}
	if j.open && j.m.Start.Match(fr.Raw) {
		if err := j.Flush(); err != nil {
			return err
		}
	}
	if !j.open {
		j.buf = Frame{Raw: append([]byte{}, fr.Raw...), Peer: fr.Peer, Framing: fr.Framing}
		j.buf.Framing.Method = "multiline"
		j.buf.Framing.RawPrefix = append([]byte{}, fr.Framing.RawPrefix...)
		j.open, j.lines, j.bound = true, 1, false
		if !j.m.Start.Match(fr.Raw) {
			j.buf.Framing.FramingConfidence = "low" // an event that did not begin with a start line
		}
	} else {
		// the previous line's terminator becomes part of the event's raw bytes
		j.buf.Raw = append(j.buf.Raw, j.buf.Framing.RawSuffix...)
		j.buf.Raw = append(j.buf.Raw, fr.Raw...)
		j.buf.Framing.RawSuffix = append([]byte{}, fr.Framing.RawSuffix...)
		j.lines++
	}
	j.buf.Framing.FragmentCount = j.lines
	j.buf.Framing.OriginalMessageLength = len(j.buf.Raw)
	if j.lines >= j.m.MaxLines || len(j.buf.Raw) >= j.m.MaxBytes {
		j.buf.Framing.FramingConfidence = "low" // forced split at the bound
		return j.Flush()
	}
	return nil
}

// Flush emits the open event, if any.
func (j *Joiner) Flush() error {
	if !j.open {
		return nil
	}
	fr := j.buf
	j.open = false
	j.buf = Frame{}
	return j.emit(fr)
}
