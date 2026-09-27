package egress

// The bounded delivery spool (laptop branch, 2026-09-27). Before it, the spool was the run's `--out` file: one file,
// never trimmed, recreated by every run. With `--spool DIR` the forwarders read a DIRECTORY of segment files instead:
//
//   - seg-<20-digit global offset>.jsonl — each segment is named by the global byte offset of its first byte, so a
//     cursor is one number across segments and a segment boundary is always a line boundary.
//   - SPOOL_ID — random, written when the spool is created: a cursor or a downstream high-water mark taken on another
//     spool is recognised as foreign.
//   - cursor-<destination>.json — one per destination, keyed by the destination's name (not by its position in the
//     --forward list, so reordering the list moves no cursor).
//
// Retention is governed by the slowest destination: a closed segment is removed when every destination's cursor has
// passed it. The cap bounds the disk: when the retained bytes exceed it, the destinations still inside the oldest
// segment are moved past it and each move is an `egress_skipped` evidence record (pipeline.go) — never a silent drop.
// The run RESUMES an existing spool (a reversal of "every run creates a fresh spool", recorded in docs/laptop-branch.md);
// a half-written last line left by a crash is cut back and reported, because the next append would otherwise glue
// onto it and deliver a corrupt line.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var segName = regexp.MustCompile(`^seg-(\d{20})\.jsonl$`)

// Segment is one spool file.
type Segment struct {
	Base int64 // global offset of its first byte
	Size int64
	Path string
}

// End is the global offset one past its last byte.
func (s Segment) End() int64 { return s.Base + s.Size }

// Truncation reports a half-written tail cut back when an existing spool was reopened.
type Truncation struct {
	Segment string
	At      int64 // global offset the segment now ends at
	Bytes   int64 // bytes removed
}

// Spool is the writer side (the pipeline) and the listing both sides share.
type Spool struct {
	Dir          string
	SegmentBytes int64
	ID           string

	mu   sync.Mutex
	f    *os.File
	base int64
	size int64
}

// OpenSpool opens (resume) or creates a spool directory. fresh removes the previous spool and its cursors first.
func OpenSpool(dir string, segmentBytes int64, fresh bool) (*Spool, *Truncation, error) {
	if segmentBytes <= 0 {
		segmentBytes = 16 << 20
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	if fresh {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			n := e.Name()
			if segName.MatchString(n) || n == "SPOOL_ID" || (strings.HasPrefix(n, "cursor-") && strings.HasSuffix(n, ".json")) {
				if err := os.Remove(filepath.Join(dir, n)); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	s := &Spool{Dir: dir, SegmentBytes: segmentBytes}
	idb, err := os.ReadFile(filepath.Join(dir, "SPOOL_ID"))
	segs := ListSegments(dir)
	switch {
	case err == nil:
		s.ID = strings.TrimSpace(string(idb))
	case len(segs) > 0:
		return nil, nil, fmt.Errorf("egress: spool %s holds segments but no SPOOL_ID — refusing to guess which spool they belong to", dir)
	default:
		var r [8]byte
		if _, err := rand.Read(r[:]); err != nil {
			return nil, nil, err
		}
		s.ID = hex.EncodeToString(r[:])
		if err := writeFileAtomic(filepath.Join(dir, "SPOOL_ID"), []byte(s.ID+"\n")); err != nil {
			return nil, nil, err
		}
	}
	var trunc *Truncation
	if len(segs) == 0 {
		return s, nil, s.openSegment(0)
	}
	last := segs[len(segs)-1]
	b, err := os.ReadFile(last.Path)
	if err != nil {
		return nil, nil, err
	}
	keep := int64(bytes.LastIndexByte(b, '\n') + 1)
	if keep < int64(len(b)) {
		if err := os.Truncate(last.Path, keep); err != nil {
			return nil, nil, err
		}
		trunc = &Truncation{Segment: filepath.Base(last.Path), At: last.Base + keep, Bytes: int64(len(b)) - keep}
	}
	if s.f, err = os.OpenFile(last.Path, os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		return nil, nil, err
	}
	s.base, s.size = last.Base, keep
	return s, trunc, nil
}

func (s *Spool) openSegment(base int64) error {
	f, err := os.OpenFile(filepath.Join(s.Dir, fmt.Sprintf("seg-%020d.jsonl", base)), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	s.f, s.base, s.size = f, base, 0
	return nil
}

// Append writes complete lines (each ending in '\n'); a segment is rotated only between lines.
func (s *Spool) Append(lines []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.size >= s.SegmentBytes {
		if err := s.f.Close(); err != nil {
			return err
		}
		if err := s.openSegment(s.base + s.size); err != nil {
			return err
		}
	}
	n, err := s.f.Write(lines)
	s.size += int64(n)
	return err
}

// Head is the global offset one past the last byte written.
func (s *Spool) Head() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.base + s.size
}

// OpenBase is the base of the segment being written (it is never removed).
func (s *Spool) OpenBase() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.base
}

// Remove deletes a closed segment every destination has passed.
func (s *Spool) Remove(seg Segment) error {
	if seg.Base == s.OpenBase() {
		return errors.New("egress: the open spool segment is never removed")
	}
	return os.Remove(seg.Path)
}

func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// CursorPath is where a destination's cursor lives in this spool.
func (s *Spool) CursorPath(sinkName string) string {
	return filepath.Join(s.Dir, "cursor-"+strings.Trim(nonName.ReplaceAllString(sinkName, "_"), "_")+".json")
}

var nonName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// ListSegments lists a spool directory's segments in offset order.
func ListSegments(dir string) []Segment {
	ents, _ := os.ReadDir(dir)
	var out []Segment
	for _, e := range ents {
		m := segName.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		var base int64
		fmt.Sscanf(m[1], "%d", &base)
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Segment{Base: base, Size: info.Size(), Path: filepath.Join(dir, e.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Base < out[j].Base })
	return out
}

// readSpool reads up to one batch of COMPLETE lines starting at global offset off. Segments end on line boundaries,
// so a batch never spans two segments; the forwarder simply asks again from the next offset.
func readSpool(dir string, off int64, maxLines, maxBytes int) (batch [][]byte, n int64, head int64, err error) {
	segs := ListSegments(dir)
	if len(segs) == 0 {
		return nil, 0, 0, nil
	}
	head = segs[len(segs)-1].End()
	var seg *Segment
	for i := range segs {
		if off >= segs[i].Base && off < segs[i].End() {
			seg = &segs[i]
			break
		}
	}
	if seg == nil {
		if off < segs[0].Base {
			return nil, 0, head, fmt.Errorf("egress: cursor at %d is before the oldest retained spool segment (%d)", off, segs[0].Base)
		}
		return nil, 0, head, nil // at the head: nothing yet
	}
	fh, err := os.Open(seg.Path)
	if err != nil {
		return nil, 0, head, err
	}
	defer fh.Close()
	if _, err := fh.Seek(off-seg.Base, io.SeekStart); err != nil {
		return nil, 0, head, err
	}
	r := bufio.NewReaderSize(fh, 1<<20)
	for len(batch) < maxLines && n < int64(maxBytes) {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break
		}
		n += int64(len(line))
		if l := bytes.TrimRight(line, "\r\n"); len(l) > 0 {
			batch = append(batch, l)
		}
	}
	return batch, n, head, nil
}

// rangeIDs reads the event ids in [from, to) of a spool: what an egress_skipped record names.
func rangeIDs(dir string, from, to int64) (first, last string, count int64) {
	for off := from; off < to; {
		batch, n, _, err := readSpool(dir, off, 1000, 8<<20)
		if err != nil || n == 0 {
			break
		}
		for _, l := range batch { // spool lines are the event plus one '\n': count exactly up to `to`
			if off >= to {
				return first, last, count
			}
			id := lastEventID([][]byte{l})
			if first == "" {
				first = id
			}
			last = id
			count++
			off += int64(len(l)) + 1
		}
	}
	return first, last, count
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LastLine is the last complete line in the spool (nil when there is none): the last event handed to delivery.
// After a crash the pipeline re-interprets every evidence record committed after it (the invariant-3 window: a batch
// is durable before it is interpreted, so a crash can fall between the two).
func LastLine(dir string) []byte {
	segs := ListSegments(dir)
	for i := len(segs) - 1; i >= 0; i-- {
		b, err := os.ReadFile(segs[i].Path)
		if err != nil || len(b) == 0 {
			continue
		}
		end := bytes.LastIndexByte(b, '\n')
		if end <= 0 {
			continue
		}
		start := bytes.LastIndexByte(b[:end], '\n') + 1
		return b[start:end]
	}
	return nil
}
