package frame

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Pull is the directory-drop collector (plan P7): files dropped into Dir are ingested in name order
// and renamed with DoneSuffix afterwards (the drop directory is the queue; a file is never read
// twice, and a crash between read and rename re-reads the file — duplicates are visible by raw_hash,
// loss is not possible). A file that starts with `[` is one frame holding the whole batch (bounded by
// MaxBatchBytes: a larger array is emitted in bounded pieces flagged truncated / continuation and the
// router quarantines them as evidence); any other file is newline-framed. Peer = the file name.
type Pull struct {
	Dir           string
	Interval      time.Duration
	MaxEventBytes int
	MaxBatchBytes int
	DoneSuffix    string
	Once          bool // one pass over the directory, then return (tests, canned demos)
	Multiline     *Multiline
	Files         int
	// Scale-out partitioning for directory pull (sockets have SO_REUSEPORT; a directory does not): N processes share
	// one drop directory and process Shard of Shards takes only the files whose SOURCE KEY hashes to it — the part of
	// the name before the first "_" (convention: <source>_<anything>, e.g. fw01_2026-09-27T10.log), or the whole name.
	// Every file of one source goes to one process, so per-source state stays in one place, and no two processes ever
	// read or rename the same file. Shards 0 or 1 = take every file.
	Shard, Shards int
}

// Mine reports whether this process's shard takes the file (by its source key).
func (p *Pull) Mine(base string) bool {
	if p.Shards <= 1 {
		return true
	}
	key := base
	if i := strings.Index(base, "_"); i > 0 {
		key = base[:i]
	}
	h := uint32(2166136261) // FNV-1a
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return int(h%uint32(p.Shards)) == p.Shard
}

// Serve polls Dir until ctx is done (or once).
func (p *Pull) Serve(ctx context.Context, emit func(Frame) error) error {
	interval := p.Interval
	if interval <= 0 {
		interval = time.Second
	}
	done := p.DoneSuffix
	if done == "" {
		done = ".done"
	}
	for {
		names, _ := filepath.Glob(filepath.Join(p.Dir, "*"))
		sort.Strings(names)
		for _, name := range names {
			base := filepath.Base(name)
			if strings.HasPrefix(base, ".") || strings.HasSuffix(base, done) || !p.Mine(base) {
				continue
			}
			if st, err := os.Stat(name); err != nil || st.IsDir() {
				continue
			}
			if err := p.file(name, emit); err != nil {
				return err
			}
			p.Files++
			_ = os.Rename(name, name+done)
			if ctx.Err() != nil {
				return nil
			}
		}
		if p.Once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func (p *Pull) file(name string, emit func(Frame) error) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	peer := filepath.Base(name)
	em := func(fr Frame) error {
		fr.Peer = peer
		return emit(fr)
	}
	maxBytes := p.MaxEventBytes
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	br := bufio.NewReaderSize(f, 64*1024)
	head, _ := br.Peek(64)
	if t := strings.TrimLeft(string(head), " \t\r\n"); strings.HasPrefix(t, "[") {
		maxBatch := p.MaxBatchBytes
		if maxBatch <= 0 {
			maxBatch = 8 << 20
		}
		// the whole file is one frame (the pipeline de-batches it), read through a hard cap
		buf := make([]byte, 0, 64*1024)
		chunk := make([]byte, 64*1024)
		first, status := true, "none"
		for {
			n, rerr := br.Read(chunk)
			buf = append(buf, chunk[:n]...)
			if len(buf) >= maxBatch {
				if err := em(Frame{Raw: buf[:maxBatch], Framing: Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte{}, FragmentCount: 1,
					OriginalMessageLength: len(buf[:maxBatch]), TruncationStatus: "truncated", FramingConfidence: "low"}}); err != nil {
					return err
				}
				buf = append([]byte{}, buf[maxBatch:]...)
				first, status = false, "continuation"
			}
			if rerr != nil {
				break
			}
		}
		if len(buf) > 0 || first {
			if !first {
				status = "continuation"
			}
			conf := "high"
			if !first {
				conf = "low"
			}
			return em(Frame{Raw: buf, Framing: Framing{Method: "newline", RawPrefix: []byte{}, RawSuffix: []byte{}, FragmentCount: 1,
				OriginalMessageLength: len(buf), TruncationStatus: status, FramingConfidence: conf}})
		}
		return nil
	}
	if p.Multiline != nil {
		j := p.Multiline.Joiner(em)
		if err := (Newline{MaxEventBytes: maxBytes}).Scan(br, j.Feed); err != nil {
			return err
		}
		return j.Flush()
	}
	return Newline{MaxEventBytes: maxBytes}.Scan(br, em)
}
