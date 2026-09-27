// Package egress delivers normalized events to the systems downstream of ULPF — a SIEM over syslog/TCP, a
// collector over HTTP POST, a pipe over stdout — without ever dropping one silently.
//
// Design (validated against the architecture before building; P8 report §9):
//
//   - NO CONTRACT IS TOUCHED. What leaves is the normalized-event document, byte for byte as the runtime
//     emitted it; syslog only wraps it (RFC 5424 header + RFC 6587 octet counting), HTTP only batches it (NDJSON).
//   - DELIVERY IS A CURSOR OVER A DURABLE SPOOL, not a queue in memory. The spool is the normalized JSONL the
//     runtime already writes (`--out`, the lake's version 1). A forwarder reads complete lines from its cursor,
//     sends a bounded batch, and advances the cursor only when the sink accepted the batch. Memory is one batch,
//     whatever the sink does. A crash resumes from the persisted cursor.
//   - BACKPRESSURE (architecture §4.4: "state explicitly what happens at capacity; silent drop is not acceptable").
//     Ingestion never waits for a sink: evidence is written, events are normalized and spooled at the rate they
//     arrive. When a sink stops accepting, its cursor stops, the lag grows ON DISK, nothing is dropped and nothing
//     is reordered; after StallAfter the stall is reported through OnStall — the pipeline appends an
//     `egress_stalled` gap record to the EVIDENCE LOG, a Merkle leaf like any other, so an interruption of delivery
//     is tamper-evident on the same terms as an interruption of arrival — and OnResume reports the recovery with
//     the number of events delivered late. The capacity that is finite is the disk; MaxLagBytes raises an alarm
//     (OnStall again, with the lag) and still drops nothing.
//   - AT-LEAST-ONCE. A batch whose acceptance is unknown is sent again; receivers deduplicate on event_id (present
//     in the document and, for syslog, in the structured data). HTTP has a real acknowledgement (2xx). Syslog over
//     TCP has none: bytes the peer's TCP stack accepted and the peer never processed are lost unknowably — a limit
//     of RFC 6587, not of this code — so after any connection failure the forwarder re-sends the last batch it
//     believed delivered. UDP forwarding is deliberately not offered: it cannot tell "stopped accepting" from "fine".
package egress

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sink accepts a batch of normalized-event lines (no trailing newline) or returns an error; on error the
// forwarder assumes NOTHING of the batch was accepted and sends all of it again.
type Sink interface {
	Name() string
	Send(batch [][]byte) error
	Close() error
}

// Open parses a sink URL: syslog+tcp://host:port | http(s)://... | stdout:
func Open(raw string, timeout time.Duration) (Sink, error) {
	if raw == "stdout:" || raw == "stdout" {
		return &Stdout{W: os.Stdout}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "syslog+tcp":
		host, _ := os.Hostname()
		return &SyslogTCP{Addr: u.Host, Timeout: timeout, Hostname: host}, nil
	case "http", "https":
		return &HTTPPost{URL: raw, Client: &http.Client{Timeout: timeout}}, nil
	case "bulk+http", "bulk+https":
		return newBulk(u, timeout)
	case "hec+http", "hec+https":
		return newHEC(u, timeout)
	case "cef+tcp":
		host, _ := os.Hostname()
		return &SyslogTCP{Addr: u.Host, Timeout: timeout, Hostname: host, Encode: frameCEF, Scheme: "cef+tcp"}, nil
	case "syslog+udp", "udp":
		return nil, errors.New("egress: syslog over UDP is not offered — it cannot tell a sink that stopped accepting from one that is fine, and silent loss is what this package exists to prevent")
	}
	return nil, fmt.Errorf("egress: unknown sink %q (syslog+tcp://host:port | http(s)://url | bulk+http(s)://host:port[?index=…] | hec+http(s)://host:port | cef+tcp://host:port | stdout:)", raw)
}

// ---------------------------------------------------------------- sinks

// Stdout writes one event per line. A closed pipe is an error like any other: the cursor does not advance.
type Stdout struct{ W io.Writer }

func (s *Stdout) Name() string { return "stdout:" }
func (s *Stdout) Close() error { return nil }
func (s *Stdout) Send(batch [][]byte) error {
	var b bytes.Buffer
	for _, l := range batch {
		b.Write(l)
		b.WriteByte('\n')
	}
	_, err := s.W.Write(b.Bytes())
	return err
}

// HTTPPost sends a batch as application/x-ndjson; any 2xx acknowledges the whole batch.
type HTTPPost struct {
	URL    string
	Client *http.Client
}

func (h *HTTPPost) Name() string              { return h.URL }
func (h *HTTPPost) Close() error              { return nil }
func (h *HTTPPost) Send(batch [][]byte) error { return h.SendRange(batch, SpoolRange{}) }

// SendRange is Send with the batch's place in the spool: X-ULPF-Spool-Id / -Start / -End (global byte offsets, the
// batch is exactly the complete lines of [Start, End)). A receiver that must not store a redelivered event twice (the
// lake writer) keeps a durable high-water mark on it. Sent only when the forwarder reads a segmented spool.
func (h *HTTPPost) SendRange(batch [][]byte, r SpoolRange) error {
	body := append(bytes.Join(batch, []byte{'\n'}), '\n')
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("X-ULPF-Events", fmt.Sprint(len(batch)))
	if r.SpoolID != "" {
		req.Header.Set("X-ULPF-Spool-Id", r.SpoolID)
		req.Header.Set("X-ULPF-Spool-Start", fmt.Sprint(r.Start))
		req.Header.Set("X-ULPF-Spool-End", fmt.Sprint(r.End))
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("collector answered %s", resp.Status)
	}
	return nil
}

// SyslogTCP forwards each event as one RFC 5424 message, octet-counted (RFC 6587), on a persistent connection.
// PRI 134 = local0.info; the enterprise number in the structured-data id is 32473, the one RFC 5612 reserves for
// examples — a deployment substitutes its own.
type SyslogTCP struct {
	Addr     string
	Timeout  time.Duration
	Hostname string
	conn     net.Conn
	// Reconnected is set when Send had to dial again after a failure: the forwarder re-sends the previous batch.
	Reconnected bool
	// Encode frames one event (default Frame5424: the OCSF JSON as MSG); frameCEF projects it onto CEF instead.
	Encode func(event []byte, hostname string) []byte
	Scheme string // default syslog+tcp
}

func (s *SyslogTCP) Name() string {
	if s.Scheme != "" {
		return s.Scheme + "://" + s.Addr
	}
	return "syslog+tcp://" + s.Addr
}
func (s *SyslogTCP) Close() error {
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *SyslogTCP) alive() bool {
	// a peer that closed shows up as EOF on read; syslog receivers send nothing, so any data or a timeout means alive
	s.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	var one [1]byte
	_, err := s.conn.Read(one[:])
	s.conn.SetReadDeadline(time.Time{})
	if err == nil {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (s *SyslogTCP) Send(batch [][]byte) error {
	if s.conn != nil && !s.alive() {
		s.Close()
	}
	if s.conn == nil {
		c, err := net.DialTimeout("tcp", s.Addr, s.Timeout)
		if err != nil {
			return err
		}
		s.conn, s.Reconnected = c, true
	}
	var b bytes.Buffer
	for _, l := range batch {
		enc := s.Encode
		if enc == nil {
			enc = Frame5424
		}
		msg := enc(l, s.Hostname)
		fmt.Fprintf(&b, "%d ", len(msg))
		b.Write(msg)
	}
	s.conn.SetWriteDeadline(time.Now().Add(s.Timeout)) // a sink that stops READING fills the window: the write times out, it does not hang
	if _, err := s.conn.Write(b.Bytes()); err != nil {
		s.Close()
		return err
	}
	return nil
}

// Frame5424 wraps one normalized event: header, structured data carrying the event's identity, the JSON as MSG.
func Frame5424(event []byte, hostname string) []byte {
	var probe struct {
		ClassUID int   `json:"class_uid"`
		Time     int64 `json:"time"`
		L        struct {
			EventID string `json:"event_id"`
			RawHash string `json:"raw_hash"`
		} `json:"_lineage"`
	}
	_ = json.Unmarshal(event, &probe)
	ts := "-"
	if probe.Time > 0 {
		ts = time.UnixMilli(probe.Time).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if hostname == "" {
		hostname = "-"
	}
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	sd := fmt.Sprintf(`[ulpf@32473 event_id="%s" raw_hash="%s" class_uid="%d"]`, esc.Replace(probe.L.EventID), esc.Replace(probe.L.RawHash), probe.ClassUID)
	return []byte(fmt.Sprintf("<134>1 %s %s ulpf - ocsf %s %s", ts, hostname, sd, event))
}

// ---------------------------------------------------------------- forwarder

// Cursor is what survives a restart.
type Cursor struct {
	Spool       string `json:"spool"`
	Offset      int64  `json:"offset"` // bytes of the spool delivered and acknowledged
	Delivered   int64  `json:"delivered_events"`
	LastEventID string `json:"last_event_id,omitempty"`
	Sink        string `json:"sink"`
	// segmented spool only
	SpoolID    string `json:"spool_id,omitempty"`
	PrevOffset int64  `json:"prev_offset,omitempty"` // where the last acknowledged batch began: a sink without acknowledgement gets it again after a restart
	Skipped    int64  `json:"skipped_events,omitempty"`
	Rejected   int64  `json:"rejected_events,omitempty"`
}

// SpoolRange locates a batch in a segmented spool.
type SpoolRange struct {
	SpoolID    string
	Start, End int64
}

// RangedSink receives each batch with its place in the spool.
type RangedSink interface {
	SendRange(batch [][]byte, r SpoolRange) error
}

// Skip is a range of the spool a destination will never receive from it: the spool cap was reached while the
// destination was the slowest. The pipeline commits it as an `egress_skipped` evidence record.
type Skip struct {
	Sink            string
	From, To        int64 // global spool offsets
	FirstID, LastID string
	Count           int64 // -1: the range had already been removed (the cursor was older than the retained spool)
}

// Reject is one event a destination refused permanently (a document-level mapping or parse error, or a single event
// larger than the destination accepts). The forwarder moves past it; the pipeline commits an `egress_rejected` record.
type Reject struct {
	Sink    string
	EventID string
	Type    string
	Reason  string
}

// rejecter is implemented by sinks that can refuse single events inside an accepted batch.
type rejecter interface{ setReject(func(Reject)) }

// Stall describes an interruption of delivery (OnStall) or its end (OnResume).
type Stall struct {
	Sink        string
	Since       time.Time
	Duration    time.Duration
	LastEventID string // last event the sink acknowledged
	LagBytes    int64
	LagEvents   int64 // on resume: events delivered late
	Err         string
}

type Stats struct {
	Sink        string `json:"sink"`
	Delivered   int64  `json:"delivered_events"`
	Batches     int64  `json:"batches"`
	Retries     int64  `json:"retries"`
	Resent      int64  `json:"resent_events"` // at-least-once: events sent again after a connection failure
	Stalls      int64  `json:"stalls"`
	Undelivered int64  `json:"undelivered_bytes"`
	Skipped     int64  `json:"skipped_events,omitempty"`
	Rejected    int64  `json:"rejected_events,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type Forwarder struct {
	Spool      string // the single-file spool (--out), or empty with Seg
	Seg        *Spool // the segmented spool (--spool DIR); CursorPath defaults to Seg.CursorPath(sink name)
	CursorPath string
	Sink       Sink
	BatchLines int           // default 100
	BatchBytes int           // default 256 KiB
	Poll       time.Duration // default 200 ms
	StallAfter time.Duration // default 3 s
	MaxBackoff time.Duration // default 5 s
	MaxLagByte int64         // 0 = no alarm
	OnStall    func(Stall)
	OnResume   func(Stall)
	OnSkip     func(Skip)
	OnReject   func(Reject)

	skipTo atomic.Int64  // set by the retention manager: move the cursor to at least this offset
	wake   chan struct{} // a skip request interrupts a backoff sleep
	mu     sync.Mutex
	cur    Cursor
	st     Stats
	prev   [][]byte // the last batch believed delivered (re-sent after a reconnect on sinks without an acknowledgement)
	stop   chan struct{}
	done   chan struct{}
	drain  bool
}

func (f *Forwarder) defaults() {
	if f.BatchLines == 0 {
		f.BatchLines = 100
	}
	if f.BatchBytes == 0 {
		f.BatchBytes = 256 << 10
	}
	if f.Poll == 0 {
		f.Poll = 200 * time.Millisecond
	}
	if f.StallAfter == 0 {
		f.StallAfter = 3 * time.Second
	}
	if f.MaxBackoff == 0 {
		f.MaxBackoff = 5 * time.Second
	}
}

// Start loads the cursor (Reset discards it: the caller has just truncated the spool) and begins forwarding.
func (f *Forwarder) Start(reset bool) error {
	f.defaults()
	if r, ok := f.Sink.(rejecter); ok {
		r.setReject(func(x Reject) {
			x.Sink = f.Sink.Name()
			f.mu.Lock()
			f.st.Rejected++
			f.cur.Rejected++
			f.mu.Unlock()
			if f.OnReject != nil {
				f.OnReject(x)
			}
		})
	}
	f.wake = make(chan struct{}, 1)
	if f.Seg != nil {
		return f.startSegmented(reset)
	}
	f.cur = Cursor{Spool: f.Spool, Sink: f.Sink.Name()}
	if !reset {
		if b, err := os.ReadFile(f.CursorPath); err == nil {
			var c Cursor
			if json.Unmarshal(b, &c) == nil && c.Sink == f.Sink.Name() {
				f.cur = c
				f.cur.Spool = f.Spool
			}
		}
	}
	if st, err := os.Stat(f.Spool); err == nil && f.cur.Offset > st.Size() {
		return fmt.Errorf("egress: cursor for %s is at byte %d but the spool holds %d: the spool was replaced — refusing to guess what was delivered", f.Sink.Name(), f.cur.Offset, st.Size())
	}
	f.st.Sink, f.st.Delivered = f.Sink.Name(), f.cur.Delivered
	f.stop, f.done = make(chan struct{}), make(chan struct{})
	go f.loop()
	return nil
}

// startSegmented resumes from the destination's cursor in a segmented spool (reset only with a fresh spool). A cursor
// from another spool, or none, starts at the oldest retained segment: a new destination receives what is retained.
func (f *Forwarder) startSegmented(reset bool) error {
	if f.CursorPath == "" {
		f.CursorPath = f.Seg.CursorPath(f.Sink.Name())
	}
	segs := ListSegments(f.Seg.Dir)
	oldest := int64(0)
	if len(segs) > 0 {
		oldest = segs[0].Base
	}
	f.cur = Cursor{Spool: f.Seg.Dir, Sink: f.Sink.Name(), SpoolID: f.Seg.ID, Offset: oldest, PrevOffset: oldest}
	if !reset {
		if b, err := os.ReadFile(f.CursorPath); err == nil {
			var c Cursor
			if json.Unmarshal(b, &c) == nil && c.Sink == f.Sink.Name() && c.SpoolID == f.Seg.ID {
				f.cur = c
				f.cur.Spool = f.Seg.Dir
			}
		}
	}
	if head := f.Seg.Head(); f.cur.Offset > head {
		return fmt.Errorf("egress: cursor for %s is at %d but the spool ends at %d — refusing to guess what was delivered", f.Sink.Name(), f.cur.Offset, head)
	}
	if f.cur.Offset < oldest { // the range this destination still needed is already gone: say so, then continue from what is retained
		f.skipTo.Store(oldest)
	}
	if _, noAck := f.Sink.(*SyslogTCP); noAck && f.cur.PrevOffset < f.cur.Offset && f.cur.PrevOffset >= oldest {
		// syslog has no acknowledgement: the last batch the previous run believed delivered may never have been
		// processed. Load it; the first send after the (re)connect carries it again (at most a redelivery, never a loss).
		if prev, _, _, err := readSpool(f.Seg.Dir, f.cur.PrevOffset, 1<<30, int(f.cur.Offset-f.cur.PrevOffset)); err == nil {
			f.prev = prev
		}
	}
	f.st.Sink, f.st.Delivered, f.st.Skipped, f.st.Rejected = f.Sink.Name(), f.cur.Delivered, f.cur.Skipped, f.cur.Rejected
	f.stop, f.done = make(chan struct{}), make(chan struct{})
	go f.loop()
	return nil
}

// Offset is the destination's acknowledged position (for the retention manager and the UI).
func (f *Forwarder) Offset() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur.Offset
}

// Cursor returns a copy of the destination's cursor.
func (f *Forwarder) Cursor() Cursor {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

// RequestSkip asks the forwarder to move past everything before `to` (the spool cap was reached). The forwarder does
// it between two batches, reports it through OnSkip, and never skips what it has already been acknowledged for.
func (f *Forwarder) RequestSkip(to int64) {
	for {
		cur := f.skipTo.Load()
		if to <= cur {
			return
		}
		if f.skipTo.CompareAndSwap(cur, to) {
			select {
			case f.wake <- struct{}{}:
			default:
			}
			return
		}
	}
}

func (f *Forwarder) applySkip() {
	to := f.skipTo.Load()
	if f.Seg == nil || to <= f.cur.Offset {
		return
	}
	sk := Skip{Sink: f.Sink.Name(), From: f.cur.Offset, To: to, Count: -1}
	if segs := ListSegments(f.Seg.Dir); len(segs) > 0 && f.cur.Offset >= segs[0].Base {
		sk.FirstID, sk.LastID, sk.Count = rangeIDs(f.Seg.Dir, f.cur.Offset, to)
	}
	f.mu.Lock()
	f.cur.Offset, f.cur.PrevOffset = to, to
	if sk.Count > 0 {
		f.cur.Skipped += sk.Count
		f.st.Skipped += sk.Count
	}
	f.saveCursor()
	f.mu.Unlock()
	f.prev = nil
	if f.OnSkip != nil {
		f.OnSkip(sk)
	}
}

// Drain asks the forwarder to stop once the spool is fully delivered, or after timeout; it returns the stats.
func (f *Forwarder) Drain(timeout time.Duration) Stats {
	f.mu.Lock()
	f.drain = true
	f.mu.Unlock()
	select {
	case <-f.done:
	case <-time.After(timeout):
		close(f.stop)
		<-f.done
	}
	f.Sink.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Seg != nil {
		f.st.Undelivered = f.Seg.Head() - f.cur.Offset
	} else if st, err := os.Stat(f.Spool); err == nil {
		f.st.Undelivered = st.Size() - f.cur.Offset
	}
	return f.st
}

func (f *Forwarder) saveCursor() {
	b, _ := json.MarshalIndent(f.cur, "", " ")
	tmp := f.CursorPath + ".tmp"
	if os.WriteFile(tmp, append(b, '\n'), 0o644) == nil {
		os.Rename(tmp, f.CursorPath)
	}
}

// next reads up to one batch of COMPLETE lines from the cursor; a partial last line is left for later.
func (f *Forwarder) next() (batch [][]byte, n int64, lag int64, err error) {
	if f.Seg != nil {
		batch, n, head, err := readSpool(f.Seg.Dir, f.cur.Offset, f.BatchLines, f.BatchBytes)
		return batch, n, head - f.cur.Offset, err
	}
	fh, err := os.Open(f.Spool)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, 0, nil
		}
		return nil, 0, 0, err
	}
	defer fh.Close()
	st, _ := fh.Stat()
	lag = st.Size() - f.cur.Offset
	if _, err := fh.Seek(f.cur.Offset, io.SeekStart); err != nil {
		return nil, 0, lag, err
	}
	r := bufio.NewReaderSize(fh, 1<<20)
	for len(batch) < f.BatchLines && n < int64(f.BatchBytes) {
		line, err := r.ReadBytes('\n')
		if err != nil { // EOF mid-line: the writer has not finished it
			break
		}
		n += int64(len(line))
		if l := bytes.TrimRight(line, "\r\n"); len(l) > 0 {
			batch = append(batch, l)
		}
	}
	return batch, n, lag, nil
}

func lastEventID(batch [][]byte) string {
	var probe struct {
		L struct {
			EventID string `json:"event_id"`
		} `json:"_lineage"`
	}
	if len(batch) > 0 && json.Unmarshal(batch[len(batch)-1], &probe) == nil {
		return probe.L.EventID
	}
	return ""
}

func (f *Forwarder) loop() {
	defer close(f.done)
	backoff := 100 * time.Millisecond
	var failingSince time.Time
	stalled, alarmed := false, false
	var lateEvents int64
	sleep := func(d time.Duration) bool {
		select {
		case <-f.stop:
			return false
		case <-f.wake:
			return true
		case <-time.After(d):
			return true
		}
	}
	for {
		f.applySkip()
		start := f.cur.Offset
		batch, n, lag, err := f.next()
		if err != nil {
			f.mu.Lock()
			f.st.LastError = err.Error()
			f.mu.Unlock()
		}
		if f.MaxLagByte > 0 && lag > f.MaxLagByte && !alarmed && f.OnStall != nil {
			alarmed = true
			f.OnStall(Stall{Sink: f.Sink.Name(), Since: time.Now(), LastEventID: f.cur.LastEventID, LagBytes: lag, Err: fmt.Sprintf("delivery lag %d bytes exceeds the alarm threshold %d; nothing is dropped", lag, f.MaxLagByte)})
		}
		if len(batch) == 0 {
			f.mu.Lock()
			d := f.drain
			f.mu.Unlock()
			if d && n == 0 {
				return
			}
			if !sleep(f.Poll) {
				return
			}
			continue
		}
		send := batch
		if s, ok := f.Sink.(*SyslogTCP); ok && s.conn == nil && len(f.prev) > 0 {
			// no acknowledgement in RFC 6587: what the dead connection had accepted may never have been processed
			send = append(append([][]byte{}, f.prev...), batch...)
		}
		var serr error
		if rs, ok := f.Sink.(RangedSink); ok && f.Seg != nil && len(send) == len(batch) {
			serr = rs.SendRange(send, SpoolRange{SpoolID: f.Seg.ID, Start: start, End: start + n})
		} else {
			serr = f.Sink.Send(send)
		}
		if err := serr; err != nil {
			f.mu.Lock()
			f.st.Retries++
			f.st.LastError = err.Error()
			f.mu.Unlock()
			if failingSince.IsZero() {
				failingSince = time.Now()
			}
			if !stalled && time.Since(failingSince) >= f.StallAfter {
				stalled = true
				f.mu.Lock()
				f.st.Stalls++
				f.mu.Unlock()
				if f.OnStall != nil {
					f.OnStall(Stall{Sink: f.Sink.Name(), Since: failingSince, Duration: time.Since(failingSince), LastEventID: f.cur.LastEventID, LagBytes: lag, Err: err.Error()})
				}
			}
			if !sleep(backoff) {
				return
			}
			if backoff *= 2; backoff > f.MaxBackoff {
				backoff = f.MaxBackoff
			}
			continue
		}
		f.mu.Lock()
		if len(send) > len(batch) {
			f.st.Resent += int64(len(send) - len(batch))
		}
		f.cur.PrevOffset = start
		f.cur.Offset += n
		f.cur.Delivered += int64(len(batch))
		f.cur.LastEventID = lastEventID(batch)
		f.st.Delivered, f.st.Batches, f.st.LastError = f.cur.Delivered, f.st.Batches+1, ""
		f.saveCursor()
		f.mu.Unlock()
		f.prev = batch
		if !failingSince.IsZero() {
			lateEvents += int64(len(batch))
		}
		if stalled && lag-n <= 0 { // caught up: the interruption is over
			if f.OnResume != nil {
				f.OnResume(Stall{Sink: f.Sink.Name(), Since: failingSince, Duration: time.Since(failingSince), LastEventID: f.cur.LastEventID, LagEvents: lateEvents})
			}
			stalled, alarmed = false, false
		}
		if lag-n <= 0 {
			failingSince, lateEvents = time.Time{}, 0
		}
		backoff = 100 * time.Millisecond
	}
}
