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
	case "syslog+udp", "udp":
		return nil, errors.New("egress: syslog over UDP is not offered — it cannot tell a sink that stopped accepting from one that is fine, and silent loss is what this package exists to prevent")
	}
	return nil, fmt.Errorf("egress: unknown sink %q (syslog+tcp://host:port | http(s)://url | stdout:)", raw)
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

func (h *HTTPPost) Name() string { return h.URL }
func (h *HTTPPost) Close() error { return nil }
func (h *HTTPPost) Send(batch [][]byte) error {
	body := append(bytes.Join(batch, []byte{'\n'}), '\n')
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("X-ULPF-Events", fmt.Sprint(len(batch)))
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
}

func (s *SyslogTCP) Name() string { return "syslog+tcp://" + s.Addr }
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
		msg := Frame5424(l, s.Hostname)
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
}

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
	LastError   string `json:"last_error,omitempty"`
}

type Forwarder struct {
	Spool      string
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

	mu    sync.Mutex
	cur   Cursor
	st    Stats
	prev  [][]byte // the last batch believed delivered (re-sent after a reconnect on sinks without an acknowledgement)
	stop  chan struct{}
	done  chan struct{}
	drain bool
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
	if st, err := os.Stat(f.Spool); err == nil {
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
		case <-time.After(d):
			return true
		}
	}
	for {
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
		if err := f.Sink.Send(send); err != nil {
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
