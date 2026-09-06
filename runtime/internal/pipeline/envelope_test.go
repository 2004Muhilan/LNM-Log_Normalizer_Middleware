package pipeline

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
)

// Syslog-wrapped Squid lines: the evidence keeps every received byte (header included), the parser
// sees the payload, lineage carries the envelope, and reconstruction returns the wrapped stream.
func TestSyslogEnvelopeUnwrappedAfterRawWrite(t *testing.T) {
	p := loadGoldenPack(t)
	in, err := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	var wrapped bytes.Buffer
	for i, l := range bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n")) {
		if i%2 == 0 {
			wrapped.WriteString("<134>Dec 19 00:00:0" + string(rune('0'+i)) + " proxy01 squid[1234]: ")
		} else {
			wrapped.WriteString("<134>1 2024-12-19T00:00:00Z proxy01 squid 1234 - - ")
		}
		wrapped.Write(l)
		wrapped.WriteString("\n")
	}
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	st, err := Run(bytes.NewReader(wrapped.Bytes()), o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frames != 6 || st.Emitted != 6 || st.Quarantined != 0 || st.Enveloped != 6 {
		t.Fatalf("stats: %+v\n%s", st, q.String())
	}
	for i, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		lin := ev["_lineage"].(map[string]any)
		envl, ok := lin["envelope"].(map[string]any)
		if !ok {
			t.Fatalf("line %d: no envelope in lineage", i)
		}
		want := "rfc3164"
		if i%2 == 1 {
			want = "rfc5424"
		}
		if envl["kind"] != want || envl["hostname"] != "proxy01" || envl["app_name"] != "squid" || envl["proc_id"] != "1234" {
			t.Fatalf("line %d: envelope %v", i, envl)
		}
		if envl["payload_offset"].(float64) <= 0 {
			t.Fatalf("line %d: payload offset must skip the header", i)
		}
		// the parser saw the payload: the Squid client IP is where it should be
		if _, ok := ev["src_endpoint"]; !ok {
			t.Fatalf("line %d: payload not parsed", i)
		}
	}
	// evidence holds the complete received bytes, header included
	got, _, err := evidence.Reconstruct(o.EvidenceDir)
	if err != nil || !bytes.Equal(got, wrapped.Bytes()) {
		t.Fatalf("reconstruction must return the wrapped stream byte for byte (err %v)", err)
	}
}

// UDP: one datagram per frame, unwrapped and routed like any other, bounded, stops at MaxFrames.
func TestUDPDatagramsAreFramesAndEvidence(t *testing.T) {
	p := loadGoldenPack(t)
	in, err := os.ReadFile(filepath.Join(p.Dir, "samples", "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n"))
	u := frame.UDP{Addr: "127.0.0.1:0", MaxEventBytes: 65536, MaxFrames: len(lines) + 1}
	conn, err := u.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := net.Dial("udp", conn.LocalAddr().String())
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(50 * time.Millisecond)
		for _, l := range lines {
			c.Write(append([]byte("<134>Dec 19 00:00:01 proxy01 squid[1]: "), l...))
		}
		c.Write([]byte("<134>Dec 19 00:00:01 proxy01 other[2]: not a squid line at all"))
	}()
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	o.Channel = "udp:test"
	st, err := RunFrames(func(emit func(frame.Frame) error) error { return u.Serve(t.Context(), conn, emit) }, o)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frames != len(lines)+1 || st.Emitted != len(lines) || st.Quarantined != 1 || st.Enveloped != len(lines)+1 {
		t.Fatalf("stats: %+v\n%s", st, q.String())
	}
	recs, err := evidence.ReadIndex(o.EvidenceDir, "seg_00000")
	if err != nil || len(recs) != len(lines)+1 || recs[0].Framing.Method != "udp_datagram" || recs[0].Channel != "udp:test" {
		t.Fatalf("evidence records: %v %+v", err, recs)
	}
	// the quarantined datagram is evidence too: its raw bytes are in the store
	got, _, _ := evidence.Reconstruct(o.EvidenceDir)
	if !bytes.Contains(got, []byte("not a squid line at all")) {
		t.Fatal("the unroutable datagram must be retained as evidence")
	}
}
