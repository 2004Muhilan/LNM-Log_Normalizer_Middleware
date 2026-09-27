package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"ulpf/runtime/internal/egress"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
)

// Nothing ACCEPTED is lost across a crash: the process dies after its second batch is committed to the evidence log
// (frames 5–8 durable) and before any of it is interpreted. The restart, on the same evidence and spool, interprets
// exactly those four frames — original event ids, nothing twice — before it takes anything new, and says so in one
// `interpretation_recovered` record.
func TestRestartInterpretsWhatWasCommittedButNotInterpreted(t *testing.T) {
	if os.Getenv("ULPF_RECOVER_HELPER") == "1" {
		return
	}
	ev, sp := t.TempDir(), t.TempDir()
	dead := "syslog+tcp://" + deadAddr(t) // no destination accepts: the spool keeps every line
	cmd := exec.Command(os.Args[0], "-test.run=TestRecoverHelper")
	cmd.Env = append(os.Environ(), "ULPF_RECOVER_HELPER=1", "ULPF_RECOVER_EV="+ev, "ULPF_RECOVER_SPOOL="+sp, "ULPF_RECOVER_SINK="+dead)
	var ee *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &ee) || ee.ExitCode() != 137 {
		t.Fatalf("the helper should have died with 137: %v", err)
	}
	spooled := func() []string {
		var ids []string
		for _, sg := range egress.ListSegments(sp) {
			b, _ := os.ReadFile(sg.Path)
			for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
				if len(l) == 0 {
					continue
				}
				var e struct {
					L struct {
						ID string `json:"event_id"`
					} `json:"_lineage"`
				}
				json.Unmarshal(l, &e)
				ids = append(ids, e.L.ID)
			}
		}
		return ids
	}
	before := spooled()
	if len(before) != 4 {
		t.Fatalf("the first batch (4 frames) was interpreted and spooled before the crash: %d", len(before))
	}
	o := spoolOpts(t, ev, sp, dead)
	o.EgressDrain = 100 * 1e6
	st, err := RunFrames(func(emit func(frame.Frame) error) error { return nil }, o)
	if err != nil {
		t.Fatal(err)
	}
	after := spooled()
	var committed []string
	for _, seg := range evidence.Segments(ev) {
		recs, _ := evidence.ReadIndex(ev, seg)
		for _, r := range recs {
			if r.Framing.Method != evidence.MethodGapRecord {
				committed = append(committed, r.EventID)
			}
		}
	}
	if st.Recovered != 4 || len(after) != 8 || len(committed) != 8 {
		t.Fatalf("recovered %d, spooled %d, committed %d — want 4, 8, 8", st.Recovered, len(after), len(committed))
	}
	seen := map[string]bool{}
	for i, id := range after {
		if seen[id] || id != committed[i] {
			t.Fatalf("spool[%d] = %s, evidence[%d] = %s (duplicate: %v)", i, id, i, committed[i], seen[id])
		}
		seen[id] = true
	}
	if st.GapKinds["interpretation_recovered"] != 1 {
		t.Fatalf("the recovery is an evidence record: %v", st.GapKinds)
	}
	// and a clean restart recovers nothing
	st2, err := RunFrames(func(emit func(frame.Frame) error) error { return nil }, o)
	if err != nil || st2.Recovered != 0 || len(spooled()) != 8 {
		t.Fatalf("a second restart must recover nothing: %d %v", st2.Recovered, err)
	}
}

func TestRecoverHelper(t *testing.T) {
	if os.Getenv("ULPF_RECOVER_HELPER") != "1" {
		t.Skip("helper process only")
	}
	in, _ := os.ReadFile(filepath.Join(loadGoldenPack(t).Dir, "samples", "access.log"))
	var lines [][]byte // every line with its own terminator (the sample file's last line has none)
	for _, l := range bytes.Split(bytes.TrimRight(in, "\n"), []byte("\n")) {
		lines = append(lines, append(append([]byte{}, l...), '\n'))
	}
	o := spoolOpts(t, os.Getenv("ULPF_RECOVER_EV"), os.Getenv("ULPF_RECOVER_SPOOL"), os.Getenv("ULPF_RECOVER_SINK"))
	o.CommitEvents, o.CommitWait, o.FailAfterRawWrite = 4, 3600*1e9, 6
	_, _ = Run(bytes.NewReader(bytes.Join(append(lines, lines[:2]...), nil)), o)
	t.Fatal("Run returned; the kill hook did not fire")
}
