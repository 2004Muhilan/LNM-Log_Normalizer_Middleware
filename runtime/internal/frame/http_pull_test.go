package frame

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// HTTP receive: newline bodies are framed, an array body is one frame for the pipeline to de-batch, a
// body over the cap is read only up to the cap, framed, flagged and answered 413 with what was kept.
func TestHTTPReceiveBoundedBodies(t *testing.T) {
	var mu sync.Mutex
	var got []Frame
	h := &HTTP{Addr: "127.0.0.1:0", MaxBodyBytes: 200, MaxEventBytes: 4096, MaxConcurrent: 4}
	ln, err := h.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = h.Serve(ctx, ln, func(fr Frame) error { mu.Lock(); got = append(got, fr); mu.Unlock(); return nil })
	}()
	url := "http://" + ln.Addr().String() + "/ingest"
	post := func(body string) (int, string) {
		resp, err := http.Post(url, "text/plain", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := post("<13>Jan  5 04:05:06 h app: one\n<13>Jan  5 04:05:06 h app: two\n"); code != 202 || !strings.Contains(body, `"frames":2`) {
		t.Fatalf("newline body: %d %s", code, body)
	}
	if code, body := post(`[{"a":1},{"a":2}]`); code != 202 || !strings.Contains(body, `"frames":1`) {
		t.Fatalf("array body: %d %s", code, body)
	}
	over := strings.Repeat("z", 150) + "\n" + strings.Repeat("w", 150) + "\n"
	if code, body := post(over); code != 413 || !strings.Contains(body, `"retained_bytes":200`) {
		t.Fatalf("over cap: %d %s", code, body)
	}
	if resp, _ := http.Get(url); resp == nil || resp.StatusCode != 405 {
		t.Fatal("GET must be refused")
	}
	cancel()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 5 {
		t.Fatalf("frames: %d", len(got))
	}
	if string(got[2].Raw) != `[{"a":1},{"a":2}]` {
		t.Fatalf("array frame: %q", got[2].Raw)
	}
	last := got[4]
	if last.Framing.TruncationStatus != "truncated" || last.Framing.FramingConfidence != "low" || len(last.Raw) != 49 {
		t.Fatalf("over-cap tail must be flagged: %+v", last)
	}
	if h.Truncated.Load() != 1 || h.Rejected.Load() != 1 || got[0].Peer == "" {
		t.Fatalf("counters: %d %d peer=%q", h.Truncated.Load(), h.Rejected.Load(), got[0].Peer)
	}
}

// Directory drop: files are ingested in name order, batches whole, others by line; each is renamed
// .done; the file name is the peer.
func TestPullDirectoryCollector(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "b.log"), []byte("<13>Jan  5 04:05:06 h app: b1\n<13>Jan  5 04:05:06 h app: b2\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(" [{\"x\":1},{\"x\":2}]\n"), 0o644)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("no\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "c.log.done"), []byte("already\n"), 0o644)
	var got []Frame
	p := &Pull{Dir: dir, Once: true, MaxEventBytes: 4096}
	if err := p.Serve(context.Background(), func(fr Frame) error { got = append(got, fr); return nil }); err != nil {
		t.Fatal(err)
	}
	if p.Files != 2 || len(got) != 3 {
		t.Fatalf("files=%d frames=%d", p.Files, len(got))
	}
	if got[0].Peer != "a.json" || !bytes.HasPrefix(bytes.TrimSpace(got[0].Raw), []byte("[")) || got[1].Peer != "b.log" || string(got[1].Raw) != "<13>Jan  5 04:05:06 h app: b1" {
		t.Fatalf("frames: %+v", got)
	}
	for _, n := range []string{"a.json.done", "b.log.done", "c.log.done", ".hidden"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	// a second pass finds nothing new
	p2 := &Pull{Dir: dir, Once: true}
	_ = p2.Serve(context.Background(), func(Frame) error { t.Fatal("re-read"); return nil })
	_ = time.Second
}

// Group commit (invariant 3): the receiver answers 202 only after Commit returned — the request's frames are
// durable in the evidence log when the sender is told they were accepted; a failed commit answers 503.
func TestHTTPAcceptedMeansCommitted(t *testing.T) {
	var mu sync.Mutex
	emitted, committedAt := 0, -1
	fail := false
	h := &HTTP{Addr: "127.0.0.1:0", MaxEventBytes: 4096}
	h.Commit = func() error {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return io.ErrShortWrite
		}
		committedAt = emitted
		return nil
	}
	ln, err := h.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = h.Serve(ctx, ln, func(fr Frame) error { mu.Lock(); emitted++; mu.Unlock(); return nil })
	}()
	url := "http://" + ln.Addr().String() + "/ingest"
	resp, err := http.Post(url, "text/plain", strings.NewReader("a\nb\nc\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	if resp.StatusCode != 202 || committedAt != 3 {
		t.Fatalf("202 must follow the commit of all 3 frames: status %d, committed after %d", resp.StatusCode, committedAt)
	}
	fail = true
	mu.Unlock()
	resp, err = http.Post(url, "text/plain", strings.NewReader("d\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("a failed commit must not be answered 202: %d", resp.StatusCode)
	}
	cancel()
	wg.Wait()
}
