package egress

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// bulkFake answers like the _bulk API: per-document results, `index` overwrites by _id (201 created, then 200
// updated with a new _version), and scripted failures by event id.
type bulkFake struct {
	mu       sync.Mutex
	docs     map[string]int // index/_id -> _version
	actions  []string
	requests int
	status   int            // whole-request status to answer next (then reset); 0 = normal
	docFail  map[string]int // event id -> per-document status to answer (429 once, 400 always)
	maxBody  int            // > 0: 413 above this many bytes
}

func (f *bulkFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path != "/_bulk" || r.Header.Get("Content-Type") != "application/x-ndjson" {
		w.WriteHeader(400)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		f.status = 0
		return
	}
	if f.maxBody > 0 && len(body) > f.maxBody {
		w.WriteHeader(413)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var items []map[string]any
	errs := false
	for sc.Scan() {
		var a map[string]map[string]string
		json.Unmarshal(sc.Bytes(), &a)
		for act, m := range a {
			f.actions = append(f.actions, act)
			sc.Scan()
			key := m["_index"] + "/" + m["_id"]
			res := map[string]any{"_index": m["_index"], "_id": m["_id"]}
			switch st := f.docFail[m["_id"]]; st {
			case 429:
				delete(f.docFail, m["_id"])
				res["status"], res["error"] = 429, map[string]string{"type": "rejected_execution_exception", "reason": "queue full"}
				errs = true
			case 400:
				res["status"], res["error"] = 400, map[string]string{"type": "mapper_parsing_exception", "reason": "failed to parse field [src_endpoint.ip] of type [ip]"}
				errs = true
			default:
				f.docs[key]++
				res["status"], res["_version"] = 201, f.docs[key]
				if f.docs[key] > 1 {
					res["status"], res["result"] = 200, "updated"
				}
			}
			items = append(items, map[string]any{act: res})
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"took": 1, "errors": errs, "items": items})
}

func newBulkFake() *bulkFake { return &bulkFake{docs: map[string]int{}, docFail: map[string]int{}} }

func bulkSink(t *testing.T, url string) (*Bulk, *[]Reject) {
	t.Helper()
	s, err := Open("bulk+"+url, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b := s.(*Bulk)
	var rej []Reject
	b.setReject(func(r Reject) { rej = append(rej, r) })
	return b, &rej
}

func lines(n int) [][]byte {
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, bytes.TrimSpace(ev(i)))
	}
	return out
}

// `index` with _id = event_id into one index per class; a redelivered batch overwrites (a new _version), never duplicates.
func TestBulkIndexesByEventIDAndARedeliveryOverwrites(t *testing.T) {
	f := newBulkFake()
	srv := httptest.NewServer(f)
	defer srv.Close()
	b, rej := bulkSink(t, srv.URL)
	if b.Name() != "bulk+"+srv.URL {
		t.Fatal(b.Name())
	}
	for round := 0; round < 2; round++ {
		if err := b.Send(lines(5)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.docs) != 5 || f.docs["ulpf-ocsf-4001/ev_00003"] != 2 || len(*rej) != 0 {
		t.Fatalf("docs %v rejects %v", f.docs, *rej)
	}
	for _, a := range f.actions {
		if a != "index" {
			t.Fatalf("action %q: must be index (create would answer 409 on a redelivery)", a)
		}
	}
	custom, _ := Open("bulk+"+srv.URL+"?index=soc-{class_uid}", time.Second)
	custom.Send(lines(1))
	if f.docs["soc-4001/ev_00000"] != 1 {
		t.Fatalf("index template: %v", f.docs)
	}
	if _, err := Open("bulk+"+srv.URL+"?index=Bad*Name", time.Second); err == nil {
		t.Fatal("an invalid index name must be refused at start")
	}
}

// The approved classification: per-document 429 retried (those only); a mapping error rejected once and passed over;
// 413 split, a single event still too large rejected; whole-request 429/5xx and 400/401/403 are errors (retry, stall).
func TestBulkClassifiesEveryAnswer(t *testing.T) {
	f := newBulkFake()
	srv := httptest.NewServer(f)
	defer srv.Close()
	b, rej := bulkSink(t, srv.URL)

	f.docFail["ev_00001"] = 429
	f.docFail["ev_00002"] = 400
	if err := b.Send(lines(4)); err != nil {
		t.Fatal(err)
	}
	if f.docs["ulpf-ocsf-4001/ev_00001"] != 1 || f.docs["ulpf-ocsf-4001/ev_00000"] != 1 || f.requests != 2 {
		t.Fatalf("a throttled document is retried alone: docs %v requests %d", f.docs, f.requests)
	}
	if len(*rej) != 1 || (*rej)[0].EventID != "ev_00002" || (*rej)[0].Type != "mapper_parsing_exception" || !strings.Contains((*rej)[0].Reason, "400") {
		t.Fatalf("rejects %+v", *rej)
	}
	b.Send(lines(4)) // the whole batch again: the rejection is not reported twice
	if len(*rej) != 1 {
		t.Fatalf("a rejection is reported once: %+v", *rej)
	}

	f.maxBody = 300 // about two events per request
	f.requests = 0
	if err := b.Send(lines(8)); err != nil {
		t.Fatal(err)
	}
	if f.requests < 4 || f.docs["ulpf-ocsf-4001/ev_00007"] < 1 {
		t.Fatalf("413 must split: %d requests, docs %v", f.requests, f.docs)
	}
	big := []byte(fmt.Sprintf(`{"class_uid":4001,"pad":"%s","_lineage":{"event_id":"ev_big"}}`, strings.Repeat("x", 400)))
	if err := b.Send([][]byte{big}); err != nil || (*rej)[len(*rej)-1].EventID != "ev_big" || (*rej)[len(*rej)-1].Type != "request_too_large" {
		t.Fatalf("a single event too large is a rejection: %v %+v", err, *rej)
	}
	f.maxBody = 0

	for _, st := range []int{429, 503, 400, 401, 403} {
		f.status = st
		n := len(*rej)
		if err := b.Send(lines(1)); err == nil || len(*rej) != n {
			t.Fatalf("whole-request %d must be an error (retry / stall), never a rejection: err=%v", st, err)
		}
	}
	b.Attempts = 2
	f.docFail["ev_00000"] = 429
	b.Attempts = 1
	if err := b.Send(lines(1)); err == nil {
		t.Fatal("a document still throttled after the attempts is an error: the forwarder retries the batch")
	}
}
