package egress

// Bulk is an ENCODING, not a product integration: the `_bulk` NDJSON API that OpenSearch (and Elasticsearch) speak.
// Any destination that accepts it connects with no product-specific code:
//
//	--forward 'bulk+http://127.0.0.1:9200'                           one index per OCSF class: ulpf-ocsf-<class_uid>
//	--forward 'bulk+http://127.0.0.1:9200?index=soc-{class_uid}'     another naming
//
// Each event is `{"index":{"_index":…,"_id":<event_id>}}` + the normalized event, byte for byte. `index`, not `create`:
// egress is at-least-once, and a redelivered event must OVERWRITE its document (a new _version), not duplicate it and
// not fail with a 409.
//
// What an answer means (the classification approved 2026-09-27):
//   - 2xx with errors=false — every document stored.
//   - 2xx with per-document failures — 429 and 5xx documents are retried (only those, a few times, then the whole batch
//     is left to the forwarder's backoff: re-indexing the stored ones is harmless). Any other document-level failure
//     (mapping / parse errors) is PERMANENT: reported once through the reject callback — an `egress_rejected` evidence
//     record — and passed over. A rejection almost always means the index template is wrong; it is loud, not quiet.
//   - 413 — the batch is split in halves and each half sent; a single event still too large is a permanent rejection.
//   - 429 and 5xx for the whole request — an error: the forwarder backs off and retries (a stall after StallAfter).
//   - any other status (400 for the request, 401, 403, 404) — our encoding or our credentials are wrong, not the event:
//     an error, retried and reported as a stall, never a rejection.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Bulk struct {
	Base     string // scheme://host:port[/prefix]
	Index    string // template: {class_uid}
	Client   *http.Client
	onReject func(Reject)
	reported map[string]bool // event ids already reported as rejected (a whole-batch retry re-sends them)
	Attempts int             // per-document retries of 429/5xx inside one Send (default 3)
}

func newBulk(u *url.URL, timeout time.Duration) (*Bulk, error) {
	idx := u.Query().Get("index")
	if idx == "" {
		idx = "ulpf-ocsf-{class_uid}"
	}
	if strings.ContainsAny(idx, " ,\"*\\/<>|?#") || idx != strings.ToLower(idx) {
		return nil, fmt.Errorf("egress: bulk index template %q is not a valid lowercase index name", idx)
	}
	scheme := strings.TrimPrefix(u.Scheme, "bulk+")
	base := scheme + "://" + u.Host + strings.TrimSuffix(u.Path, "/")
	return &Bulk{Base: base, Index: idx, Client: &http.Client{Timeout: timeout}, reported: map[string]bool{}, Attempts: 3}, nil
}

func (b *Bulk) Name() string              { return "bulk+" + b.Base }
func (b *Bulk) Close() error              { return nil }
func (b *Bulk) setReject(fn func(Reject)) { b.onReject = fn }
func (b *Bulk) Send(batch [][]byte) error { return b.send(batch) }

type bulkProbe struct {
	ClassUID int64 `json:"class_uid"`
	L        struct {
		EventID string `json:"event_id"`
	} `json:"_lineage"`
}

func (b *Bulk) reject(id, typ, reason string) {
	if b.reported[id] {
		return
	}
	if len(b.reported) > 100000 { // bounded memory; at worst an old rejection is reported a second time
		b.reported = map[string]bool{}
	}
	b.reported[id] = true
	if b.onReject != nil {
		b.onReject(Reject{EventID: id, Type: typ, Reason: reason})
	}
}

func (b *Bulk) body(batch [][]byte) ([]byte, []string, error) {
	var buf bytes.Buffer
	ids := make([]string, len(batch))
	for i, l := range batch {
		var p bulkProbe
		if err := json.Unmarshal(l, &p); err != nil || p.L.EventID == "" {
			return nil, nil, fmt.Errorf("egress: bulk: a spool line is not a normalized event with an event_id")
		}
		ids[i] = p.L.EventID
		action, _ := json.Marshal(map[string]map[string]string{"index": {"_index": strings.ReplaceAll(b.Index, "{class_uid}", fmt.Sprint(p.ClassUID)), "_id": p.L.EventID}})
		buf.Write(action)
		buf.WriteByte('\n')
		buf.Write(l)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), ids, nil
}

type bulkResponse struct {
	Errors bool `json:"errors"`
	Items  []map[string]struct {
		ID     string `json:"_id"`
		Status int    `json:"status"`
		Error  *struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"error"`
	} `json:"items"`
}

func (b *Bulk) send(batch [][]byte) error {
	pending := batch
	for attempt := 0; ; attempt++ {
		retry, err := b.once(pending)
		if err != nil || len(retry) == 0 {
			return err
		}
		if attempt+1 >= b.Attempts {
			return fmt.Errorf("bulk: %d document(s) still throttled or failing on the server after %d attempts", len(retry), b.Attempts)
		}
		time.Sleep(time.Duration(200<<attempt) * time.Millisecond)
		pending = retry
	}
}

// once sends one request; it returns the documents to retry (per-document 429/5xx).
func (b *Bulk) once(batch [][]byte) ([][]byte, error) {
	body, ids, err := b.body(batch)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, b.Base+"/_bulk", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	switch {
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		if len(batch) == 1 {
			b.reject(ids[0], "request_too_large", fmt.Sprintf("a single event of %d bytes exceeds what the destination accepts in one request", len(body)))
			return nil, nil
		}
		h := len(batch) / 2
		if err := b.send(batch[:h]); err != nil {
			return nil, err
		}
		return nil, b.send(batch[h:])
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, fmt.Errorf("bulk: destination answered %s (retried with backoff)", resp.Status)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("bulk: destination refused the request %s: %s — the encoding or the credentials are wrong, not the event", resp.Status, snippet(rb))
	}
	var r bulkResponse
	if err := json.Unmarshal(rb, &r); err != nil {
		return nil, fmt.Errorf("bulk: 2xx without a readable bulk response: %v", err)
	}
	if len(r.Items) != len(batch) {
		return nil, fmt.Errorf("bulk: %d result(s) for %d document(s)", len(r.Items), len(batch))
	}
	if !r.Errors {
		return nil, nil
	}
	var retry [][]byte
	for i, item := range r.Items {
		for _, res := range item { // one action per item: "index"
			switch {
			case res.Status >= 200 && res.Status <= 299:
			case res.Status == http.StatusTooManyRequests || res.Status >= 500:
				retry = append(retry, batch[i])
			default:
				typ, reason := "unknown", ""
				if res.Error != nil {
					typ, reason = res.Error.Type, res.Error.Reason
				}
				b.reject(ids[i], typ, fmt.Sprintf("status %d: %s", res.Status, reason))
			}
		}
	}
	return retry, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
