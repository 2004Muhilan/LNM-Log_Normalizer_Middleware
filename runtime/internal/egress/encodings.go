package egress

// Two small envelope adapters (laptop branch, 2026-09-27), so that "syslog SIEMs and Splunk connect too" is a tested
// statement — tested against fake receivers, NOT against a live Splunk or a live CEF SIEM:
//
//	--forward 'hec+http://splunk:8088'      Splunk HTTP Event Collector: {"time","sourcetype","source","event"} per event,
//	                                        token from $ULPF_HEC_TOKEN (never on the command line)
//	--forward 'cef+tcp://siem:514'          CEF over syslog (RFC 5424 header, RFC 6587 octet counting)
//
// OCSF stays the internal format; both are projections of it at the edge. HEC carries the whole event. CEF is LOSSY by
// construction — a fixed header and a handful of extension keys (below); what does not fit is not sent — and it keeps
// the traceability keys: externalId = event_id, cs1 = raw_hash.
//
// HEC answers per request, not per event: 2xx acknowledges the batch; 429 and 5xx (503 "server is busy") are retried; any
// other status (400 invalid data, 401/403 token) is an error — a stall, never a silent rejection, because HEC does not
// say which event it refused.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------- Splunk HEC

type HEC struct {
	Base   string
	Token  string
	Client *http.Client
}

func newHEC(u *url.URL, timeout time.Duration) (*HEC, error) {
	tok := os.Getenv("ULPF_HEC_TOKEN")
	if tok == "" {
		return nil, errors.New("egress: hec+ needs the collector token in $ULPF_HEC_TOKEN (not on the command line)")
	}
	return &HEC{Base: strings.TrimPrefix(u.Scheme, "hec+") + "://" + u.Host, Token: tok, Client: &http.Client{Timeout: timeout}}, nil
}

func (h *HEC) Name() string { return "hec+" + h.Base }
func (h *HEC) Close() error { return nil }

func (h *HEC) Send(batch [][]byte) error {
	var body bytes.Buffer
	for _, l := range batch {
		var p struct {
			ClassUID int64 `json:"class_uid"`
			Time     int64 `json:"time"`
		}
		if err := json.Unmarshal(l, &p); err != nil {
			return fmt.Errorf("hec: a spool line is not JSON: %v", err)
		}
		env := map[string]any{"sourcetype": fmt.Sprintf("ocsf:%d", p.ClassUID), "source": "ulpf", "event": json.RawMessage(l)}
		if p.Time > 0 {
			env["time"] = float64(p.Time) / 1000
		}
		b, _ := json.Marshal(env)
		body.Write(b)
		body.WriteByte('\n')
	}
	req, err := http.NewRequest(http.MethodPost, h.Base+"/services/collector/event", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+h.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("hec: collector answered %s: %s", resp.Status, snippet(rb))
	}
	return nil
}

// ---------------------------------------------------------------- CEF

var actionNames = map[int64]string{0: "unknown", 1: "allowed", 2: "denied", 99: "other"}

func cefHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ").Replace(s)
}

func cefValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// CEF projects one normalized event onto a CEF record: CEF:0|ULPF|ULPF|1.0|<class_uid>|<class>/<activity>|<severity>|ext.
func CEF(event []byte) ([]byte, error) {
	var e struct {
		ClassUID   int64  `json:"class_uid"`
		ClassName  string `json:"class_name"`
		ActivityID int64  `json:"activity_id"`
		SeverityID *int64 `json:"severity_id"`
		Time       int64  `json:"time"`
		ActionID   *int64 `json:"action_id"`
		Src        struct {
			IP   string `json:"ip"`
			Port *int64 `json:"port"`
		} `json:"src_endpoint"`
		Dst struct {
			IP   string `json:"ip"`
			Port *int64 `json:"port"`
		} `json:"dst_endpoint"`
		Conn struct {
			Proto string `json:"protocol_name"`
		} `json:"connection_info"`
		Traffic struct {
			In  *int64 `json:"bytes_in"`
			Out *int64 `json:"bytes_out"`
		} `json:"traffic"`
		L struct {
			EventID  string `json:"event_id"`
			RawHash  string `json:"raw_hash"`
			SourceID string `json:"source_id"`
		} `json:"_lineage"`
	}
	if err := json.Unmarshal(event, &e); err != nil {
		return nil, fmt.Errorf("cef: not a normalized event: %v", err)
	}
	sev := int64(3)
	if e.SeverityID != nil && *e.SeverityID >= 0 {
		sev = *e.SeverityID * 2 // OCSF 0..6 onto CEF 0..10 (capped)
		if sev > 10 {
			sev = 10
		}
	}
	name := e.ClassName
	if name == "" {
		name = fmt.Sprintf("ocsf class %d", e.ClassUID)
	}
	var ext []string
	add := func(k, v string) {
		if v != "" {
			ext = append(ext, k+"="+cefValue(v))
		}
	}
	num := func(p *int64) string {
		if p == nil {
			return ""
		}
		return fmt.Sprint(*p)
	}
	if e.Time > 0 {
		add("rt", fmt.Sprint(e.Time))
	}
	add("src", e.Src.IP)
	add("spt", num(e.Src.Port))
	add("dst", e.Dst.IP)
	add("dpt", num(e.Dst.Port))
	add("proto", e.Conn.Proto)
	if e.ActionID != nil {
		add("act", actionNames[*e.ActionID])
	}
	add("in", num(e.Traffic.In))
	add("out", num(e.Traffic.Out))
	add("externalId", e.L.EventID)
	add("cs1Label", "ulpf_raw_hash")
	add("cs1", e.L.RawHash)
	add("cs2Label", "ulpf_source_id")
	add("cs2", e.L.SourceID)
	return []byte(fmt.Sprintf("CEF:0|ULPF|ULPF|1.0|%d|%s|%d|%s", e.ClassUID, cefHeader(fmt.Sprintf("%s/%d", name, e.ActivityID)), sev, strings.Join(ext, " "))), nil
}

// frameCEF wraps a CEF record in an RFC 5424 header (APP-NAME ulpf, MSGID cef, no structured data).
func frameCEF(event []byte, hostname string) []byte {
	c, err := CEF(event)
	if err != nil {
		c = []byte("CEF:0|ULPF|ULPF|1.0|0|unencodable event|5|msg=" + cefValue(err.Error()))
	}
	if hostname == "" {
		hostname = "-"
	}
	return []byte(fmt.Sprintf("<134>1 %s %s ulpf - cef - %s", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), hostname, c))
}
