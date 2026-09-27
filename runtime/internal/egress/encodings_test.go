package egress

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"ulpf/runtime/internal/frame"
)

const ocsfEvent = `{"class_uid":4001,"class_name":"Network Activity","activity_id":6,"severity_id":1,"time":1790467200123,"action_id":2,` +
	`"src_endpoint":{"ip":"10.4.1.7","port":40000},"dst_endpoint":{"ip":"203.0.113.66","port":443},"connection_info":{"protocol_name":"tcp"},` +
	`"traffic":{"bytes_in":10,"bytes_out":20},"unmapped":{"note":"a=b\\c|d"},"_lineage":{"event_id":"ev_cef1","raw_hash":"sha256:abc","source_id":"flowtap-01"}}`

// CEF is a lossy projection that keeps the traceability keys; the proof that it is well-formed CEF is that ULPF's OWN
// CEF parser (the ingress side, frame.UnwrapChain) reads it back: syslog 5424 + CEF envelope, header and extension.
func TestCEFEncodingRoundTripsThroughULPFsOwnCEFParser(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	got := make(chan []byte, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		for {
			ls, err := r.ReadString(' ')
			if err != nil {
				return
			}
			n, _ := strconv.Atoi(strings.TrimSpace(ls))
			m := make([]byte, n)
			io.ReadFull(r, m)
			got <- m
		}
	}()
	s, err := Open("cef+tcp://"+ln.Addr().String(), time.Second)
	if err != nil || s.Name() != "cef+tcp://"+ln.Addr().String() {
		t.Fatal(err, s)
	}
	if err := s.Send([][]byte{[]byte(ocsfEvent)}); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	ch := frame.UnwrapChain(msg)
	if k := ch.Kinds(); len(k) != 2 || k[0] != "rfc5424" || k[1] != "cef" {
		t.Fatalf("envelope chain %v for %s", k, msg)
	}
	env := ch.Innermost()
	if env.DeviceVendor != "ULPF" || env.SignatureID != "4001" || env.Name != "Network Activity/6" {
		t.Fatalf("CEF header as ULPF reads it: %+v", env)
	}
	ext := string(msg[len(msg)-env.PayloadLength:])
	for _, want := range []string{"rt=1790467200123", "src=10.4.1.7", "spt=40000", "dst=203.0.113.66", "dpt=443", "act=denied", "externalId=ev_cef1", "cs1Label=ulpf_raw_hash", "cs1=sha256:abc", "proto=tcp"} {
		if !strings.Contains(ext, want) {
			t.Fatalf("extension lacks %q: %s", want, ext)
		}
	}
	if strings.Contains(ext, "a=b") {
		t.Fatal("CEF is a projection: unmapped vendor fields are not sent")
	}
	if c, _ := CEF([]byte(`{"class_uid":1,"_lineage":{"event_id":"x=y\\z"}}`)); !strings.Contains(string(c), `externalId=x\=y\\z`) {
		t.Fatalf("extension values must escape = and \\: %s", c)
	}
}

// HEC: the envelope Splunk's collector expects, the token from the environment only, a batch acknowledged by 2xx;
// 503/429 and any other refusal are errors (retried / a stall) — HEC does not name the event it refused.
func TestHECEnvelopeTokenAndAnswers(t *testing.T) {
	var auth string
	var lines []map[string]any
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector/event" {
			w.WriteHeader(404)
			return
		}
		auth = r.Header.Get("Authorization")
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			var m map[string]any
			json.Unmarshal(sc.Bytes(), &m)
			lines = append(lines, m)
		}
		w.WriteHeader(status)
		io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer srv.Close()
	t.Setenv("ULPF_HEC_TOKEN", "")
	if _, err := Open("hec+"+srv.URL, time.Second); err == nil {
		t.Fatal("no token, no sink")
	}
	t.Setenv("ULPF_HEC_TOKEN", "t0k3n")
	s, err := Open("hec+"+srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send([][]byte{[]byte(ocsfEvent), []byte(ocsfEvent)}); err != nil {
		t.Fatal(err)
	}
	if auth != "Splunk t0k3n" || len(lines) != 2 || lines[0]["sourcetype"] != "ocsf:4001" || lines[0]["time"] != 1790467200.123 {
		t.Fatalf("auth %q lines %v", auth, lines)
	}
	ev := lines[0]["event"].(map[string]any)
	if ev["_lineage"].(map[string]any)["event_id"] != "ev_cef1" {
		t.Fatal("HEC carries the whole OCSF event")
	}
	for _, st := range []int{503, 429, 400, 403} {
		status = st
		if err := s.Send([][]byte{[]byte(ocsfEvent)}); err == nil {
			t.Fatalf("HEC %d must be an error", st)
		}
	}
}
