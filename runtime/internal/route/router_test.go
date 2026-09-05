package route

import (
	"strings"
	"testing"
)

func TestSignatureClassifierMatchesGoldenSketch(t *testing.T) {
	line := []byte("1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://example.com/index.html - HIER_DIRECT/93.184.216.34 text/html")
	_, _, classes := Signature(line)
	want := []string{"float", "integer", "ipv4", "text", "integer", "word", "url", "word", "text", "text"}
	if strings.Join(classes, ",") != strings.Join(want, ",") {
		t.Fatalf("classes %v", classes)
	}
	// CONNECT lines carry host:port, still a url token
	_, _, classes = Signature([]byte("1734567896.010     78 10.20.31.7 TCP_DENIED/403 1893 CONNECT badsite.example:443 - HIER_NONE/- text/html"))
	if classes[6] != "url" {
		t.Fatalf("host:port should classify as url, got %s", classes[6])
	}
}
