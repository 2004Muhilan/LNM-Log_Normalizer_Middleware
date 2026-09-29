package pipeline

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ulpf/runtime/internal/normalize"
	"ulpf/runtime/internal/pack"
)

// parser-pack 1.4.0, time.timezone_field (2026-09-30, from the real FortiGate: every line carries tz="+0530", and the
// normalized event said source_timezone null / unresolved). Where the event states a valid offset in the named field,
// the lineage says so — the offset, confidence "declared"; where it does not (absent, a zone name, out of range), the
// pack's own defaults stand. Every event still validates against normalized-event.
func TestTheSourcesOwnOffsetIsUsedWhereTheEventStatesIt(t *testing.T) {
	p := formatPack(t, "fg-tz", "raw", "kv", `{"schema_version":"1.1.0","spec_id":"fg-tz",`+specHead+
		`{"op":"kv","pair_separator":{"whitespace_run":true},"key_value_separator":"=","quote":"\"","escape":"backslash","key_pattern":"[a-z][a-z0-9_]*","unknown_keys":"opaque","order":"any",
		  "keys":{"ts":{"field":"ts",`+tsCell+`},"src":{"field":"src",`+ipCell+`},"dst":{"field":"dst",`+ipCell+`},"tz":{"field":"tz","kind":"semantic","class":"text"}}}}`, "ts", "src", "dst")
	p.Time.TimezoneField = "tz"
	in := "ts=1734567890123 src=10.0.0.1 dst=10.0.0.2 tz=\"+0530\"\n" +
		"ts=1734567890124 src=10.0.0.3 dst=10.0.0.4\n" +
		"ts=1734567890125 src=10.0.0.5 dst=10.0.0.6 tz=Asia/Kolkata\n" +
		"ts=1734567890126 src=10.0.0.7 dst=10.0.0.8 tz=-05:00\n"
	var out, q bytes.Buffer
	o := fixedOpts(t, p, &out, &q)
	o.Pack, o.Packs = nil, []*pack.Pack{p}
	if _, err := Run(strings.NewReader(in), o); err != nil {
		t.Fatal(err)
	}
	if n := validateEvents(t, out.String()); n != 4 {
		t.Fatalf("validated %d events; quarantine: %s", n, q.String())
	}
	want := [][2]any{{"+05:30", "declared"}, {nil, "unresolved"}, {nil, "unresolved"}, {"-05:00", "declared"}}
	for i, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var ev map[string]any
		json.Unmarshal([]byte(line), &ev)
		lin := ev["_lineage"].(map[string]any)
		if lin["source_timezone"] != want[i][0] || lin["timezone_confidence"] != want[i][1] {
			t.Fatalf("event %d: source_timezone %v, confidence %v; want %v", i, lin["source_timezone"], lin["timezone_confidence"], want[i])
		}
	}
}

func TestUTCOffset(t *testing.T) {
	for in, want := range map[string]string{"+0530": "+05:30", "+05:30": "+05:30", "-0500": "-05:00", "Z": "+00:00", "+1400": "+14:00"} {
		if got, ok := normalize.UTCOffset(in); !ok || got != want {
			t.Errorf("%q -> %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "Asia/Kolkata", "+1500", "+0560", "0530", "+5:30", "+05-30", "+053"} {
		if got, ok := normalize.UTCOffset(in); ok {
			t.Errorf("%q must not read as an offset, got %q", in, got)
		}
	}
}
