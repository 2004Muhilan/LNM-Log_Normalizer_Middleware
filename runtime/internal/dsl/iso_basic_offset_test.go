package dsl

import (
	"testing"

	"ulpf/runtime/internal/spec"
)

// Suricata's EVE timestamp is ISO 8601 with a BASIC offset ("+0000", no colon) — not RFC 3339. The learning plane now
// derives the existing `pattern` kind for it (discriminators.coercion_for, 2026-09-30); the runtime must read it to the
// same instant as the Python twin (learning/tests/test_time_is_a_timestamp.py holds the same values).
func TestISOBasicOffsetPatternIsTheSameInstantAsRFC3339(t *testing.T) {
	f := spec.TSFormat{Kind: "pattern", Pattern: "%Y-%m-%dT%H:%M:%S.%f%z", Timezone: "in_value"}
	for _, c := range []struct {
		val  string
		want int64
	}{
		{"2026-09-29T17:01:40.291297+0000", 1790701300291},
		{"2026-09-29T22:31:40.291297+0530", 1790701300291},
		{"2026-09-29T12:01:40.291297-0500", 1790701300291},
		{"2026-09-29T17:01:40.291297+00:00", 1790701300291},
	} {
		got, err := ParseTimestamp(f, c.val, Env{})
		if err != nil || got != c.want {
			t.Fatalf("%s: got %d, %v; want %d", c.val, got, err, c.want)
		}
	}
	if _, err := ParseTimestamp(f, "2026-09-29T17:01:40.291297", Env{}); err == nil {
		t.Fatal("in_value without an offset must fail, never assume one")
	}
}
