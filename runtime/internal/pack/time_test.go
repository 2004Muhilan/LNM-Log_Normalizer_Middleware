package pack

import (
	"strings"
	"testing"
)

// The 2026-09-30 Suricata pack mapped `time` from a cell with no coercion: every event carried the text, the SIEM
// rejected each one. Such a family must not load, whoever promoted it; one with a timestamp coercion, a timestamp
// transform or the envelope's own time must.
func TestAFamilyWhoseTimeIsNotATimestampDoesNotLoad(t *testing.T) {
	fam := func(tr *Transform) *Family {
		return &Family{FamilyID: "json-20", Mapping: Mapping{Fields: []MappingField{{Path: "timestamp", OCSFAttribute: "time", Mandatory: true, Transform: tr}}}}
	}
	text := []byte(`{"root":{"op":"json","keys":{"timestamp":{"field":"timestamp","kind":"semantic","class":"text"}}}}`)
	coerced := []byte(`{"root":{"op":"json","keys":{"timestamp":{"field":"timestamp","kind":"semantic","class":"text",
		"coerce":{"op":"coerce","to":"timestamp","format":{"kind":"pattern","pattern":"%Y-%m-%dT%H:%M:%S.%f%z","timezone":"in_value"},"on_failure":"reject"}}}}}`)
	if err := checkTimeIsTimestamp(fam(nil), text); err == nil || !strings.Contains(err.Error(), "no timestamp coercion") {
		t.Fatalf("text time must be refused, got %v", err)
	}
	if err := checkTimeIsTimestamp(fam(nil), coerced); err != nil {
		t.Fatalf("a coerced time must load: %v", err)
	}
	if err := checkTimeIsTimestamp(fam(&Transform{Kind: "epoch_ms"}), text); err != nil {
		t.Fatalf("a timestamp transform must load: %v", err)
	}
	env := &Family{FamilyID: "asa", Mapping: Mapping{Fields: []MappingField{{EnvelopeField: "timestamp", OCSFAttribute: "time", Transform: &Transform{Kind: "timestamp"}}}}}
	if err := checkTimeIsTimestamp(env, text); err != nil {
		t.Fatalf("the envelope's time must load: %v", err)
	}
}
