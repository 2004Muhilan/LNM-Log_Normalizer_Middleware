package spec

// The typed mirror must match contracts/parser-spec.schema.json exactly: every schema property has a
// Go field with the same JSON name and the same optionality, and no Go field exists that the schema
// does not define. This test walks the schema with reflection so drift between contract and mirror
// is caught mechanically in every phase, not by reading.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	wd, _ := os.Getwd()
	p := filepath.Join(wd, "..", "..", "..", "contracts", "parser-spec.schema.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

type goField struct {
	omitempty bool
	kind      reflect.Kind
	typ       reflect.Type
}

func goFields(t reflect.Type) map[string]goField {
	out := map[string]goField{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		out[parts[0]] = goField{omitempty: len(parts) > 1 && parts[1] == "omitempty", kind: f.Type.Kind(), typ: f.Type}
	}
	return out
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func strSet(v any) map[string]bool {
	out := map[string]bool{}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			out[x.(string)] = true
		}
	}
	return out
}

func TestMirrorMatchesSchema(t *testing.T) {
	schema := loadSchema(t)
	defs := schema["$defs"].(map[string]any)
	def := func(name string) map[string]any {
		if name == "" {
			return schema
		}
		if d, ok := defs[name].(map[string]any); ok {
			return d
		}
		// inlined object under the root's properties (bounds)
		if d, ok := schema["properties"].(map[string]any)[name].(map[string]any); ok {
			return d
		}
		t.Fatalf("schema has no definition for %q", name)
		return nil
	}
	cases := []struct {
		def string
		typ reflect.Type
	}{
		{"", reflect.TypeOf(Spec{})},
		{"bounds", reflect.TypeOf(Bounds{})},
		{"timestamp_format", reflect.TypeOf(TSFormat{})},
		{"coerce", reflect.TypeOf(Coerce{})},
		{"decode", reflect.TypeOf(Decode{})},
		{"cell", reflect.TypeOf(Cell{})},
		{"op_literal", reflect.TypeOf(Literal{})},
		{"op_regex", reflect.TypeOf(Regex{})},
		{"op_csv", reflect.TypeOf(CSV{})},
		{"op_kv", reflect.TypeOf(KV{})},
		{"op_positional", reflect.TypeOf(Positional{})},
		{"op_quoted", reflect.TypeOf(Quoted{})},
		{"op_optional", reflect.TypeOf(Optional{})},
		{"op_repeated", reflect.TypeOf(Repeated{})},
		{"op_json", reflect.TypeOf(JSONOp{})},
		{"op_xml", reflect.TypeOf(XMLOp{})},
	}
	for _, c := range cases {
		name := c.def
		if name == "" {
			name = "(root)"
		}
		t.Run(name, func(t *testing.T) {
			d := def(c.def)
			props := d["properties"].(map[string]any)
			required := strSet(d["required"])
			fields := goFields(c.typ)
			if !reflect.DeepEqual(keys(props), keys(fields)) {
				t.Fatalf("property sets differ\n schema: %v\n go:     %v", keys(props), keys(fields))
			}
			for p, f := range fields {
				req := required[p]
				nullable := f.kind == reflect.Ptr || f.kind == reflect.Slice || f.kind == reflect.Map
				switch {
				case req && f.omitempty:
					t.Errorf("%s: required in the schema but omitempty in Go", p)
				case !req && !f.omitempty && !nullable:
					t.Errorf("%s: optional in the schema but not omitempty in Go", p)
				}
				// every enum-bearing scalar property must be a plain Go string (values live in the schema)
				if ps, ok := props[p].(map[string]any); ok {
					if _, hasEnum := ps["enum"]; hasEnum && f.kind != reflect.String {
						t.Errorf("%s: schema enum but Go kind %s", p, f.kind)
					}
					if ps["type"] == "integer" && f.kind != reflect.Int {
						t.Errorf("%s: schema integer but Go kind %s", p, f.kind)
					}
					if ps["type"] == "boolean" && f.kind != reflect.Bool {
						t.Errorf("%s: schema boolean but Go kind %s", p, f.kind)
					}
				}
			}
			if d["additionalProperties"] != false {
				t.Errorf("schema object %s must be closed (additionalProperties false)", name)
			}
		})
	}

	// Delimiter: the union of the oneOf branches' single properties equals the Go fields.
	t.Run("delimiter", func(t *testing.T) {
		union := map[string]bool{}
		for _, br := range def("delimiter")["oneOf"].([]any) {
			for k := range br.(map[string]any)["properties"].(map[string]any) {
				union[k] = true
			}
		}
		if !reflect.DeepEqual(keys(union), keys(goFields(reflect.TypeOf(Delim{})))) {
			t.Fatalf("delimiter alternatives differ: schema %v go %v", keys(union), keys(goFields(reflect.TypeOf(Delim{}))))
		}
	})

	// step: the closed op set. Every op_* def referenced by step.oneOf has a Go type above, and vice versa.
	t.Run("step op set", func(t *testing.T) {
		refs := map[string]bool{}
		for _, br := range def("step")["oneOf"].([]any) {
			if r, ok := br.(map[string]any)["$ref"].(string); ok {
				refs[strings.TrimPrefix(r, "#/$defs/")] = true
			}
		}
		mirrored := map[string]bool{}
		for _, c := range cases {
			if strings.HasPrefix(c.def, "op_") {
				mirrored[c.def] = true
			}
		}
		if !reflect.DeepEqual(keys(refs), keys(mirrored)) {
			t.Fatalf("op set differs: schema %v mirror %v", keys(refs), keys(mirrored))
		}
	})

	// slot and csv_cell: the branch discriminators the custom unmarshallers switch on.
	t.Run("slot and csv_cell branches", func(t *testing.T) {
		branchKeys := func(name string) []string {
			var out []string
			for _, br := range def(name)["oneOf"].([]any) {
				b := br.(map[string]any)
				if r, ok := b["$ref"].(string); ok && r == "#/$defs/cell" {
					out = append(out, "field")
					continue
				}
				for _, k := range strSet(b["required"]) {
					_ = k
				}
				req := keys(strSet(b["required"]))
				out = append(out, req...)
			}
			sort.Strings(out)
			return out
		}
		if got := branchKeys("slot"); !reflect.DeepEqual(got, []string{"field", "step", "token"}) {
			t.Fatalf("slot branches %v", got)
		}
		if got := branchKeys("csv_cell"); !reflect.DeepEqual(got, []string{"field", "parse"}) {
			t.Fatalf("csv_cell branches %v", got)
		}
		// behavioural check of the unmarshallers against each branch
		var s Slot
		for _, in := range []string{`{"field":"a","kind":"semantic"}`, `{"token":{"parse":{"op":"literal","text":"x"}}}`, `{"step":{"op":"literal","text":"x"}}`} {
			s = Slot{}
			if err := json.Unmarshal([]byte(in), &s); err != nil {
				t.Fatal(err)
			}
		}
		if err := json.Unmarshal([]byte(`{"bogus":1}`), &s); err == nil {
			t.Fatal("slot accepted an unknown branch")
		}
		var c CsvCell
		if err := json.Unmarshal([]byte(`{"bogus":1}`), &c); err == nil {
			t.Fatal("csv_cell accepted an unknown branch")
		}
	})

	// Parse refuses unknown contract versions, like the loader.
	t.Run("version", func(t *testing.T) {
		if _, err := Parse([]byte(`{"schema_version":"2.0.0","spec_id":"x","regex_dialect":"re2","bounds":{},"root":{}}`)); err == nil {
			t.Fatal("unknown schema_version accepted")
		}
	})
}
