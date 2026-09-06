// Package mlfeat emits the ML feature tuple (requirement h): (template_id, parameter_vector,
// timestamp, entity_ids), one record per normalized event, alongside the OCSF JSONL. The tuple is a
// projection of what the pipeline already established — the routed family (the template), the
// parser's semantic spans in spec field order (the parameters), the event time, and the entity-bearing
// OCSF attributes — so it carries no interpretation the normalized event does not.
package mlfeat

import (
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/spanmap"
)

// SchemaVersion of contracts/ml-feature.schema.json, the sixth contract (frozen at the P6 boundary).
// The runtime produces these records and checks its own output against the schema in its tests.
const SchemaVersion = "1.0.0"

// entity attributes, in a fixed order; absent ones are omitted from entity_ids. Entities are what recur
// across events and can be followed by a sequence model; a rule name or a verb is a parameter, not an
// entity. `domain` takes the first of several sources, by class: proxies name the URL host, DNS the
// query, firewalls sometimes a destination domain.
var entityAttrs = [][2]string{
	{"src_ip", "src_endpoint.ip"}, {"dst_ip", "dst_endpoint.ip"},
	{"src_host", "src_endpoint.hostname"}, {"dst_host", "dst_endpoint.hostname"},
	{"user", "actor.user.name"}, {"src_user", "src_endpoint.owner.name"}, {"dst_user", "dst_endpoint.owner.name"},
	{"device", "device.hostname"}, {"session", "connection_info.uid"},
	{"domain", "http_request.url.hostname"}, {"domain", "query.hostname"}, {"domain", "dst_endpoint.domain"},
}

type Record struct {
	SchemaVersion string `json:"schema_version"`
	EventID       string `json:"event_id"`
	SourceID      string `json:"source_id"`
	ClassUID      int    `json:"class_uid"`
	// TemplateID names the structure the event was routed to: pack/family, pinned to the parser that
	// produced the parameters (two packs with the same family id are different templates).
	TemplateID string `json:"template_id"`
	// ParameterVector holds one entry per semantic field of the family's spec, in the spec's field
	// order: the coerced value when coercion happened, else the string, null when the field did not
	// participate in this event (optional group, empty cell, declared null, opaque).
	ParameterVector []any          `json:"parameter_vector"`
	ParameterNames  []string       `json:"parameter_names"`
	Timestamp       int64          `json:"timestamp"` // event time, epoch ms (the OCSF `time`)
	EntityIDs       map[string]any `json:"entity_ids"`
}

// Build projects one normalized event onto the tuple.
func Build(p *pack.Pack, f *pack.Family, m *spanmap.SpanMap, ev map[string]any, env *frame.Envelope, eventID string) Record {
	names := f.Program.Fields()
	vals := map[string]any{}
	for _, s := range m.Spans {
		if s.Kind != "semantic" || s.Value == nil || s.DeclaredNull {
			continue
		}
		if _, seen := vals[s.Path]; seen {
			continue // first occurrence wins for repeated paths
		}
		if s.Coerced != nil {
			vals[s.Path] = s.Coerced.Value
		} else {
			vals[s.Path] = *s.Value
		}
	}
	vec := make([]any, len(names))
	for i, n := range names {
		if v, ok := vals[n]; ok {
			vec[i] = v
		}
	}
	ents := map[string]any{}
	for _, e := range entityAttrs {
		if _, have := ents[e[0]]; have {
			continue // first source wins
		}
		if v, ok := lookup(ev, e[1]); ok {
			ents[e[0]] = v
		}
	}
	if env != nil && env.Hostname != "" {
		if _, has := ents["device"]; !has {
			ents["device"] = env.Hostname // the relay-stated origin, when the payload names none
		}
	}
	var ts int64
	if t, ok := ev["time"]; ok {
		switch n := t.(type) {
		case int64:
			ts = n
		case int:
			ts = int64(n)
		case float64:
			ts = int64(n)
		}
	}
	return Record{SchemaVersion: SchemaVersion, EventID: eventID, SourceID: p.Source.SourceID, ClassUID: f.EventClassUID,
		TemplateID: p.PackID + "/" + f.FamilyID + "@" + f.Parser.ParserHash, ParameterVector: vec, ParameterNames: names, Timestamp: ts, EntityIDs: ents}
}

func lookup(ev map[string]any, dotted string) (any, bool) {
	cur := any(ev)
	start := 0
	for i := 0; i <= len(dotted); i++ {
		if i == len(dotted) || dotted[i] == '.' {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			cur, ok = m[dotted[start:i]]
			if !ok {
				return nil, false
			}
			start = i + 1
		}
	}
	return cur, true
}
