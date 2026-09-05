// Package normalize applies a family's OCSF mapping to a span map and produces the normalized
// event (contracts/normalized-event.schema.json): OCSF attributes nested as objects, vendor
// extensions under "unmapped", and the _lineage block.
package normalize

import (
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/spanmap"
)

const LineageSchemaVersion = "1.0.0"

type Context struct {
	Pack           *pack.Pack
	Family         *pack.Family
	Record         evidence.Record
	Signature      string
	ProcessingTime time.Time
}

// Normalize returns the event and the list of mandatory OCSF attributes that ended up absent
// (empty when the event is fully usable).
func Normalize(m *spanmap.SpanMap, ctx Context) (map[string]any, []string, error) {
	vals := map[string]any{}    // path -> coerced value or string
	strs := map[string]string{} // path -> string value
	for _, s := range m.Spans {
		if s.Kind != "semantic" || s.Value == nil {
			continue
		}
		strs[s.Path] = *s.Value
		if s.Coerced != nil {
			vals[s.Path] = s.Coerced.Value
		} else {
			vals[s.Path] = *s.Value
		}
	}
	out := map[string]any{"class_uid": ctx.Family.EventClassUID}
	present := map[string]bool{}
	for _, f := range ctx.Family.Mapping.Fields {
		v, ok := vals[f.Path]
		if !ok && !(f.Transform != nil && f.Transform.Kind == "compose_datetime") {
			continue
		}
		v, ok = transform(f.Transform, v, strs)
		if !ok {
			continue
		}
		setPath(out, f.OCSFAttribute, v)
		present[f.OCSFAttribute] = true
	}
	var missing []string
	for _, a := range ctx.Family.Mapping.Acceptance.MandatoryAttributes {
		if !present[a] {
			missing = append(missing, a)
		}
	}
	unmapped := map[string]any{}
	for _, u := range ctx.Family.Mapping.Unmapped {
		if v, ok := vals[u.Path]; ok {
			unmapped[u.Name] = v
		}
	}
	if len(unmapped) > 0 {
		out["unmapped"] = unmapped
	}
	var eventTime int64
	if t, ok := out["time"]; ok {
		if n, ok := toInt64(t); ok {
			eventTime = n
		}
	}
	lineage := map[string]any{
		"schema_version":        LineageSchemaVersion,
		"event_id":              ctx.Record.EventID,
		"raw_hash":              ctx.Record.RawHash,
		"segment_id":            ctx.Record.SegmentID,
		"offset":                ctx.Record.Offset,
		"length":                ctx.Record.Length,
		"parser_id":             ctx.Pack.PackID,
		"parser_version":        ctx.Pack.PackVersion,
		"mapping_version":       ctx.Family.Mapping.MappingVersion,
		"ocsf_version":          ctx.Pack.OCSF.Version,
		"source_id":             ctx.Pack.Source.SourceID,
		"collector_id":          ctx.Record.Collector,
		"ingest_channel":        ctx.Record.Channel,
		"family_id":             ctx.Family.FamilyID,
		"routing_signature":     ctx.Signature,
		"event_time":            eventTime,
		"ingest_time":           ctx.Record.IngestTime,
		"processing_time":       ctx.ProcessingTime.UnixMilli(),
		"source_timezone":       ctx.Pack.Time.SourceTimezone,
		"timezone_confidence":   ctx.Pack.Time.TimezoneConfidence,
		"normalization_version": 1,
		"framing": map[string]any{
			"method":                  ctx.Record.Framing.Method,
			"raw_prefix":              base64.StdEncoding.EncodeToString(ctx.Record.Framing.RawPrefix),
			"raw_suffix":              base64.StdEncoding.EncodeToString(ctx.Record.Framing.RawSuffix),
			"fragment_count":          ctx.Record.Framing.FragmentCount,
			"original_message_length": ctx.Record.Framing.OriginalMessageLength,
			"truncation_status":       ctx.Record.Framing.TruncationStatus,
			"framing_confidence":      ctx.Record.Framing.FramingConfidence,
		},
	}
	out["_lineage"] = lineage
	if _, ok := out["time"]; !ok {
		return out, missing, fmt.Errorf("normalized event has no time")
	}
	return out, missing, nil
}

func transform(t *pack.Transform, v any, strs map[string]string) (any, bool) {
	if t == nil || t.Kind == "none" {
		return v, true
	}
	switch t.Kind {
	case "int":
		return toInt(v)
	case "float":
		switch x := v.(type) {
		case float64:
			return x, true
		case int64:
			return float64(x), true
		case string:
			f, err := strconv.ParseFloat(x, 64)
			return f, err == nil
		}
		return nil, false
	case "lowercase":
		return strings.ToLower(fmt.Sprint(v)), true
	case "epoch_ms":
		return toInt(v)
	case "lookup":
		key := fmt.Sprint(v)
		if r, ok := t.Lookup[key]; ok {
			return normNumber(r), true
		}
		if t.Default != nil {
			return normNumber(t.Default), true
		}
		return nil, false
	case "compose_datetime":
		// with: [date "YYYY-MM-DD", time "HH:MM:SS", optional tz "-0500" / "+05:30"]
		if len(t.With) < 2 {
			return nil, false
		}
		d, ok1 := strs[t.With[0]]
		tm, ok2 := strs[t.With[1]]
		if !ok1 || !ok2 {
			return nil, false
		}
		layout := "2006-01-02 15:04:05"
		s := d + " " + tm
		if len(t.With) >= 3 {
			if tz, ok := strs[t.With[2]]; ok && tz != "" {
				tz = strings.Replace(tz, ":", "", 1)
				layout, s = layout+" -0700", s+" "+tz
			}
		}
		tt, err := time.Parse(layout, s)
		if err != nil {
			return nil, false
		}
		return tt.UnixMilli(), true
	}
	return nil, false
}

func normNumber(v any) any {
	if f, ok := v.(float64); ok && f == math.Trunc(f) {
		return int64(f)
	}
	return v
}

func toInt(v any) (any, bool) {
	n, ok := toInt64(v)
	return n, ok
}

func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// setPath sets a dotted OCSF attribute path, creating nested objects.
func setPath(out map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := out
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = v
}
