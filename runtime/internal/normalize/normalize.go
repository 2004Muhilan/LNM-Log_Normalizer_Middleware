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

	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/evidence"
	"ulpf/runtime/internal/frame"
	"ulpf/runtime/internal/pack"
	"ulpf/runtime/internal/spanmap"
)

const LineageSchemaVersion = "1.3.0" // P5: optional envelope record; P7: relay_chain, batch, cef envelope, udp_datagram (additive; earlier documents remain valid)

type Context struct {
	Pack           *pack.Pack
	Family         *pack.Family
	Record         evidence.Record
	Signature      string
	ProcessingTime time.Time
	Envelope       *frame.Envelope // the innermost unwrapped envelope, when there was one (1.2.0; the device's own header on a relay chain)
	Chain          *frame.Chain    // P7 (1.3.0): every envelope removed, when more than one
	// P8 (invariant 8): a correction is normalization@vN with derived_from naming the version it corrects.
	// Zero means the live path: version 1, derived from nothing.
	NormalizationVersion int
	DerivedFrom          int
}

// Absent records a mapped mandatory attribute that has no value in this event, with its cause.
// Mandatory is a mapping obligation, not a per-event presence requirement: absence is a fact about
// the event, not a defect — but the two causes are different facts and are kept apart.
type Absent struct {
	Attribute string `json:"attribute"`
	// structural: the source carried no span for the mapped field (empty cell, optional group that
	// did not participate). uncoercible: a span exists but its value failed coercion and was
	// downgraded to opaque (e.g. Squid's "-" for an upstream address).
	Cause string `json:"cause"`
}

// Result is what Normalize produces besides the event itself.
type Result struct {
	Absent   []Absent // mapped mandatory attributes without a value, by cause
	Unmapped []string // mandatory attributes the pack does not map at all — must be empty for a valid pack
}

// Normalize returns the event and the usability facts for it. The only absence that is an error is
// `time`, which the envelope contract (and OCSF) require on every event.
func Normalize(m *spanmap.SpanMap, ctx Context) (map[string]any, Result, error) {
	vals := map[string]any{}    // path -> coerced value or string
	strs := map[string]string{} // path -> string value
	opaque := map[string]bool{} // paths whose span exists but carries no usable value
	nulls := map[string]bool{}  // paths whose span is a pack-declared null marker
	for _, s := range m.Spans {
		if s.DeclaredNull {
			nulls[s.Path] = true
			continue
		}
		if s.Kind == "opaque" {
			opaque[s.Path] = true
			continue
		}
		if s.Kind != "semantic" || s.Value == nil {
			if s.Kind == "semantic" {
				opaque[s.Path] = true // decode_status invalid
			}
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
	mapped := map[string]string{} // attribute -> path ("" for constants)
	for _, f := range ctx.Family.Mapping.Fields {
		mapped[f.OCSFAttribute] = f.Path
		if f.Constant != nil {
			// pack-declared constant (e.g. severity_id): provenance-bearing, never derived
			setPath(out, f.OCSFAttribute, normNumber(f.Constant))
			present[f.OCSFAttribute] = true
			continue
		}
		if f.EnvelopeField != "" {
			// 1.3.0: the value comes from the transport envelope unwrapped at ingest (ASA's syslog header
			// timestamp is the event time; the payload carries none). Absent when there was no envelope.
			raw, ok := envelopeValue(ctx.Envelope, f.EnvelopeField)
			if !ok {
				mapped[f.OCSFAttribute] = "@envelope." + f.EnvelopeField
				continue
			}
			var v any = raw
			if f.Transform != nil && f.Transform.Kind == "timestamp" && f.Transform.Format != nil {
				ms, err := dsl.ParseTimestamp(*f.Transform.Format, raw, dsl.Env{SourceLocation: ctx.Pack.Location, IngestTime: time.UnixMilli(ctx.Record.IngestTime)})
				if err != nil {
					mapped[f.OCSFAttribute] = "@envelope." + f.EnvelopeField
					opaque["@envelope."+f.EnvelopeField] = true
					continue
				}
				v = ms
			} else if f.Transform != nil {
				var okT bool
				v, okT = transform(f.Transform, v, strs)
				if !okT {
					continue
				}
			}
			setPath(out, f.OCSFAttribute, v)
			present[f.OCSFAttribute] = true
			continue
		}
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
	var res Result
	for _, a := range ctx.Family.Mapping.Acceptance.MandatoryAttributes {
		if present[a] {
			continue
		}
		path, isMapped := mapped[a]
		switch {
		case !isMapped:
			res.Unmapped = append(res.Unmapped, a) // the acceptance gate should have blocked this pack
		case nulls[path]:
			res.Absent = append(res.Absent, Absent{Attribute: a, Cause: "declared_null"})
		case opaque[path]:
			res.Absent = append(res.Absent, Absent{Attribute: a, Cause: "uncoercible"})
		default:
			res.Absent = append(res.Absent, Absent{Attribute: a, Cause: "structural"})
		}
	}
	// OCSF base attributes that are mechanical derivations (P3 boundary): category from the pinned
	// class table, type_uid from class and activity, metadata from the pack. severity_id is NOT
	// derived — it is pack-declared like any other attribute.
	if cat, ok := ctx.Pack.CategoryUIDs[ctx.Family.EventClassUID]; ok {
		out["category_uid"] = cat
	}
	activity := int64(0)
	if a, ok := out["activity_id"]; ok {
		if n, ok := toInt64(a); ok {
			activity = n
		}
	}
	out["type_uid"] = int64(ctx.Family.EventClassUID)*100 + activity
	// metadata: the pack may have mapped attributes under it (metadata.event_code, metadata.logged_time);
	// the mechanical derivations are added beside them, never over them (found by the P6 agreement tool).
	meta, _ := out["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["version"] = ctx.Pack.OCSF.Version
	meta["product"] = map[string]any{"vendor_name": ctx.Pack.Source.Vendor, "name": ctx.Pack.Source.Product}
	out["metadata"] = meta
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
		"schema_version":        lineageVersion(ctx),
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
		"normalization_version": normVersion(ctx),
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
	if ctx.NormalizationVersion > 1 {
		if ctx.DerivedFrom < 1 || ctx.DerivedFrom >= ctx.NormalizationVersion {
			return nil, res, fmt.Errorf("normalization@v%d must be derived_from an earlier version, got %d (invariant 8)", ctx.NormalizationVersion, ctx.DerivedFrom)
		}
		lineage["derived_from"] = ctx.DerivedFrom
	}
	if len(res.Absent) > 0 {
		lineage["absent"] = res.Absent
	}
	if ctx.Envelope != nil {
		lineage["envelope"] = ctx.Envelope
	}
	if ctx.Chain != nil && ctx.Chain.Depth() > 1 {
		lineage["relay_chain"] = ctx.Chain.Envelopes
	}
	if ctx.Record.Framing.BatchSize > 0 {
		lineage["batch"] = map[string]any{"batch_hash": ctx.Record.Framing.BatchHash, "index": ctx.Record.Framing.BatchIndex, "size": ctx.Record.Framing.BatchSize}
	}
	out["_lineage"] = lineage
	if _, ok := out["time"]; !ok {
		return out, res, fmt.Errorf("normalized event has no time (required by OCSF and by the envelope contract)")
	}
	return out, res, nil
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

// envelopeValue reads one header field of the unwrapped envelope as a string.
func envelopeValue(e *frame.Envelope, field string) (string, bool) {
	if e == nil || e.Kind == "none" {
		return "", false
	}
	switch field {
	case "timestamp":
		return e.Timestamp, e.Timestamp != "" && e.Timestamp != "-"
	case "hostname":
		return e.Hostname, e.Hostname != "" && e.Hostname != "-"
	case "app_name":
		return e.AppName, e.AppName != "" && e.AppName != "-"
	case "proc_id":
		return e.ProcID, e.ProcID != "" && e.ProcID != "-"
	case "msg_id":
		return e.MsgID, e.MsgID != "" && e.MsgID != "-"
	case "priority":
		if e.Priority != nil {
			return strconv.Itoa(*e.Priority), true
		}
	case "facility":
		if e.Facility != nil {
			return strconv.Itoa(*e.Facility), true
		}
	case "severity":
		if e.Severity != nil {
			return strconv.Itoa(*e.Severity), true
		}
	}
	return "", false
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

func normVersion(ctx Context) int {
	if ctx.NormalizationVersion > 1 {
		return ctx.NormalizationVersion
	}
	return 1
}

// lineageVersion: 1.4.0 only for an event that carries what 1.4.0 added (a LEEF envelope); everything else keeps
// declaring 1.3.0, so no existing output — and no golden vector — changes.
func lineageVersion(ctx Context) string {
	if ctx.Envelope != nil && ctx.Envelope.Kind == "leef" {
		return "1.4.0"
	}
	if ctx.Chain != nil {
		for _, e := range ctx.Chain.Envelopes {
			if e.Kind == "leef" {
				return "1.4.0"
			}
		}
	}
	return LineageSchemaVersion
}
