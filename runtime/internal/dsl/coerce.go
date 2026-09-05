package dsl

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"ulpf/runtime/internal/spanmap"
	"ulpf/runtime/internal/spec"
)

var validCoerceTargets = map[string]bool{"string": true, "int": true, "float": true, "bool": true, "ipv4": true, "ipv6": true, "ip": true, "mac": true, "timestamp": true, "enum": true}
var validTSKinds = map[string]bool{"epoch_s": true, "epoch_ms": true, "epoch_us": true, "epoch_ns": true, "epoch_s_frac": true, "epoch_auto": true, "rfc3339": true, "rfc3164": true, "pattern": true}

func checkCoerce(c *spec.Coerce) error {
	if !validCoerceTargets[c.To] {
		return fmt.Errorf("unknown coerce target %q", c.To)
	}
	if c.OnFailure != "reject" && c.OnFailure != "opaque" {
		return errors.New("coerce.on_failure must be reject or opaque")
	}
	if c.To == "timestamp" {
		fs := c.Formats
		if c.Format != nil {
			fs = append(fs, *c.Format)
		}
		if len(fs) == 0 {
			return errors.New("timestamp coerce needs format or formats")
		}
		for _, f := range fs {
			if !validTSKinds[f.Kind] {
				return fmt.Errorf("unknown timestamp format kind %q", f.Kind)
			}
			if f.Kind == "pattern" && f.Pattern == "" {
				return errors.New("pattern format needs pattern")
			}
			if f.Kind == "pattern" {
				if err := checkPattern(f.Pattern); err != nil {
					return err
				}
			}
		}
	}
	if c.To == "enum" && len(c.Values) == 0 {
		return errors.New("enum coerce needs values")
	}
	return nil
}

func checkPattern(p string) error {
	for i := 0; i < len(p); i++ {
		if p[i] == '%' {
			if i+1 >= len(p) || !strings.ContainsRune("YymdeHMSfbjzZpI", rune(p[i+1])) {
				return fmt.Errorf("unsupported strptime token in %q", p)
			}
			i++
		}
	}
	return nil
}

// Env carries per-source coercion context from the pack.
type Env struct {
	SourceLocation *time.Location // nil when the pack's timezone is unresolved -> UTC assumed, flagged in lineage
	IngestTime     time.Time      // for rfc3164 assume_year=ingest
}

// coerce converts a decoded string value. It returns the coerced record, or an error when the value
// does not fit; the caller applies on_failure.
func coerce(c *spec.Coerce, val string, env Env) (*spanmap.Coerced, error) {
	switch c.To {
	case "string":
		return &spanmap.Coerced{To: "string", Value: val}, nil
	case "int":
		i, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return nil, err
		}
		return &spanmap.Coerced{To: "int", Value: i}, nil
	case "float":
		f, err := strconv.ParseFloat(val, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("not a finite float")
		}
		return &spanmap.Coerced{To: "float", Value: f}, nil
	case "bool":
		switch strings.ToLower(val) {
		case "true", "1", "yes", "on":
			return &spanmap.Coerced{To: "bool", Value: true}, nil
		case "false", "0", "no", "off":
			return &spanmap.Coerced{To: "bool", Value: false}, nil
		}
		return nil, fmt.Errorf("not a bool")
	case "ipv4", "ipv6", "ip":
		ip := net.ParseIP(val)
		if ip == nil || (c.To == "ipv4" && ip.To4() == nil) || (c.To == "ipv6" && ip.To4() != nil) {
			return nil, fmt.Errorf("not an %s", c.To)
		}
		return &spanmap.Coerced{To: c.To, Value: ip.String()}, nil
	case "mac":
		hw, err := net.ParseMAC(val)
		if err != nil {
			return nil, err
		}
		return &spanmap.Coerced{To: "mac", Value: hw.String()}, nil
	case "enum":
		for _, v := range c.Values {
			if v == val {
				return &spanmap.Coerced{To: "enum", Value: val}, nil
			}
		}
		return nil, fmt.Errorf("not in enum")
	case "timestamp":
		fs := c.Formats
		if c.Format != nil {
			fs = []spec.TSFormat{*c.Format}
		}
		var lastErr error
		for i, f := range fs {
			ms, prec, err := parseTimestamp(f, val, env)
			if err == nil {
				out := &spanmap.Coerced{To: "timestamp", Value: ms, PrecisionSelected: prec}
				if c.Format == nil {
					idx := i
					out.FormatSelected = &idx
				}
				return out, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return nil, fmt.Errorf("unknown coerce target")
}

const (
	epochWindowStart = 946684800  // 2000-01-01T00:00:00Z
	epochWindowEnd   = 4102444800 // 2100-01-01T00:00:00Z
)

// toMillis converts an epoch value in units of 1/unitsPerSecond seconds to milliseconds without
// overflowing: n*1000/div overflowed int64 for nanosecond epochs (1.7e18 * 1000 > 9.2e18), turning a
// 2024 FortiGate eventtime into 573947194 ms. Found by the P4 op-coverage matrix against the reference
// executor; the P2 replay tests parsed those values but never compared the coerced result.
func toMillis(n, unitsPerSecond int64) int64 {
	if unitsPerSecond <= 1000 {
		return n * (1000 / unitsPerSecond)
	}
	return n / (unitsPerSecond / 1000)
}

// parseTimestamp returns epoch milliseconds and, for epoch_auto, the selected precision.
func parseTimestamp(f spec.TSFormat, val string, env Env) (int64, string, error) {
	switch f.Kind {
	case "epoch_s", "epoch_ms", "epoch_us", "epoch_ns":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0, "", err
		}
		return toMillis(n, map[string]int64{"epoch_s": 1, "epoch_ms": 1000, "epoch_us": 1000000, "epoch_ns": 1000000000}[f.Kind]), "", nil
	case "epoch_s_frac":
		fl, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, "", err
		}
		return int64(math.Round(fl * 1000)), "", nil
	case "epoch_auto":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0, "", err
		}
		// Disjoint 2000–2100 windows per precision; exactly one may contain the value, else fail.
		var sel string
		var ms int64
		for _, p := range []struct {
			name string
			mult int64
		}{{"s", 1}, {"ms", 1000}, {"us", 1000000}, {"ns", 1000000000}} {
			lo, hi := epochWindowStart*p.mult, epochWindowEnd*p.mult
			if n >= lo && n < hi {
				if sel != "" {
					return 0, "", fmt.Errorf("epoch_auto: value matches more than one precision")
				}
				sel = p.name
				ms = toMillis(n, p.mult)
			}
		}
		if sel == "" {
			return 0, "", fmt.Errorf("epoch_auto: value %d is outside every 2000–2100 window", n)
		}
		return ms, sel, nil
	case "rfc3339":
		t, err := time.Parse(time.RFC3339Nano, val)
		if err != nil {
			return 0, "", err
		}
		return t.UnixMilli(), "", nil
	case "rfc3164":
		// "Jan  2 15:04:05" — no year, no zone.
		t, err := time.Parse("Jan _2 15:04:05", val)
		if err != nil {
			return 0, "", err
		}
		year := env.IngestTime.Year()
		if env.IngestTime.IsZero() {
			year = time.Now().UTC().Year()
		}
		if yy, ok := json0(f.AssumeYear).year(); ok {
			year = yy
		}
		loc := time.UTC
		if env.SourceLocation != nil {
			loc = env.SourceLocation
		}
		tt := time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc)
		// rollover: a January event ingested in late December belongs to next year
		if !env.IngestTime.IsZero() && tt.After(env.IngestTime.Add(48*time.Hour)) {
			tt = tt.AddDate(-1, 0, 0)
		}
		return tt.UnixMilli(), "", nil
	case "pattern":
		return parsePattern(f, val, env)
	}
	return 0, "", fmt.Errorf("unknown timestamp kind %q", f.Kind)
}

type json0 []byte

func (j json0) year() (int, bool) {
	s := strings.TrimSpace(string(j))
	if s == "" || s == `"ingest"` {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

var monthAbbr = map[string]time.Month{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

// parsePattern implements the strptime token subset %Y %y %m %d %e %H %M %S %f %b %j %z %Z %p %I,
// identically to the Python side: numeric fields of at most two digits accept one or two digits.
func parsePattern(f spec.TSFormat, val string, env Env) (int64, string, error) {
	p := f.Pattern
	year, month, day, hour, min, sec, nsec, yday := 1970, 1, 1, 0, 0, 0, 0, 0
	pm := -1
	var offset *int
	i, j := 0, 0
	digits := func(min, max int) (int, error) {
		k := j
		for k < len(val) && k-j < max && val[k] >= '0' && val[k] <= '9' {
			k++
		}
		if k-j < min {
			return 0, fmt.Errorf("expected %d-%d digits at %d", min, max, j)
		}
		n, _ := strconv.Atoi(val[j:k])
		j = k
		return n, nil
	}
	for i < len(p) {
		if p[i] != '%' {
			if j >= len(val) || val[j] != p[i] {
				return 0, "", fmt.Errorf("literal mismatch at %d", j)
			}
			i++
			j++
			continue
		}
		tok := p[i+1]
		i += 2
		var err error
		switch tok {
		case 'Y':
			year, err = digits(4, 4)
		case 'y':
			var y int
			y, err = digits(2, 2)
			year = 2000 + y
			if y >= 69 {
				year = 1900 + y
			}
		case 'm':
			month, err = digits(1, 2)
		case 'd', 'e':
			for j < len(val) && val[j] == ' ' {
				j++
			}
			day, err = digits(1, 2)
		case 'H', 'I':
			hour, err = digits(1, 2)
		case 'M':
			min, err = digits(1, 2)
		case 'S':
			sec, err = digits(1, 2)
		case 'f':
			k := j
			for k < len(val) && k-j < 9 && val[k] >= '0' && val[k] <= '9' {
				k++
			}
			if k == j {
				return 0, "", fmt.Errorf("expected fraction at %d", j)
			}
			frac := val[j:k]
			for len(frac) < 9 {
				frac += "0"
			}
			nsec, _ = strconv.Atoi(frac)
			j = k
		case 'j':
			yday, err = digits(1, 3)
		case 'b':
			if j+3 > len(val) {
				return 0, "", fmt.Errorf("expected month abbreviation at %d", j)
			}
			m, ok := monthAbbr[strings.ToLower(val[j:j+3])]
			if !ok {
				return 0, "", fmt.Errorf("bad month abbreviation %q", val[j:j+3])
			}
			month = int(m)
			j += 3
		case 'z':
			if j < len(val) && (val[j] == 'Z' || val[j] == 'z') {
				z := 0
				offset = &z
				j++
				break
			}
			if j >= len(val) || (val[j] != '+' && val[j] != '-') {
				return 0, "", fmt.Errorf("expected offset at %d", j)
			}
			sign := 1
			if val[j] == '-' {
				sign = -1
			}
			j++
			hh, e1 := digits(2, 2)
			if e1 != nil {
				return 0, "", e1
			}
			if j < len(val) && val[j] == ':' {
				j++
			}
			mm, e2 := digits(2, 2)
			if e2 != nil {
				return 0, "", e2
			}
			z := sign * (hh*3600 + mm*60)
			offset = &z
		case 'Z':
			k := j
			for k < len(val) && ((val[k] >= 'A' && val[k] <= 'Z') || (val[k] >= 'a' && val[k] <= 'z')) {
				k++
			}
			if k == j {
				return 0, "", fmt.Errorf("expected zone name at %d", j)
			}
			if strings.EqualFold(val[j:k], "UTC") || strings.EqualFold(val[j:k], "GMT") || val[j:k] == "Z" {
				z := 0
				offset = &z
			}
			j = k
		case 'p':
			if j+2 > len(val) {
				return 0, "", fmt.Errorf("expected AM/PM at %d", j)
			}
			switch strings.ToUpper(val[j : j+2]) {
			case "AM":
				pm = 0
			case "PM":
				pm = 1
			default:
				return 0, "", fmt.Errorf("expected AM/PM at %d", j)
			}
			j += 2
		}
		if err != nil {
			return 0, "", err
		}
	}
	if j != len(val) {
		return 0, "", fmt.Errorf("trailing bytes after timestamp at %d", j)
	}
	if pm == 1 && hour < 12 {
		hour += 12
	}
	if pm == 0 && hour == 12 {
		hour = 0
	}
	loc := time.UTC
	switch f.Timezone {
	case "in_value":
		if offset == nil {
			return 0, "", fmt.Errorf("timezone in_value but no offset in value")
		}
		loc = time.FixedZone("", *offset)
	case "source":
		if offset != nil {
			loc = time.FixedZone("", *offset)
		} else if env.SourceLocation != nil {
			loc = env.SourceLocation
		}
	case "utc", "":
		if offset != nil {
			loc = time.FixedZone("", *offset)
		}
	}
	var t time.Time
	if yday > 0 {
		t = time.Date(year, 1, 1, hour, min, sec, nsec, loc).AddDate(0, 0, yday-1)
	} else {
		t = time.Date(year, time.Month(month), day, hour, min, sec, nsec, loc)
		if t.Month() != time.Month(month) || t.Day() != day {
			return 0, "", fmt.Errorf("invalid calendar date")
		}
	}
	return t.UnixMilli(), "", nil
}
