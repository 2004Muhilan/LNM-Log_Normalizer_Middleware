// Package spec holds the typed form of the parser-spec contract (contracts/parser-spec.schema.json).
// It is a faithful mirror of the JSON, not an interpretation: the compiler (internal/dsl) is where
// semantics live.
package spec

import (
	"encoding/json"
	"fmt"
)

type Bounds struct {
	MaxEventBytes int `json:"max_event_bytes"`
	MaxFields     int `json:"max_fields"`
	MaxNesting    int `json:"max_nesting"`
	MaxRepeat     int `json:"max_repeat"`
}

type Spec struct {
	SchemaVersion string          `json:"schema_version"`
	SpecID        string          `json:"spec_id"`
	Description   string          `json:"description,omitempty"`
	RegexDialect  string          `json:"regex_dialect"`
	Bounds        Bounds          `json:"bounds"`
	Root          json.RawMessage `json:"root"`
}

type TSFormat struct {
	Kind       string          `json:"kind"`
	Pattern    string          `json:"pattern,omitempty"`
	AssumeYear json.RawMessage `json:"assume_year,omitempty"` // "ingest" or an integer
	Timezone   string          `json:"timezone,omitempty"`
}

type Coerce struct {
	Op        string     `json:"op"`
	To        string     `json:"to"`
	Format    *TSFormat  `json:"format,omitempty"`
	Formats   []TSFormat `json:"formats,omitempty"`
	Values    []string   `json:"values,omitempty"`
	OnFailure string     `json:"on_failure"`
}

type Decode struct {
	Op        string          `json:"op"`
	Encoding  string          `json:"encoding"`
	Then      json.RawMessage `json:"then,omitempty"`
	OnFailure string          `json:"on_failure"`
}

type Cell struct {
	Field  string  `json:"field"`
	Kind   string  `json:"kind"`
	Class  string  `json:"class,omitempty"`
	Coerce *Coerce `json:"coerce,omitempty"`
	Decode *Decode `json:"decode,omitempty"`
}

// Delim is one of {whitespace_run:true} | {char:"x"} | {string:"xyz"}.
type Delim struct {
	WhitespaceRun bool   `json:"whitespace_run,omitempty"`
	Char          string `json:"char,omitempty"`
	String        string `json:"string,omitempty"`
}

type Literal struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

type Regex struct {
	Op       string          `json:"op"`
	Pattern  string          `json:"pattern"`
	Captures map[string]Cell `json:"captures"`
}

// CsvCell is either a Cell (has "field") or {"parse": step}.
type CsvCell struct {
	Cell  *Cell
	Parse json.RawMessage
}

func (c *CsvCell) UnmarshalJSON(b []byte) error {
	var probe struct {
		Field *string         `json:"field"`
		Parse json.RawMessage `json:"parse"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	if probe.Field != nil {
		var cell Cell
		if err := json.Unmarshal(b, &cell); err != nil {
			return err
		}
		c.Cell = &cell
		return nil
	}
	if len(probe.Parse) == 0 {
		return fmt.Errorf("cell is neither a field cell nor a parse cell")
	}
	c.Parse = probe.Parse
	return nil
}

type CSV struct {
	Op            string    `json:"op"`
	Delimiter     string    `json:"delimiter"`
	Quote         *string   `json:"quote"`
	Escape        string    `json:"escape"`
	Fields        []CsvCell `json:"fields"`
	ExtraFields   string    `json:"extra_fields"`
	MissingFields string    `json:"missing_fields"`
}

type KV struct {
	Op                string             `json:"op"`
	PairSeparator     Delim              `json:"pair_separator"`
	KeyValueSeparator string             `json:"key_value_separator"`
	Quote             *string            `json:"quote"`
	Escape            string             `json:"escape"`
	KeyPattern        string             `json:"key_pattern"`
	Keys              map[string]CsvCell `json:"keys"`
	UnknownKeys       string             `json:"unknown_keys"`
	Order             string             `json:"order"`
	AllowBareKeys     bool               `json:"allow_bare_keys"`
}

// Slot is a token cell, a token-with-parse, or a direct step.
type Slot struct {
	Cell  *Cell
	Token json.RawMessage // the "parse" step of a token slot
	Step  json.RawMessage
}

func (s *Slot) UnmarshalJSON(b []byte) error {
	var probe struct {
		Field *string `json:"field"`
		Token *struct {
			Parse json.RawMessage `json:"parse"`
		} `json:"token"`
		Step json.RawMessage `json:"step"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	switch {
	case probe.Field != nil:
		var cell Cell
		if err := json.Unmarshal(b, &cell); err != nil {
			return err
		}
		s.Cell = &cell
	case probe.Token != nil:
		s.Token = probe.Token.Parse
	case len(probe.Step) > 0:
		s.Step = probe.Step
	default:
		return fmt.Errorf("slot is none of cell / token / step")
	}
	return nil
}

type Positional struct {
	Op                string `json:"op"`
	Delimiter         Delim  `json:"delimiter"`
	Slots             []Slot `json:"slots"`
	LeadingDelimiter  string `json:"leading_delimiter"`
	TrailingDelimiter string `json:"trailing_delimiter"`
	Tail              *Cell  `json:"tail"`
}

type Quoted struct {
	Op      string          `json:"op"`
	Open    string          `json:"open"`
	Close   string          `json:"close"`
	Escape  string          `json:"escape"`
	Content Cell            `json:"content"`
	Parse   json.RawMessage `json:"parse,omitempty"`
}

type Optional struct {
	Op   string          `json:"op"`
	Step json.RawMessage `json:"step"`
}

type Repeated struct {
	Op        string          `json:"op"`
	Step      json.RawMessage `json:"step"`
	Separator json.RawMessage `json:"separator,omitempty"`
	Min       int             `json:"min"`
	Max       int             `json:"max"`
}

// OpOf returns the "op" of a step object, or isSeq=true for a sequence (JSON array).
func OpOf(raw json.RawMessage) (op string, isSeq bool, err error) {
	trim := 0
	for trim < len(raw) && (raw[trim] == ' ' || raw[trim] == '\n' || raw[trim] == '\t' || raw[trim] == '\r') {
		trim++
	}
	if trim < len(raw) && raw[trim] == '[' {
		return "", true, nil
	}
	var probe struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", false, err
	}
	return probe.Op, false, nil
}

func Parse(b []byte) (*Spec, error) {
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.SchemaVersion != "1.0.0" {
		return nil, fmt.Errorf("unsupported schema_version %q", s.SchemaVersion)
	}
	return &s, nil
}
