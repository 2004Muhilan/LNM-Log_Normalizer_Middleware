// Package pack loads a parser-pack bundle for the runtime: contract validation (via contracts),
// compilation of every family spec, and verification that each family's parser_hash equals the
// hash of the compiled representation — fail closed on any mismatch.
package pack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ulpf/runtime/contracts"
	"ulpf/runtime/internal/dsl"
)

type MappingField struct {
	Path          string          `json:"path,omitempty"`
	Constant      any             `json:"constant,omitempty"`
	OCSFAttribute string          `json:"ocsf_attribute"`
	Mandatory     bool            `json:"mandatory"`
	Transform     *Transform      `json:"transform,omitempty"`
	Provenance    json.RawMessage `json:"provenance"`
}

type Transform struct {
	Kind    string         `json:"kind"`
	With    []string       `json:"with,omitempty"`
	Lookup  map[string]any `json:"lookup,omitempty"`
	Default any            `json:"default,omitempty"`
}

type Unmapped struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

type Mapping struct {
	MappingVersion string         `json:"mapping_version"`
	Fields         []MappingField `json:"fields"`
	Unmapped       []Unmapped     `json:"unmapped"`
	Acceptance     struct {
		MandatoryAttributes []string `json:"mandatory_attributes"`
	} `json:"acceptance_snapshot"`
}

type StructuralLiteral struct {
	SlotIndex int    `json:"slot_index"`
	Text      string `json:"text"`
}

type RoutingSignature struct {
	L1               string              `json:"l1_envelope"`
	L2               string              `json:"l2_structure"`
	L3AnchorIDs      []string            `json:"l3_anchor_ids"`
	L3StructuralLits []StructuralLiteral `json:"l3_structural_literals"`
	L4               struct {
		ArityBucket        string   `json:"arity_bucket"`
		TokenClassSequence []string `json:"token_class_sequence"`
	} `json:"l4_sketch"`
}

type Family struct {
	FamilyID      string           `json:"family_id"`
	EventClassUID int              `json:"event_class_uid"`
	Routing       RoutingSignature `json:"routing_signature"`
	Parser        struct {
		SpecRef    string `json:"spec_ref"`
		SpecID     string `json:"spec_id"`
		DSLHash    string `json:"dsl_hash"`
		ParserHash string `json:"parser_hash"`
	} `json:"parser"`
	Mapping Mapping      `json:"mapping"`
	Program *dsl.Program `json:"-"`
}

type Pack struct {
	PackID      string `json:"pack_id"`
	PackVersion string `json:"pack_version"`
	Source      struct {
		SourceID string `json:"source_id"`
		Vendor   string `json:"vendor"`
		Product  string `json:"product"`
	} `json:"source"`
	OCSF struct {
		Version string `json:"version"`
	} `json:"ocsf"`
	Time struct {
		SourceTimezone     *string `json:"source_timezone"`
		TimezoneConfidence string  `json:"timezone_confidence"`
	} `json:"time"`
	TiebreakerField *string        `json:"tiebreaker_field"`
	Families        []Family       `json:"families"`
	Dir             string         `json:"-"`
	Location        *time.Location `json:"-"`
	CategoryUIDs    map[int]int64  `json:"-"` // class uid -> category uid, from the pinned index
}

type LoadOptions struct {
	ContractsDir string
	PinnedIndex  string
	// RequireSignature is false in P2: signing and the trust store are P5. When true, a missing or
	// invalid pack.json.sig refuses the pack.
	RequireSignature bool
}

// Load validates pack.json against the contract, compiles every family spec, and verifies hashes.
func Load(dir string, opts LoadOptions) (*Pack, error) {
	loader, err := contracts.NewLoader(opts.ContractsDir, opts.PinnedIndex)
	if err != nil {
		return nil, err
	}
	packPath := filepath.Join(dir, "pack.json")
	if _, err := loader.Load(contracts.ParserPack, packPath); err != nil {
		return nil, fmt.Errorf("pack rejected: %w", err)
	}
	if opts.RequireSignature {
		if _, err := os.Stat(filepath.Join(dir, "pack.json.sig")); err != nil {
			return nil, errors.New("pack rejected: signature required and pack.json.sig is missing (fail closed)")
		}
		return nil, errors.New("pack rejected: signature verification is not implemented before P5 (fail closed)")
	}
	raw, err := os.ReadFile(packPath)
	if err != nil {
		return nil, err
	}
	var p Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	p.Dir = dir
	p.CategoryUIDs = map[int]int64{}
	for _, f := range p.Families {
		if cat, ok := loader.CategoryUID(int64(f.EventClassUID)); ok {
			p.CategoryUIDs[f.EventClassUID] = cat
		}
	}
	if p.Time.SourceTimezone != nil && p.Time.TimezoneConfidence != "unresolved" {
		if loc, err := time.LoadLocation(*p.Time.SourceTimezone); err == nil {
			p.Location = loc
		}
	}
	for i := range p.Families {
		f := &p.Families[i]
		specBytes, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Parser.SpecRef)))
		if err != nil {
			return nil, err
		}
		prog, err := dsl.Compile(specBytes)
		if err != nil {
			return nil, fmt.Errorf("family %s: %w", f.FamilyID, err)
		}
		if prog.DSLHash != f.Parser.DSLHash {
			return nil, fmt.Errorf("family %s: dsl_hash mismatch (fail closed)", f.FamilyID)
		}
		if prog.ParserHash() != f.Parser.ParserHash {
			return nil, fmt.Errorf("family %s: parser_hash %s does not match the compiled representation %s (fail closed)", f.FamilyID, f.Parser.ParserHash, prog.ParserHash())
		}
		f.Program = prog
	}
	return &p, nil
}
