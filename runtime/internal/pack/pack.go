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
	"strings"
	"time"

	"ulpf/runtime/contracts"
	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/keys"
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
	TiebreakerField *string  `json:"tiebreaker_field"`
	Families        []Family `json:"families"`
	Signing         struct {
		AuthorityID   string `json:"authority_id"`
		Algorithm     string `json:"algorithm"`
		SignatureFile string `json:"signature_file"`
	} `json:"signing"`
	SignatureVerified bool           `json:"-"`
	Dir               string         `json:"-"`
	Location          *time.Location `json:"-"`
	CategoryUIDs      map[int]int64  `json:"-"` // class uid -> category uid, from the pinned index
}

type LoadOptions struct {
	ContractsDir string
	PinnedIndex  string
	// AllowUnsigned disables signature verification (development only; the CLI prints a warning).
	// Since P5 the default is to REQUIRE a valid detached signature: pack.json.sig must hold an ed25519
	// signature over the exact bytes of pack.json by the authority named in signing.authority_id, and
	// that authority must be in the trust store. Missing file, unknown authority, or any mismatch
	// refuses the pack before anything in it is compiled (fail closed).
	AllowUnsigned bool
	TrustDir      string
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
	raw, err := os.ReadFile(packPath)
	if err != nil {
		return nil, err
	}
	var p Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if !opts.AllowUnsigned {
		if opts.TrustDir == "" {
			return nil, errors.New("pack rejected: no trust store configured and unsigned packs are not allowed (fail closed)")
		}
		sigB, err := os.ReadFile(filepath.Join(dir, p.Signing.SignatureFile))
		if err != nil {
			return nil, fmt.Errorf("pack rejected: detached signature %s is missing (fail closed)", p.Signing.SignatureFile)
		}
		if err := (keys.TrustStore{Dir: opts.TrustDir}).Verify(p.Signing.AuthorityID, raw, strings.TrimSpace(string(sigB))); err != nil {
			return nil, fmt.Errorf("pack rejected: %w (fail closed)", err)
		}
		p.SignatureVerified = true
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
