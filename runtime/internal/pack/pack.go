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
	"regexp"
	"strings"
	"time"

	"ulpf/runtime/contracts"
	"ulpf/runtime/internal/dsl"
	"ulpf/runtime/internal/keys"
	"ulpf/runtime/internal/spec"
)

type MappingField struct {
	Path          string          `json:"path,omitempty"`
	Constant      any             `json:"constant,omitempty"`
	EnvelopeField string          `json:"envelope_field,omitempty"` // 1.3.0: value from the unwrapped transport envelope
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
	Format  *spec.TSFormat `json:"format,omitempty"` // 1.3.0: timestamp transform for textual (envelope) values
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

type AnchorValues struct {
	AnchorID string   `json:"anchor_id"`
	Values   []string `json:"values"`
}

type Anchor struct {
	AnchorID string `json:"anchor_id"`
	Locator  struct {
		Kind        string `json:"kind"` // envelope_header | slot | key | pattern
		SlotIndex   int    `json:"slot_index"`
		Key         string `json:"key"`
		Pattern     string `json:"pattern"`
		HeaderField string `json:"header_field"`
	} `json:"locator"`
	Domain struct {
		Kind    string   `json:"kind"` // enum | pattern
		Values  []string `json:"values"`
		Pattern string   `json:"pattern"`
	} `json:"expected_value_domain"`
	Status string `json:"anchor_status"`
}

type RoutingSignature struct {
	L1               string              `json:"l1_envelope"`
	L2               string              `json:"l2_structure"`
	L3AnchorIDs      []string            `json:"l3_anchor_ids"`
	L3AnchorValues   []AnchorValues      `json:"l3_anchor_values"`
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
	Anchors         []Anchor `json:"anchors"`
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
	raw, err := os.ReadFile(packPath)
	if err != nil {
		return nil, err
	}
	// 1. Signature BEFORE anything parses the bytes (P5 boundary decision 3). The detached file is
	//    `<authority_id> <hex>`; the authority comes from the .sig, not from the unverified document.
	var sigAuthority string
	if !opts.AllowUnsigned {
		if opts.TrustDir == "" {
			return nil, errors.New("pack rejected: no trust store configured and unsigned packs are not allowed (fail closed)")
		}
		sigB, err := os.ReadFile(filepath.Join(dir, "pack.json.sig"))
		if err != nil {
			return nil, errors.New("pack rejected: detached signature pack.json.sig is missing (fail closed)")
		}
		parts := strings.Fields(string(sigB))
		if len(parts) != 2 {
			return nil, errors.New("pack rejected: pack.json.sig must be `<authority_id> <hex signature>` (fail closed)")
		}
		sigAuthority = parts[0]
		if err := (keys.TrustStore{Dir: opts.TrustDir}).Verify(sigAuthority, raw, parts[1]); err != nil {
			return nil, fmt.Errorf("pack rejected: %w (fail closed)", err)
		}
	}
	// 2. Contract, over bytes now known to be the authority's.
	if _, err := loader.Load(contracts.ParserPack, packPath); err != nil {
		return nil, fmt.Errorf("pack rejected: %w", err)
	}
	var p Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if !opts.AllowUnsigned {
		// 3. The document must name the authority that signed it and the file that was checked.
		if p.Signing.AuthorityID != sigAuthority || p.Signing.SignatureFile != "pack.json.sig" {
			return nil, fmt.Errorf("pack rejected: pack names authority %q / file %q but was signed by %q over pack.json.sig (fail closed)", p.Signing.AuthorityID, p.Signing.SignatureFile, sigAuthority)
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
	if err := checkAnchors(&p); err != nil {
		return nil, fmt.Errorf("pack rejected: %w (fail closed)", err)
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

// checkAnchors enforces what the contract cannot express across objects: every family anchor value
// names a pack anchor and lies inside that anchor's declared domain. A value outside the domain would
// let a family claim events the anchor itself calls a domain violation.
func checkAnchors(p *Pack) error {
	byID := map[string]*Anchor{}
	for i := range p.Anchors {
		byID[p.Anchors[i].AnchorID] = &p.Anchors[i]
	}
	for _, f := range p.Families {
		for _, av := range f.Routing.L3AnchorValues {
			a, ok := byID[av.AnchorID]
			if !ok {
				return fmt.Errorf("family %s: anchor %q is not declared by the pack", f.FamilyID, av.AnchorID)
			}
			for _, v := range av.Values {
				if !a.InDomain(v) {
					return fmt.Errorf("family %s: anchor %s value %q is outside the declared domain", f.FamilyID, av.AnchorID, v)
				}
			}
		}
	}
	return nil
}

// InDomain reports whether v lies in the anchor's declared value domain.
func (a *Anchor) InDomain(v string) bool {
	if a.Domain.Kind == "enum" {
		for _, d := range a.Domain.Values {
			if d == v {
				return true
			}
		}
		return false
	}
	re, err := regexp.Compile("^(?:" + a.Domain.Pattern + ")$")
	return err == nil && re.MatchString(v)
}
