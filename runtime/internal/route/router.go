// Package route is the P2 interim router: exact routing-signature match or quarantine. It never
// tries parsers to find out which one fits (invariant 6). The full L0–L4 decision DAG with anchors,
// K=4 and the per-pack tiebreaker is P6; this router handles raw-envelope positional families only
// and quarantines everything else with an explicit reason.
package route

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"ulpf/runtime/internal/pack"
)

type Decision struct {
	Family    *pack.Family
	Signature string
	Reason    string // set when Family is nil
}

type entry struct {
	family  *pack.Family
	arity   int
	classes []string
	lits    map[int]string
}

type Router struct {
	entries []entry
}

func New(p *pack.Pack) *Router {
	r := &Router{}
	for i := range p.Families {
		f := &p.Families[i]
		if f.Routing.L1 != "raw" || f.Routing.L2 != "positional" {
			continue // not routable by the interim router; such events quarantine
		}
		e := entry{family: f, arity: len(f.Routing.L4.TokenClassSequence), classes: f.Routing.L4.TokenClassSequence, lits: map[int]string{}}
		for _, l := range f.Routing.L3StructuralLits {
			e.lits[l.SlotIndex] = l.Text
		}
		r.entries = append(r.entries, e)
	}
	return r
}

var (
	reInt   = regexp.MustCompile(`^-?[0-9]+$`)
	reFloat = regexp.MustCompile(`^-?[0-9]+\.[0-9]+$`)
	reWord  = regexp.MustCompile(`^[A-Za-z0-9_.:\-]+$`)
	reHostP = regexp.MustCompile(`^[A-Za-z0-9.\-]+:[0-9]+$`)
)

// classify is the cheap per-token structural classifier used for the L4 sketch.
func classify(tok string) string {
	switch {
	case reInt.MatchString(tok):
		return "integer"
	case reFloat.MatchString(tok):
		return "float"
	case strings.Count(tok, ".") == 3 && net.ParseIP(tok) != nil:
		return "ipv4"
	case strings.Contains(tok, "://") || reHostP.MatchString(tok):
		return "url"
	case reWord.MatchString(tok):
		return "word"
	default:
		return "text"
	}
}

// Signature computes the interim L1/L2/L4 key for a raw positional event.
func Signature(raw []byte) (string, []string, []string) {
	toks := strings.Fields(string(raw))
	classes := make([]string, len(toks))
	for i, t := range toks {
		classes[i] = classify(t)
	}
	return fmt.Sprintf("raw|positional|%d|%s", len(toks), strings.Join(classes, ",")), toks, classes
}

// Route matches the event's signature against the declared families. Exactly one match routes;
// zero or several quarantine. No parser is executed here.
func (r *Router) Route(raw []byte) Decision {
	sig, toks, classes := Signature(raw)
	var matches []*pack.Family
	for _, e := range r.entries {
		if e.arity != len(toks) {
			continue
		}
		ok := true
		for i, want := range e.classes {
			if want == "literal" {
				if e.lits[i] != toks[i] {
					ok = false
					break
				}
				continue
			}
			if want != classes[i] {
				ok = false
				break
			}
		}
		if ok {
			matches = append(matches, e.family)
		}
	}
	switch len(matches) {
	case 1:
		return Decision{Family: matches[0], Signature: sig}
	case 0:
		return Decision{Signature: sig, Reason: "unknown signature: no family matches (quarantined, not guessed)"}
	default:
		return Decision{Signature: sig, Reason: fmt.Sprintf("ambiguous signature: %d families match; the decision DAG and tiebreaker are P6 (quarantined)", len(matches))}
	}
}
