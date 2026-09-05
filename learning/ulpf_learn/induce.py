"""Structure induction — deterministic, no model.

Whitespace-delimited positional templates: tokenise every sample, require one arity (one structural
family per onboarding batch — a second arity is a second family and is reported, not merged), classify
each slot with the same structural classifier the runtime router uses, mark constant slots as
structural literals, and produce the CANDIDATE spec (positional cells pos_1..pos_N with their observed
classes, no semantics), the L1–L4 routing sketch, and per-slot observations for the provider and the
enumerator.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field

_INT = re.compile(r"^-?[0-9]+$")
_FLOAT = re.compile(r"^-?[0-9]+\.[0-9]+$")
_WORD = re.compile(r"^[A-Za-z0-9_.:\-]+$")
_HOSTP = re.compile(r"^[A-Za-z0-9.\-]+:[0-9]+$")


def classify(tok: str) -> str:
    if _INT.match(tok):
        return "integer"
    if _FLOAT.match(tok):
        return "float"
    if tok.count(".") == 3:
        try:
            ipaddress.IPv4Address(tok)
            return "ipv4"
        except ValueError:
            pass
    if "://" in tok or _HOSTP.match(tok):
        return "url"
    if _WORD.match(tok):
        return "word"
    return "text"


# a slot's class is the most specific class every sample agrees on; disagreement widens to text
_WIDEN = {("integer", "float"): "float", ("float", "integer"): "float"}


def join_class(a: str, b: str) -> str:
    """Widen two observed classes: equal stays; integer/float widen to float; anything else to text."""
    if a == b:
        return a
    return _WIDEN.get((a, b), "text")


@dataclass
class SlotObservation:
    index: int                      # 0-based
    token_class: str                # observed structural class
    distinct: int
    samples: list[str]
    constant: str | None = None     # set when every sample has the same token
    has_slash: bool = False
    name: str | None = None         # vendor field name when the structure carries one (kv keys, documented
                                    # csv columns); induction from bare positional text leaves it None


@dataclass
class Structure:
    arity: int
    slots: list[SlotObservation]
    sample_count: int
    other_arities: Counter = field(default_factory=Counter)

    def candidate_spec(self, spec_id: str) -> dict:
        return {
            "schema_version": "1.1.0",
            "spec_id": spec_id,
            "description": f"Candidate parser: induced {self.arity}-slot whitespace positional template; slot classes are observed token classes, no semantics.",
            "regex_dialect": "re2",
            "bounds": {"max_event_bytes": 8192, "max_fields": 64, "max_nesting": 4, "max_repeat": 16},
            "root": {
                "op": "positional",
                "delimiter": {"whitespace_run": True},
                "leading_delimiter": "reject",
                "trailing_delimiter": "reject",
                "tail": None,
                "slots": [{"field": f"pos_{s.index + 1}", "kind": "semantic", "class": s.token_class} for s in self.slots],
            },
        }

    def routing_sketch(self) -> dict:
        seq = ["literal" if s.constant is not None else s.token_class for s in self.slots]
        lits = [{"slot_index": s.index, "text": s.constant} for s in self.slots if s.constant is not None]
        return {"l1_envelope": "raw", "l2_structure": "positional", "l3_anchor_ids": [], "l3_structural_literals": lits,
                "l4_sketch": {"arity_bucket": str(self.arity), "token_class_sequence": seq}}


def induce(lines: list[bytes]) -> Structure:
    rows = [l.decode("utf-8", "replace").split() for l in lines if l.strip()]
    if not rows:
        raise ValueError("no samples")
    arities = Counter(len(r) for r in rows)
    arity, _ = arities.most_common(1)[0]
    kept = [r for r in rows if len(r) == arity]
    others = Counter({a: c for a, c in arities.items() if a != arity})
    slots = []
    for i in range(arity):
        toks = [r[i] for r in kept]
        cls = classify(toks[0])
        for t in toks[1:]:
            cls = join_class(cls, classify(t))
        distinct = len(set(toks))
        constant = toks[0] if distinct == 1 and len(kept) > 1 else None
        slots.append(SlotObservation(i, cls, distinct, sorted(set(toks))[:8], constant, any("/" in t for t in toks)))
    return Structure(arity, slots, len(kept), others)
