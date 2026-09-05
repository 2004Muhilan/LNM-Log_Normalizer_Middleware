"""Candidate provider interface. The model (P4) is one implementation; until then a fixture and hand
entry are the implementations. A provider proposes semantics for an induced structure; it never
decides anything — every proposal is a candidate with `proposed_by` recorded, and mandatory fields
still need non-model provenance before promotion (invariant 4).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .induce import Structure


@dataclass
class SlotProposal:
    slot_index: int                  # 0-based
    candidates: list[str]            # ranked OCSF attributes (dotted), or [] for "no proposal"
    note: str = ""
    unmapped_name: str | None = None # proposal to carry the value as a vendor extension instead
    sub_split: str | None = None     # proposal that the token is a compound joined by this char


@dataclass
class Proposal:
    event_class_uid: int
    event_class_name: str
    slots: list[SlotProposal]
    proposed_by: str                 # fixture | model | operator
    model_hash: str = "none:fixture"
    notes: dict = field(default_factory=dict)


class Provider:
    name = "abstract"

    def propose(self, structure: Structure) -> Proposal:  # pragma: no cover - interface
        raise NotImplementedError


class FixtureProvider(Provider):
    """Reads a fixture keyed by arity; stands in for the model exactly where the model will stand."""

    name = "fixture"

    def __init__(self, fixture_path: Path):
        self.fixture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))

    def propose(self, structure: Structure) -> Proposal:
        key = str(structure.arity)
        if key not in self.fixture["by_arity"]:
            raise KeyError(f"fixture has no proposal for a {structure.arity}-slot structure")
        fx = self.fixture["by_arity"][key]
        slots = [SlotProposal(int(k) - 1, v.get("candidates", []), v.get("note", ""), v.get("unmapped_name"), v.get("sub_split"))
                 for k, v in sorted(fx["slots"].items(), key=lambda kv: int(kv[0]))]
        return Proposal(fx["event_class_uid"], fx["event_class_name"], slots, "fixture", self.fixture.get("model_hash", "none:fixture"), fx.get("notes", {}))
