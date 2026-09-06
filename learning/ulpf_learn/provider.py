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


class RecordedProvider(Provider):
    """Replays proposals the model made in a recorded spike run (spike/results/<machine>/<model>__<backend>__<case>__<mode>.json).
    Keyed by the spec's field names, so the same recording labels the same given spec on any machine — the
    model's judgement, reproduced without the GPU; provenance names the recording and the model digest. It is
    the P6 onboarding path for the vendor families (the live path is --provider model, unchanged)."""

    name = "recorded"

    def __init__(self, result_path: Path):
        self.result = json.loads(Path(result_path).read_text(encoding="utf-8"))
        self.path = str(result_path)
        rows = self.result["judgement"]["rows"]
        self.by_field = {r["field"]: r for r in rows}

    def propose(self, structure: Structure) -> Proposal:
        slots = []
        for obs in structure.slots:
            row = self.by_field.get(obs.name or "")
            if row is None:
                slots.append(SlotProposal(obs.index, [], "not in the recording"))
                continue
            slots.append(SlotProposal(obs.index, list(row.get("proposal") or []), row.get("note", ""),
                                      None if row.get("label") != "unmapped" else (obs.name or None)))
        uid = self.result["event_class_uid"]
        name = {4001: "network_activity", 4002: "http_activity", 4003: "dns_activity"}.get(uid, str(uid))
        prov = dict(self.result.get("provenance") or {})
        prov.update({"recording": self.path, "recorded_on": self.result.get("machine")})
        return Proposal(uid, name, slots, "model", self.result["model_hash"], {"provenance": prov})
