"""The working plan: per-slot structure + semantics with provenance. Built from induction and the
provider's proposals, rewritten by discriminator evidence, compiled into a spec and a mapping.
Everything here is data the acceptance engine judges; nothing here promotes itself."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

MODEL_PROVENANCES = {"model_proposal", "fixture_proposal"}
SUFFICIENT = {"vendor_schema_or_device_configuration", "validated_discriminator", "resolved_ambiguity_certificate", "operator_assertion", "structural_determination"}


@dataclass
class Mapping:
    attribute: str
    provenance: dict                 # {category, ...} per the pack contract
    transform: dict | None = None
    mandatory: bool = False


@dataclass
class Part:
    """One value-producing cell: a whole slot, or one component of a '/'-split slot."""
    field: str
    cls: str
    kind: str = "semantic"
    coerce: dict | None = None
    null_values: list[str] | None = None
    mappings: list[Mapping] = field(default_factory=list)
    unmapped_name: str | None = None
    candidates: list[str] = field(default_factory=list)   # ranked proposals when unresolved
    proposed_by: str = "fixture"


@dataclass
class Slot:
    index: int
    token_class: str
    parts: list[Part]
    split: str | None = None          # literal separator when the token is compound
    samples: list[str] = field(default_factory=list)


@dataclass
class EnvelopeMapping:
    """1.3.0: an attribute whose value comes from the transport envelope (ASA's time is the syslog header)."""
    envelope_field: str
    attribute: str
    provenance: dict
    transform: dict | None = None
    mandatory: bool = False


@dataclass
class Plan:
    source_id: str
    event_class_uid: int
    event_class_name: str
    slots: list[Slot]
    null_values: list[str] = field(default_factory=list)
    constants: list[Mapping] = field(default_factory=list)
    source_timezone: str | None = None
    timezone_confidence: str = "unresolved"
    proposed_by: str = "fixture"
    model_hash: str = "none:fixture"
    given_spec: dict | None = None          # P6: a hand-authored spec (csv/kv/regex) — the plan maps its fields, it does not rebuild the structure
    family_id: str | None = None
    envelope_mappings: list[EnvelopeMapping] = field(default_factory=list)
    drafted: bool = False                   # laptop branch: given_spec was DRAFTED from the samples (draft.py); its cells are rebuilt from the parts

    def parts(self):
        for s in self.slots:
            for p in s.parts:
                yield s, p

    def spec(self, spec_id: str, description: str) -> dict:
        if self.given_spec is not None:
            out = copy.deepcopy(self.given_spec)
            if self.drafted:   # the structure is the draft's; every cell carries what the plan knows now (observed class, coercion)
                by_field = {p.field: p for _, p in self.parts()}
                root = out["root"]
                cells = root.get("keys") or root.get("paths")
                if cells is not None:
                    for k, c in cells.items():
                        cells[k] = _cell(by_field[c["field"]]) if c["field"] in by_field else c
                else:
                    root["fields"] = [_cell(by_field[c["field"]]) if c["field"] in by_field else c for c in root["fields"]]
            return out
        slots = []
        for s in self.slots:
            if s.split is None:
                slots.append(_cell(s.parts[0]))
            else:
                slots.append({"token": {"parse": {
                    "op": "positional", "delimiter": {"char": s.split}, "leading_delimiter": "reject", "trailing_delimiter": "reject", "tail": None,
                    "slots": [_cell(p) for p in s.parts]}}})
        out = {"schema_version": "1.1.0", "spec_id": spec_id, "description": description, "regex_dialect": "re2"}
        if self.null_values:
            out["null_values"] = list(self.null_values)
        out["bounds"] = {"max_event_bytes": 8192, "max_fields": 64, "max_nesting": 4, "max_repeat": 16}
        out["root"] = {"op": "positional", "delimiter": {"whitespace_run": True}, "leading_delimiter": "reject", "trailing_delimiter": "reject", "tail": None, "slots": slots}
        return out

    def mapping_fields(self) -> list[dict]:
        out = []
        for _, p in self.parts():
            for m in p.mappings:
                row = {"path": p.field, "ocsf_attribute": m.attribute, "mandatory": m.mandatory, "provenance": copy.deepcopy(m.provenance)}
                if m.transform:
                    row["transform"] = copy.deepcopy(m.transform)
                out.append(row)
        for m in self.constants:
            row = {"constant": m.transform["constant"] if m.transform else None, "ocsf_attribute": m.attribute, "mandatory": m.mandatory, "provenance": copy.deepcopy(m.provenance)}
            out.append(row)
        for e in self.envelope_mappings:
            row = {"envelope_field": e.envelope_field, "ocsf_attribute": e.attribute, "mandatory": e.mandatory, "provenance": copy.deepcopy(e.provenance)}
            if e.transform:
                row["transform"] = copy.deepcopy(e.transform)
            out.append(row)
        return out

    def unmapped(self) -> list[dict]:
        return [{"path": p.field, "name": p.unmapped_name} for _, p in self.parts() if p.unmapped_name]


def _cell(p: Part) -> dict:
    c = {"field": p.field, "kind": p.kind}
    if p.kind == "semantic":
        c["class"] = p.cls
        if p.coerce:
            c["coerce"] = copy.deepcopy(p.coerce)
        if p.null_values is not None:
            c["null_values"] = list(p.null_values)
    return c
