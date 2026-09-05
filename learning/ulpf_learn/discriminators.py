"""Discriminator appliers: turn supplied evidence into provenance-bearing plan rewrites.

v1 implements `device_logformat_configuration` (Squid, via the vendor table), `operator_assertion`,
and `operator_labelled_session`. Every other library discriminator is listed in requests as an
alternative but has no applier yet — applying one raises, it does not pretend.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import yaml

from .plan import Mapping, Part, Plan, Slot

ROOT = Path(__file__).resolve().parents[2]
VENDOR_TABLES = {"squid": ROOT / "library" / "vendor-tables" / "squid-logformat.yaml"}

CODE_LEXICON = ["ts", "tu", "tr", "tl", "tg", "Ss", "Sh", "Hs", "st", "rm", "ru", "rv", "un", "ul", "ue", "ui", "mt", "la", "lp", "ea", "a", "p", "h", "A"]
_MODS = set("-+0123456789.[#\"'")


class NoApplier(Exception):
    pass


def lex_logformat(directive: str) -> list[list[tuple[str, str]]]:
    """'logformat squid %ts.%03tu %6tr %>a ...' -> per whitespace slot, a list of (kind, text) parts
    where kind is 'code' (direction+letters, modifiers stripped) or 'lit'."""
    s = directive.strip()
    if s.startswith("logformat"):
        toks = s.split(None, 2)
        s = toks[2] if len(toks) == 3 else ""
    slots = []
    for tok in s.split():
        parts, i = [], 0
        while i < len(tok):
            if tok[i] != "%":
                parts.append(("lit", tok[i]))
                i += 1
                continue
            i += 1
            while i < len(tok) and tok[i] in _MODS:
                i += 1
            direction = ""
            if i < len(tok) and tok[i] in "<>":
                direction = tok[i]
                i += 1
            code = None
            for c in sorted(CODE_LEXICON, key=len, reverse=True):
                if tok.startswith(c, i):
                    code = c
                    i += len(c)
                    break
            if code is None:
                raise ValueError(f"unknown logformat code at {tok!r}[{i}]")
            parts.append(("code", direction + code))
        slots.append(parts)
    return slots


def load_vendor_table(vendor: str) -> dict:
    return yaml.safe_load(VENDOR_TABLES[vendor].read_text(encoding="utf-8"))


def _part_from_code(code: str, entry: dict, mandatory: set[str], evidence_prefix: str, cert_for_field: dict) -> Part:
    prov = {"category": "vendor_schema_or_device_configuration", "discriminator_id": "device_logformat_configuration",
            "evidence_ref": f"{evidence_prefix}%{code}: {entry.get('description', '')}"}
    p = Part(entry["field"], entry.get("class", "text"), "semantic", copy.deepcopy(entry.get("coerce")), None, [], entry.get("unmapped_name"), [], "vendor-table")
    if entry.get("attribute"):
        pv = dict(prov)
        if entry["field"] in cert_for_field:
            pv["certificate_id"] = cert_for_field[entry["field"]]
        p.mappings.append(Mapping(entry["attribute"], pv, copy.deepcopy(entry.get("transform")), entry["attribute"] in mandatory))
    for also in entry.get("also", []):
        p.mappings.append(Mapping(also["attribute"], {**prov, "evidence_ref": f"{evidence_prefix}%{code}: {also.get('description', '')}"},
                                  copy.deepcopy(also.get("transform")), also["attribute"] in mandatory))
    return p


def apply_logformat(plan: Plan, directive: str, vendor: str, mandatory: set[str], operator_id: str, cert_for_slot: dict[int, str]) -> tuple[Plan, list[str]]:
    """Rewrite the plan from the operator-supplied logformat directive. Returns the new plan and the
    list of fields resolved. Fails loudly when the directive's arity does not match the samples."""
    table = load_vendor_table(vendor)
    slots = lex_logformat(directive)
    if len(slots) != len(plan.slots):
        raise ValueError(f"logformat has {len(slots)} slots but the induced structure has {len(plan.slots)}: the directive does not describe these samples")
    new = copy.deepcopy(plan)
    new.null_values = list(table.get("null_values", []))
    new.source_timezone = table.get("source_timezone")
    new.timezone_confidence = table.get("timezone_confidence", "unresolved")
    resolved: list[str] = []
    for slot, parts in zip(new.slots, slots):
        codes = [t for k, t in parts if k == "code"]
        lits = [t for k, t in parts if k == "lit"]
        cert_for_field = {}
        for p in slot.parts:
            if slot.index in cert_for_slot:
                cert_for_field[p.field] = cert_for_slot[slot.index]
        key = ".".join(codes) if lits == ["."] * (len(codes) - 1) and len(codes) > 1 else None
        if key and key in table.get("compounds", {}):
            entry = table["compounds"][key]
            part = _part_from_code(key, entry, mandatory, "logformat ", {})
            if slot.index in cert_for_slot:
                for m in part.mappings:
                    m.provenance["certificate_id"] = cert_for_slot[slot.index]
            slot.parts, slot.split = [part], None
        elif len(codes) == 1:
            entry = table["codes"].get(codes[0])
            if entry is None:
                raise ValueError(f"vendor table has no entry for %{codes[0]}")
            part = _part_from_code(codes[0], entry, mandatory, "logformat ", {})
            if slot.index in cert_for_slot:
                for m in part.mappings:
                    m.provenance["certificate_id"] = cert_for_slot[slot.index]
            slot.parts, slot.split = [part], None
        else:
            sep = set(lits)
            if len(sep) != 1 or len(next(iter(sep))) != 1:
                raise ValueError(f"unsupported compound slot {parts!r}")
            slot.split = next(iter(sep))
            slot.parts = []
            for c in codes:
                entry = table["codes"].get(c)
                if entry is None:
                    raise ValueError(f"vendor table has no entry for %{c}")
                part = _part_from_code(c, entry, mandatory, "logformat ", {})
                if slot.index in cert_for_slot:
                    for m in part.mappings:
                        m.provenance["certificate_id"] = cert_for_slot[slot.index]
                slot.parts.append(part)
        resolved.extend(p.field for p in slot.parts)
    sev = table.get("severity_id")
    if sev:
        new.constants = [Mapping("severity_id", {"category": "operator_assertion", "operator_id": operator_id, "evidence_ref": sev["note"]},
                                 {"constant": sev["constant"]}, False)]
    return new, resolved


def apply_operator_assertion(plan: Plan, field: str, attribute: str, operator_id: str, note: str, mandatory: set[str]) -> Plan:
    new = copy.deepcopy(plan)
    for _, p in new.parts():
        if p.field == field:
            p.mappings = [Mapping(attribute, {"category": "operator_assertion", "operator_id": operator_id, "evidence_ref": note}, None, attribute in mandatory)]
            p.candidates = []
            return new
    raise KeyError(field)


def apply_labelled_session(plan: Plan, sample_line: str, initiator_ip: str, mandatory: set[str], operator_id: str, cert_id: str | None) -> tuple[Plan, str]:
    """operator_labelled_session: the operator names one line and the address that initiated it. The
    slot holding that address is the source endpoint; the other IPv4 slot is the destination. Fails when
    the address appears in zero or several slots."""
    toks = sample_line.split()
    hits = [i for i, t in enumerate(toks) if t == initiator_ip or t.endswith("/" + initiator_ip)]
    if len(hits) != 1:
        raise ValueError(f"initiator address appears in {len(hits)} slots; the sample does not discriminate")
    new = copy.deepcopy(plan)
    slot = new.slots[hits[0]]
    prov = {"category": "validated_discriminator", "discriminator_id": "operator_labelled_session", "operator_id": operator_id,
            "evidence_ref": f"operator-labelled session: {initiator_ip} was the initiator in the supplied line"}
    if cert_id:
        prov["certificate_id"] = cert_id
    part = slot.parts[-1]
    part.mappings = [Mapping("src_endpoint.ip", prov, None, "src_endpoint.ip" in mandatory)]
    part.candidates = []
    return new, part.field


def mandatory_for(plan: Plan) -> set[str]:
    from .acceptance import policy_for
    return set(policy_for(plan.event_class_uid)["mandatory_attributes"])


_ = re  # kept for lexer extension
