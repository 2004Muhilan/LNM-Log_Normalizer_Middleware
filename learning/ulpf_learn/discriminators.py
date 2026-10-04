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
    new.timezone_field = table.get("timezone_field")   # vendor schema evidence: the key the device states its offset in
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


_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$")
# ISO 8601 with a BASIC offset (+0000, +0530) — not RFC 3339, which needs the colon. Suricata's EVE writes it
# (2026-09-30: "2026-09-29T17:01:40.291297+0000"). The existing `pattern` kind expresses it on both stacks; %z takes
# +HHMM and +HH:MM alike.
_ISO_BASIC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?[+-][0-9]{4}$")


def coercion_for(class_uid: int, attribute: str, token_class: str, samples: list[str]) -> dict | None:
    """The value coercion an asserted mapping needs, derived deterministically from the PINNED OCSF type of the
    attribute and the slot's observed token class — never from a proposal. An operator who says "this column is
    `time`" has said it is a timestamp; without this the cell stays a string and the event carries the sensor's text
    (found with the live demo: `"time": "1789900220.082"`, lineage event_time 0). None = no coercion can be derived
    (a textual timestamp that is not RFC 3339, a type with no coercion): the value stays a string, as before."""
    from .enumerate_ import load_table
    t = next((l.get("type") for l in load_table(class_uid)["leaf_paths"] if l["path"] == attribute), None)
    if t in ("timestamp_t", "datetime_t"):
        if token_class == "float":
            return {"op": "coerce", "to": "timestamp", "format": {"kind": "epoch_s_frac", "timezone": "utc"}, "on_failure": "reject"}
        if token_class == "integer":
            return {"op": "coerce", "to": "timestamp", "format": {"kind": "epoch_auto", "timezone": "utc"}, "on_failure": "reject"}
        if samples and all(_RFC3339.match(s) for s in samples):
            return {"op": "coerce", "to": "timestamp", "format": {"kind": "rfc3339"}, "on_failure": "reject"}
        if samples and all(_ISO_BASIC.match(s) for s in samples):
            frac = {bool(_ISO_BASIC.match(s).group(1)) for s in samples}
            fmts = [{"kind": "pattern", "pattern": "%Y-%m-%dT%H:%M:%S" + (".%f" if f else "") + "%z", "timezone": "in_value"} for f in sorted(frac, reverse=True)]
            return {"op": "coerce", "to": "timestamp", **({"format": fmts[0]} if len(fmts) == 1 else {"formats": fmts}), "on_failure": "reject"}
        return None
    if t in ("integer_t", "long_t", "port_t") and token_class == "integer":
        return {"op": "coerce", "to": "int", "on_failure": "reject"}
    if t == "float_t" and token_class in ("float", "integer"):
        return {"op": "coerce", "to": "float", "on_failure": "reject"}
    if t == "ip_t" and token_class in ("ipv4", "ipv6", "ip"):
        return {"op": "coerce", "to": "ip", "on_failure": "reject"}
    return None


def apply_operator_assertion(plan: Plan, field: str, attribute: str, operator_id: str, note: str, mandatory: set[str], lookup: dict | None = None) -> Plan:
    """The operator states what a field is. With `lookup` (2026-09-30) the operator also states how its values map onto an
    enum attribute — FortiGate's status="success"/"failed" onto status_id 1/2 — as the vendor tables do (transform kind
    lookup, parser-pack 1.3.0); the map is part of the recorded assertion. Values outside it take `default` (99, Other)."""
    new = copy.deepcopy(plan)
    transform = None
    if lookup:
        table = {str(k): int(v) for k, v in (lookup.get("lookup") or lookup).items() if k != "default"}
        transform = {"kind": "lookup", "lookup": table, "default": int(lookup.get("default", 99))}
        note = f"{note} [value map stated by the operator: {', '.join(f'{k}={v}' for k, v in table.items())}; otherwise {transform['default']}]"
    for slot, p in new.parts():
        if p.field == field and attribute == "unmapped":
            # the operator says: this field is none of the class's attributes — carry it under OCSF's `unmapped` object by its
            # own name (what withholding does to a field nobody answered; here it is the operator's decision, 2026-10-02)
            p.mappings, p.candidates, p.unmapped_name, p.coerce = [], [], p.field, None
            return new
        if p.field == field:
            p.mappings = [Mapping(attribute, {"category": "operator_assertion", "operator_id": operator_id, "evidence_ref": note}, transform, attribute in mandatory)]
            p.candidates = []
            p.unmapped_name = None   # the provider's "carry it unmapped" no longer applies: the operator said what it is
            if p.coerce is None and transform is None:   # a looked-up value stays text: the lookup makes the enum
                p.coerce = coercion_for(new.event_class_uid, attribute, p.cls, slot.samples)
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


# ---------------------------------------------------------------- vendor_schema_field_order (P6)

VENDOR_TABLES.update({
    "cisco-asa": ROOT / "library" / "vendor-tables" / "cisco-asa.yaml",
    "paloalto-panos": ROOT / "library" / "vendor-tables" / "panos-traffic.yaml",
    "fortinet-fortigate": ROOT / "library" / "vendor-tables" / "fortigate-traffic.yaml",
})


def apply_vendor_schema(plan: Plan, vendor: str, family_id: str, mandatory: set[str], operator_id: str, cert_for_slot: dict[int, str]) -> tuple[Plan, list[str]]:
    """vendor_schema_field_order: the vendor's field-order documentation names every field of a
    structured format (ASA message guide, PAN-OS field reference, FortiOS log reference). The plan's
    parts carry the spec's field names (hand-authored draft or kv keys); each name found in the vendor
    table is resolved with provenance vendor_schema_or_device_configuration. Names the table does not
    know stay unevidenced — the table never guesses. Per-family constants (action_id, severity_id,
    activity_id) and envelope-sourced mappings (ASA's time from the syslog header) come from the table too."""
    table = load_vendor_table(vendor)
    fam = (table.get("families") or {}).get(family_id, {})
    doc = table.get("document", vendor)
    new = copy.deepcopy(plan)
    new.family_id = family_id
    new.null_values = list(table.get("null_values", []))
    new.source_timezone = table.get("source_timezone")
    new.timezone_confidence = table.get("timezone_confidence", "unresolved")
    new.timezone_field = table.get("timezone_field")   # vendor schema evidence: the key the device states its offset in
    resolved: list[str] = []
    for slot, part in new.parts():
        entry = table["fields"].get(part.field)
        if entry is None:
            continue
        prov = {"category": "vendor_schema_or_device_configuration", "discriminator_id": "vendor_schema_field_order",
                "evidence_ref": f"{doc}: {part.field}" + (f" — {entry['description']}" if entry.get("description") else "")}
        if slot.index in cert_for_slot:
            prov["certificate_id"] = cert_for_slot[slot.index]
        part.mappings = []
        part.candidates = []
        part.unmapped_name = entry.get("unmapped_name")
        if entry.get("attribute"):
            part.mappings.append(Mapping(entry["attribute"], dict(prov), copy.deepcopy(entry.get("transform")), bool(entry.get("mandatory")) or entry["attribute"] in mandatory))
        for also in entry.get("also", []):
            part.mappings.append(Mapping(also["attribute"], {**prov, "evidence_ref": f"{doc}: {part.field} — {also.get('description', '')}"},
                                         copy.deepcopy(also.get("transform")), bool(also.get("mandatory")) or also["attribute"] in mandatory))
        resolved.append(part.field)
    new.constants = []
    for attr in ("action_id", "severity_id", "activity_id"):
        if fam.get(attr) is not None:
            new.constants.append(Mapping(attr, {"category": "vendor_schema_or_device_configuration", "discriminator_id": "vendor_schema_field_order",
                                               "evidence_ref": f"{doc}: {family_id} {attr} is fixed by the message/log type"},
                                         {"constant": fam[attr]}, attr in mandatory))
    new.envelope_mappings = []
    for field_name, e in (table.get("envelope_fields") or {}).items():
        from .plan import EnvelopeMapping
        new.envelope_mappings.append(EnvelopeMapping(field_name, e["attribute"],
                                                     {"category": "vendor_schema_or_device_configuration", "discriminator_id": "vendor_schema_field_order",
                                                      "evidence_ref": f"{doc}: {e.get('description', field_name)}"},
                                                     copy.deepcopy(e.get("transform")), bool(e.get("mandatory")) or e["attribute"] in mandatory))
    return new, resolved


def vendor_table_meta(vendor: str, family_id: str) -> dict:
    """Pack-level facts the vendor table declares: source identity, anchors, and the family's routing declaration."""
    table = load_vendor_table(vendor)
    fam = (table.get("families") or {}).get(family_id, {})
    return {"vendor": table.get("vendor"), "product": table.get("product"), "declared_envelope": table.get("declared_envelope", "raw"),
            "transport_hint": table.get("transport_hint", "file"), "anchors": table.get("anchors", []), "family": fam}
