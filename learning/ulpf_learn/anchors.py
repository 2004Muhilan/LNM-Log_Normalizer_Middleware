"""Anchor admission (architecture §3.4, plan §4/P6 exit criterion).

An anchor is a value the router may use to separate families of one source at L3. It is admitted on
exactly two grounds, both of which are evidence about the VALUE DOMAIN, not about the samples:

  declared_domain   — the vendor documentation (or device configuration) declares the set or pattern
                      of values the slot takes: an ASA message id, a PAN-OS log type, a FortiGate `type`;
  measured_utility  — across the families observed in the capture, the slot's value partitions the
                      families perfectly (every value belongs to exactly one family, every family has
                      at least one value), AND the domain has been observed on at least two families.

Sample cardinality alone NEVER admits an anchor. A slot that happens to hold one or two distinct values
in a small sample (a constant hostname, a rarely-changing zone name, `-`) is exactly what an implementer
reaches for first and exactly what drifts the moment the sample is not representative — the rejected
approach recorded in the architecture's revision notes. `admit` refuses it by name.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import re2


@dataclass
class Candidate:
    locator: dict                                   # pack anchor locator (kind slot|key|pattern|envelope_header + selector)
    observed_values: list[str]                      # distinct values seen across the capture
    values_by_family: dict[str, set[str]] = field(default_factory=dict)  # family_id -> values seen in that family
    declared_domain: dict | None = None             # {"kind": "enum", "values": [...]} or {"kind": "pattern", "pattern": ...}


@dataclass
class Decision:
    admitted: bool
    basis: str | None          # declared_domain | measured_utility | None
    reason: str
    anchor: dict | None = None # the pack anchor entry when admitted


def _domain_covers(domain: dict, values: list[str]) -> tuple[bool, list[str]]:
    if domain["kind"] == "enum":
        allowed = set(domain["values"])
        out = [v for v in values if v not in allowed]
        return not out, out
    rx = re2.compile(domain["pattern"])
    out = [v for v in values if not rx.fullmatch(v)]
    return not out, out


def admit(anchor_id: str, c: Candidate) -> Decision:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", anchor_id):
        return Decision(False, None, "anchor_id must be a slug")
    if c.declared_domain:
        ok, outside = _domain_covers(c.declared_domain, c.observed_values)
        if not ok:
            return Decision(False, None, f"declared domain does not cover observed values {outside[:5]} — the observation contradicts the declaration; this is a drift signal, not an admission")
        return Decision(True, "declared_domain", "value domain declared by vendor documentation / device configuration",
                        {"anchor_id": anchor_id, "locator": c.locator, "expected_value_domain": c.declared_domain,
                         "observed_cardinality": len(set(c.observed_values)), "anchor_status": "active", "admission_basis": "declared_domain"})
    fams = {f: set(v) for f, v in c.values_by_family.items() if v}
    if len(fams) >= 2:
        # perfect partition: no value shared by two families
        owner: dict[str, str] = {}
        clash = None
        for f, vals in fams.items():
            for v in vals:
                if v in owner and owner[v] != f:
                    clash = (v, owner[v], f)
                owner[v] = f
        if clash is None:
            values = sorted(owner)
            return Decision(True, "measured_utility", f"partitions {len(fams)} observed families perfectly ({len(values)} values)",
                            {"anchor_id": anchor_id, "locator": c.locator, "expected_value_domain": {"kind": "enum", "values": values},
                             "observed_cardinality": len(values), "anchor_status": "probation", "admission_basis": "measured_utility",
                             "utility_note": f"measured over {len(fams)} families; probation until a declared domain confirms it"})
        return Decision(False, None, f"value {clash[0]!r} appears in families {clash[1]} and {clash[2]}: no discriminative utility")
    n = len(set(c.observed_values))
    return Decision(False, None, f"refused: {n} distinct value(s) in the sample, no declared domain, one family observed — sample cardinality alone never admits an anchor")


def load_declared(table: dict) -> list[dict]:
    """Anchors a vendor table declares (declared_domain), as pack anchor entries."""
    out = []
    for a in table.get("anchors", []):
        out.append({"anchor_id": a["anchor_id"], "locator": a["locator"], "expected_value_domain": a["expected_value_domain"],
                    "observed_cardinality": 0, "anchor_status": "active", "admission_basis": a.get("admission_basis", "declared_domain"),
                    **({"utility_note": a["utility_note"]} if a.get("utility_note") else {})})
    return out
