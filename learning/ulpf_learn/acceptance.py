"""Acceptance policy engine (architecture §3.3, P1/P2/P3 boundary decisions).

Promotion requires: every sample parses with 100% byte coverage; semantic coverage at or above the
class budget; every mandatory attribute mapped with SUFFICIENT provenance — a proposal from the
model/fixture alone is never sufficient (invariant 4); structural determination is granted only when
the deterministic enumerator leaves exactly one survivor, and the enumerated set is recorded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import dslexec
from .enumerate_ import enumerate_candidates
from .plan import MODEL_PROVENANCES, SUFFICIENT, Plan

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "acceptance" / "policy-v1.json").read_text(encoding="utf-8"))


def policy_for(class_uid: int) -> dict:
    return POLICY["classes"][str(class_uid)]


@dataclass
class Coverage:
    samples: int
    parsed: int
    byte_coverage: float
    semantic_coverage: float
    held_out_samples: int
    held_out_passed: int
    failures: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    promotable: bool
    coverage: Coverage
    critical_coverage: float
    blockers: list[str]
    provenance_report: list[dict]     # per mandatory attribute: attribute, path, category, sufficient
    determinations: list[dict]        # structural determinations granted, with enumerated sets


def run_coverage(spec: dict, samples: list[bytes], held_out_fraction: float = 0.25) -> tuple[Coverage, list[dict]]:
    prog = dslexec.compile_spec(json.dumps(spec).encode("utf-8"))
    maps, fails = [], []
    for i, line in enumerate(samples):
        m = prog.parse(line)
        maps.append(m)
        if m["status"] != "ok":
            fails.append(f"sample {i + 1}: at {m['failure']['at_offset']}: {m['failure']['reason']}")
    ok = [m for m in maps if m["status"] == "ok"]
    total = sum(m["event"]["raw_length"] for m in ok) or 1
    literal = sum(s["end"] - s["start"] for m in ok for s in m["spans"] if s["kind"] == "literal")
    semantic = sum(s["end"] - s["start"] for m in ok for s in m["spans"] if s["kind"] == "semantic" and not s.get("declared_null"))
    extractable = max(total - literal, 1)
    n_held = max(1, int(len(samples) * held_out_fraction)) if len(samples) > 1 else 0
    held = maps[len(maps) - n_held:] if n_held else []
    cov = Coverage(len(samples), len(ok), 1.0 if len(ok) == len(samples) else len(ok) / len(samples), semantic / extractable,
                   n_held, sum(1 for m in held if m["status"] == "ok"), fails)
    return cov, maps


def evaluate(plan: Plan, spec: dict, samples: list[bytes]) -> Verdict:
    pol = policy_for(plan.event_class_uid)
    mandatory = list(pol["mandatory_attributes"])
    cov, _ = run_coverage(spec, samples)
    blockers: list[str] = []
    if cov.parsed != cov.samples:
        blockers.append(f"{cov.samples - cov.parsed} of {cov.samples} samples fail to parse")
    if cov.semantic_coverage < pol["semantic_budget"]:
        blockers.append(f"semantic coverage {cov.semantic_coverage:.2f} below class budget {pol['semantic_budget']}")
    mapped: dict[str, tuple] = {}
    for slot, part in plan.parts():
        for m in part.mappings:
            mapped[m.attribute] = (slot, part, m)
    for m in plan.constants:
        mapped[m.attribute] = (None, None, m)
    report, determinations = [], []
    sufficient_count = 0
    for attr in mandatory:
        if attr not in mapped:
            report.append({"attribute": attr, "path": None, "category": None, "sufficient": False, "reason": "not mapped"})
            blockers.append(f"mandatory attribute {attr} is not mapped")
            continue
        slot, part, m = mapped[attr]
        cat = m.provenance.get("category")
        if cat in SUFFICIENT:
            sufficient_count += 1
            report.append({"attribute": attr, "path": part.field if part else None, "category": cat, "sufficient": True})
            continue
        # model/fixture proposal alone: try structural determination over the enumerator (never over the proposal)
        if part is not None:
            en = enumerate_candidates(plan.event_class_uid, part.cls, slot.samples if slot else [])
            if len(en.survivors) == 1 and en.survivors[0] == attr:
                m.provenance = {"category": "structural_determination", "enumerated_survivors": list(en.survivors)}
                sufficient_count += 1
                determinations.append({"attribute": attr, "path": part.field, "enumeration": en.record()})
                report.append({"attribute": attr, "path": part.field, "category": "structural_determination", "sufficient": True})
                continue
            report.append({"attribute": attr, "path": part.field, "category": cat, "sufficient": False,
                           "reason": f"{cat} alone is not sufficient for a mandatory field; enumeration left {len(en.survivors)} survivors"})
        else:
            report.append({"attribute": attr, "path": None, "category": cat, "sufficient": False, "reason": f"{cat} alone is not sufficient"})
        blockers.append(f"mandatory attribute {attr} rests on a {cat} only (invariant 4)")
    critical = sufficient_count / len(mandatory) if mandatory else 1.0
    return Verdict(not blockers, cov, critical, blockers, report, determinations)
