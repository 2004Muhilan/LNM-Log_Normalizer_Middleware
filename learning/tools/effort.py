"""Operator effort per onboarded family, from the session timelines ULPF has recorded since P3 (plan §8.4).

    python tools/effort.py SESSION_DIR [SESSION_DIR ...] [--json OUT]

What is MEASURED (read from session.json, nothing else): fields in the family; certificates raised; evidence
requests issued; operator responses given; fields resolved per response; slots resolved by propagation with
no response; the provider's proposal time; whether the family promoted.

What is NOT measured anywhere in this project: a human's minutes. No analyst was timed — not on ULPF, not
on a hand-written parser. So the comparison is made in COUNTED DECISIONS, which both paths have:

    baseline (hand-authored parser + mapping)  = one mapping decision per semantic field, by definition
    ULPF                                       = operator responses + certificates the operator must read

and minutes appear only as a stated conversion with the assumption printed beside it (--minutes-per-decision,
--minutes-per-response); change the assumption and the figure changes. The sample is printed with every
aggregate: n families over m sources. Agreement with a reference parser is a different, separate measure
(tools/agreement.py) and is an effort metric too, not correctness.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def family(session_dir: Path) -> dict:
    s = json.loads((session_dir / "session.json").read_text(encoding="utf-8"))
    tl = s.get("timeline", [])
    parts = [p for slot in (s.get("plan") or {}).get("slots", []) for p in slot["parts"] if p.get("kind") == "semantic"]
    resolved_by_response = sum(len(r["fields"]) for r in s.get("resolutions", []))
    proposed = [e for e in tl if e["step"] == "proposed"]
    return {
        "session": session_dir.name, "source_id": s["source_id"], "family_id": s.get("family_id") or f"positional-{s['structure']['arity']}",
        "samples": s["sample_count"], "fields": len(parts), "mapped_fields": sum(1 for p in parts if p["mappings"]),
        "certificates": len(s.get("certificates", {})), "certificates_retained": sum(1 for c in s.get("certificates", {}).values() if c["status"] != "resolved"),
        "evidence_requests": sum(1 for e in tl if e["step"] == "request_issued"), "operator_responses": sum(1 for e in tl if e["step"] == "response_received"),
        "fields_resolved_by_responses": resolved_by_response, "slots_propagated": len(s.get("propagated", [])),
        "provider": (s.get("proposal") or {}).get("provider"), "proposal_seconds": proposed[0].get("seconds") if proposed else None,
        "promoted": s.get("state") == "promoted",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("sessions", nargs="+")
    ap.add_argument("--minutes-per-decision", type=float, default=None, help="ASSUMPTION: analyst minutes per hand-made mapping decision (baseline)")
    ap.add_argument("--minutes-per-response", type=float, default=None, help="ASSUMPTION: analyst minutes to find and supply one piece of evidence (ULPF)")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    rows = []
    for d in a.sessions:
        p = Path(d)
        if not (p / "session.json").exists():
            print(f"no session.json in {p}", file=sys.stderr)
            return 1
        rows.append(family(p))
    if not rows:
        return 1
    print(f"{'source':<18} {'family':<20} {'fields':>6} {'certs':>5} {'requests':>8} {'responses':>9} {'resolved/resp':>13} {'propagated':>10} {'proposal s':>10}  promoted")
    for r in rows:
        per = f"{r['fields_resolved_by_responses'] / r['operator_responses']:.0f}" if r["operator_responses"] else "-"
        print(f"{r['source_id']:<18} {r['family_id']:<20} {r['fields']:>6} {r['certificates']:>5} {r['evidence_requests']:>8} {r['operator_responses']:>9} {per:>13} {r['slots_propagated']:>10} "
              f"{(str(r['proposal_seconds']) if r['proposal_seconds'] is not None else '-'):>10}  {r['promoted']}")
    n, m = len(rows), len({r["source_id"] for r in rows})
    base = sum(r["fields"] for r in rows)
    ulpf = sum(r["operator_responses"] + r["certificates"] for r in rows)
    resp = sum(r["operator_responses"] for r in rows)
    print(f"\nSAMPLE: n={n} families over m={m} sources; every family promoted: {all(r['promoted'] for r in rows)}")
    print(f"baseline decisions (one per semantic field, by definition): {base}   [{base / n:.1f} per family, n={n}]")
    print(f"ULPF operator decisions (responses {resp} + certificates read {ulpf - resp}): {ulpf}   [{ulpf / n:.1f} per family, n={n}]")
    print(f"ratio {base / ulpf:.1f} : 1 in counted decisions over n={n} families / m={m} sources — an effort measure; it says nothing about whether any mapping is correct")
    per_source = {}
    for r in rows:
        ps = per_source.setdefault(r["source_id"], {"families": 0, "fields": 0, "responses": 0, "certificates": 0})
        ps["families"] += 1; ps["fields"] += r["fields"]; ps["responses"] += r["operator_responses"]; ps["certificates"] += r["certificates"]
    out = {"sample": {"families": n, "sources": m}, "rows": rows, "per_source": per_source, "baseline_decisions": base, "ulpf_decisions": ulpf}
    if a.minutes_per_decision is not None and a.minutes_per_response is not None:
        print(f"\nANALYST-MINUTES under STATED ASSUMPTIONS (not measured): {a.minutes_per_decision} min per baseline mapping decision, "
              f"{a.minutes_per_response} min per ULPF evidence response, certificates read at the per-decision rate")
        for src, ps in per_source.items():
            b = ps["fields"] * a.minutes_per_decision
            u = ps["responses"] * a.minutes_per_response + ps["certificates"] * a.minutes_per_decision
            print(f"  {src:<18} baseline {b:6.0f} min   ULPF {u:6.0f} min   (families n={ps['families']}, fields {ps['fields']}, responses {ps['responses']}, certificates {ps['certificates']})")
            ps["assumed_minutes"] = {"baseline": b, "ulpf": u}
        out["assumptions"] = {"minutes_per_decision": a.minutes_per_decision, "minutes_per_response": a.minutes_per_response, "measured": False}
    else:
        print("\n(no minutes printed: none were measured. Pass --minutes-per-decision and --minutes-per-response to convert under a stated assumption.)")
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
