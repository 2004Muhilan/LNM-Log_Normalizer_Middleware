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
    per_source = {}
    for r in rows:
        ps = per_source.setdefault(r["source_id"], {"families": 0, "fields": 0, "responses": 0, "certificates": 0, "propagated_slots": 0})
        ps["families"] += 1; ps["fields"] += r["fields"]; ps["responses"] += r["operator_responses"]; ps["certificates"] += r["certificates"]; ps["propagated_slots"] += r["slots_propagated"]
    # THE SPREAD, weakest first. No aggregate leads: a single ratio hides that the saving depends on how many
    # fields a family carries and how many families share structure — and the weakest case is where it gets asked about.
    for ps in per_source.values():
        ps["ulpf_decisions"] = ps["responses"] + ps["certificates"]
        ps["ratio"] = round(ps["fields"] / ps["ulpf_decisions"], 2) if ps["ulpf_decisions"] else None
        # break-even: with a baseline mapping decision and a certificate read both costing d minutes, ULPF is cheaper only
        # while one evidence response costs less than this many d (fields - certificates, shared over the responses)
        ps["break_even_response_cost_in_decisions"] = round((ps["fields"] - ps["certificates"]) / ps["responses"], 1) if ps["responses"] else None
    order = sorted(per_source.items(), key=lambda kv: (kv[1]["ratio"] is None, kv[1]["ratio"]))
    print(f"\nPER SOURCE, weakest first (counted decisions; n={n} families over m={m} sources; every family promoted: {all(r['promoted'] for r in rows)})")
    print(f"{'source':<18} {'families':>8} {'baseline':>9} {'responses':>9} {'certs':>6} {'ULPF':>5} {'ratio':>7}  break-even: one evidence response may cost up to")
    for src, ps in order:
        be = f"{ps['break_even_response_cost_in_decisions']} mapping decisions" if ps["break_even_response_cost_in_decisions"] is not None else "n/a"
        print(f"{src:<18} {ps['families']:>8} {ps['fields']:>9} {ps['responses']:>9} {ps['certificates']:>6} {ps['ulpf_decisions']:>5} {str(ps['ratio']) + ':1':>7}  {be}")
    lo, hi = order[0], order[-1]
    print(f"\nRANGE: {lo[1]['ratio']}:1 ({lo[0]}, {lo[1]['families']} families) to {hi[1]['ratio']}:1 ({hi[0]}, {hi[1]['families']} family/ies). The saving grows with fields per family and with structure shared "
          f"between families (propagation); a source of many small families, each needing its own evidence response and its own certificates, sits near break-even.")
    base = sum(r["fields"] for r in rows); ulpf = sum(ps["ulpf_decisions"] for ps in per_source.values())
    print(f"(pooled, for completeness only: {base} baseline decisions vs {ulpf}, {base / ulpf:.1f}:1 over n={n}/m={m} — dominated by the two wide single-family formats; do not quote without the range)")
    print("An effort measure. It says nothing about whether any mapping is correct; no analyst was timed.")
    out = {"sample": {"families": n, "sources": m}, "rows": rows, "per_source": per_source, "pooled": {"baseline_decisions": base, "ulpf_decisions": ulpf}}
    if a.minutes_per_decision is not None and a.minutes_per_response is not None:
        d_, r_ = a.minutes_per_decision, a.minutes_per_response
        print(f"\nMINUTES UNDER STATED ASSUMPTIONS (NOT MEASURED): {d_} min per mapping decision and per certificate read, {r_} min per evidence response")
        for src, ps in order:
            b = ps["fields"] * d_; u = ps["responses"] * r_ + ps["certificates"] * d_
            be = ps["break_even_response_cost_in_decisions"]
            verdict = "ULPF cheaper" if u < b else "ULPF DEARER than hand-authoring"
            print(f"  {src:<18} baseline {b:6.0f} min   ULPF {u:6.0f} min   {verdict} by {abs(b - u):.0f} min; flips when a response costs more than {be * d_:.0f} min" if be is not None else f"  {src:<18} baseline {b:6.0f} min   ULPF {u:6.0f} min")
            ps["assumed_minutes"] = {"baseline": b, "ulpf": u, "flips_above_response_minutes": be * d_ if be is not None else None}
        out["assumptions"] = {"minutes_per_decision": d_, "minutes_per_response": r_, "measured": False}
    else:
        print("\n(no minutes printed: none were measured. --minutes-per-decision and --minutes-per-response convert under a stated assumption.)")
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
