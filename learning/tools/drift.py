"""Drift monitor (detection only — architecture §3.6: healing is semi-automatic, a human re-onboards).

    python tools/drift.py --quarantine Q.jsonl --stats STATS.json [--json OUT]
    python tools/drift.py --quarantine Q.jsonl --stats STATS.json --evidence EVDIR --extract asa-message-id=302015 --out samples.log

Reads what the runtime already wrote — the quarantine records and the run's stats — and turns them into the
three signals the plan names, each with the action a HUMAN takes. It decides nothing and onboards nothing:

  re-onboard candidate   an anchor located a value INSIDE its declared domain that no onboarded family owns
                         (the vendor's documented message, not yet onboarded; or a format that changed its id).
                         Action: collect samples, onboard through the same path as any source.
  domain violation       an anchor located a value OUTSIDE its declared domain. Never a candidate: it is either
                         an undocumented message or an attack on the router. Action: investigate; stays quarantined.
  parse-success drop     events routed to a family and refused by its parser, per family signature.
  unknown signature      events no family matches at all, grouped by signature.

`--extract` pulls the RAW BYTES of the quarantined events behind one candidate out of the evidence store (by the
quarantine record's segment, offset and length, checked against its raw_hash) as onboarding samples: the
evidence log is what makes healing possible at all — the bytes were retained when nothing could read them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

_UNOWNED = re.compile(r"no onboarded family owns it \(([^)]*)\)")
_VIOLATION = re.compile(r"anchor (\S+) located \"([^\"]*)\" outside its declared domain")


def signals(q: list[dict], stats: dict) -> dict:
    frames = stats.get("frames") or 0
    cand: dict[str, list[dict]] = defaultdict(list)
    viol: dict[str, list[dict]] = defaultdict(list)
    parse: dict[str, list[dict]] = defaultdict(list)
    unknown: dict[str, list[dict]] = defaultdict(list)
    other = Counter()
    for r in q:
        stage, reason = r["stage"], r["reason"]
        if stage == "routing_drift":
            for a, v in _VIOLATION.findall(reason):
                viol[f"{a}={v}"].append(r)
        elif stage == "routing" and _UNOWNED.search(reason):
            for kv in _UNOWNED.search(reason).group(1).split(","):
                cand[kv.strip()].append(r)
        elif stage == "routing":
            unknown[r.get("routing_signature", "?")].append(r)
        elif stage in ("parse", "tiling", "normalize"):
            parse[r.get("routing_signature", "?")].append(r)
        else:
            other[stage] += 1
    def rows(d):
        return [{"key": k, "events": len(v), "share_of_frames": round(len(v) / frames, 4) if frames else None, "event_ids": [x["event_id"] for x in v][:20]} for k, v in sorted(d.items(), key=lambda kv: -len(kv[1]))]
    return {"frames": frames, "emitted": stats.get("emitted"), "quarantined": stats.get("quarantined"),
            "reonboard_candidates": rows(cand), "domain_violations": rows(viol), "parse_success_drop": rows(parse), "unknown_signatures": rows(unknown),
            "other_quarantine_stages": dict(other)}


def extract(q: list[dict], key: str, evidence: Path) -> list[bytes]:
    out = []
    for r in q:
        m = _UNOWNED.search(r["reason"]) if r["stage"] == "routing" else None
        if not m or key not in [kv.strip() for kv in m.group(1).split(",")]:
            continue
        raw = (evidence / f"{r['segment_id']}.raw").read_bytes()[r["offset"]:r["offset"] + r["length"]]
        if "sha256:" + hashlib.sha256(raw).hexdigest() != r["raw_hash"]:
            raise SystemExit(f"evidence bytes of {r['event_id']} do not match the quarantine record's raw_hash — refusing to use them as samples")
        out.append(raw)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--quarantine", required=True); ap.add_argument("--stats", required=True)
    ap.add_argument("--json"); ap.add_argument("--evidence"); ap.add_argument("--extract", help="anchor=value of a re-onboard candidate"); ap.add_argument("--out")
    a = ap.parse_args(argv)
    q = [json.loads(l) for l in Path(a.quarantine).read_text(encoding="utf-8").splitlines() if l.strip()]
    stats = json.loads(Path(a.stats).read_text(encoding="utf-8"))
    if len(q) != stats.get("quarantined"):
        print(f"quarantine file holds {len(q)} records, stats say {stats.get('quarantined')}: refusing to report on a partial file", file=sys.stderr)
        return 1
    if a.extract:
        if not (a.evidence and a.out):
            ap.error("--extract needs --evidence and --out")
        lines = extract(q, a.extract, Path(a.evidence))
        if not lines:
            print(f"no quarantined event is a re-onboard candidate for {a.extract}", file=sys.stderr)
            return 1
        Path(a.out).write_bytes(b"".join(l.rstrip(b"\r\n") + b"\n" for l in lines))
        print(f"extracted {len(lines)} quarantined event(s) for {a.extract} from the evidence store (raw_hash checked) -> {a.out}")
        return 0
    s = signals(q, stats)
    print(f"frames {s['frames']}  emitted {s['emitted']}  quarantined {s['quarantined']}")
    for title, key, action in (("RE-ONBOARD CANDIDATE", "reonboard_candidates", "in the declared domain, owned by no family: collect samples, onboard through the usual path"),
                               ("DOMAIN VIOLATION", "domain_violations", "outside the declared domain: investigate; never onboarded from this signal"),
                               ("PARSE-SUCCESS DROP", "parse_success_drop", "routed, then refused by the family's parser: the format moved under a known signature"),
                               ("UNKNOWN SIGNATURE", "unknown_signatures", "no family matches: family discovery input")):
        for r in s[key]:
            print(f"  {title:<21} {r['key'][:70]:<40} {r['events']:>4} event(s)  — {action}")
    if a.json:
        Path(a.json).write_text(json.dumps(s, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
