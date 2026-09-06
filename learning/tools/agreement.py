"""Agreement with a mature reference parser (plan §5.2; decided in P1, tooling built in P6, measured in P8).

    python tools/agreement.py --normalized OUT.jsonl --expected corpus/cache/<vendor>/<file>-expected.json [--crosswalk library/crosswalk/ecs-ocsf.yaml] [--json REPORT]

For every ULPF event, the reference event is the one whose `event.original` (or `message`) equals the
payload ULPF parsed (matched through the evidence record's raw bytes when given `--raw`); for every
crosswalk row present on both sides the values are compared under the row's `compare` rule. Output:
per-attribute agree / disagree / reference-only / ulpf-only counts and the disagreeing pairs, so each
can be hand-adjudicated against vendor documentation. **Agreement is an effort metric about how far the
two parsers read the same line the same way — not a correctness metric**; the reference is one
production parser's opinion, and the crosswalk's own errors are a third source of disagreement, which is
why the crosswalk is reviewed separately from the parsers.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
VENDOR_NS = {"cisco", "panw", "fortinet", "squid"}


def get(d: dict, dotted: str):
    cur = d
    for k in dotted.split("."):
        if not isinstance(cur, dict) or k not in cur:
            # ECS expected files are often flat with dotted keys
            return d.get(dotted) if dotted in d else None
        cur = cur[k]
    return cur


def norm(v, how: str):
    if v is None:
        return None
    if how == "ip":
        try:
            return str(ipaddress.ip_address(str(v)))
        except ValueError:
            return str(v)
    if how == "int":
        try:
            return int(v)
        except (TypeError, ValueError):
            return str(v)
    if how == "lower":
        return str(v).lower()
    if how == "epoch_ms":
        if isinstance(v, (int, float)):
            return int(v)
        try:
            return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            return str(v)
    return str(v)


def compare(rows: list[dict], ref: dict, ev: dict) -> list[tuple[str, str, str, object, object]]:
    """Per row: (ecs, ocsf, verdict, ref_value, ulpf_value). verdict: agree | disagree | reference_only | ulpf_only | known_mismatch_class"""
    out = []
    namespaces = {k.split(".")[0] for k in ref}
    for r in rows:
        if not r.get("ocsf") or r["ecs"].endswith("*"):
            continue
        ns = r["ecs"].split(".")[0]
        if ns in VENDOR_NS and ns not in namespaces:
            continue  # another vendor's namespace: this reference cannot have the field
        rv, uv = get(ref, r["ecs"]), get(ev, r["ocsf"])
        if rv is None and uv is None:
            continue
        if uv is None:
            out.append((r["ecs"], r["ocsf"], "reference_only", rv, None))
            continue
        if rv is None:
            out.append((r["ecs"], r["ocsf"], "ulpf_only", None, uv))
            continue
        how = r.get("compare", "exact")
        if how == "set-of-known-mismatch":
            out.append((r["ecs"], r["ocsf"], "known_mismatch_class", rv, uv))
            continue
        a, b = norm(rv, how), norm(uv, how)
        if how == "epoch_ms" and isinstance(a, int) and isinstance(b, int) and a != b:
            # Two known mismatch classes, neither a parser disagreement: (1) timezone assumption — the reference applied
            # a zone the line does not carry (Filebeat's test harness pins one), ULPF's pack says timezone_confidence
            # unresolved and keeps the wall clock; (2) year assumption — a year-less header resolved with different
            # clocks. Both show as the same wall-clock digits.
            tb = datetime.fromtimestamp(b / 1000, timezone.utc)
            try:
                wall = datetime.fromisoformat(str(rv).replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                wall = datetime.fromtimestamp(a / 1000, timezone.utc).replace(tzinfo=None)
            same_clock = (wall.month, wall.day, wall.hour, wall.minute, wall.second) == (tb.month, tb.day, tb.hour, tb.minute, tb.second)
            if same_clock:
                out.append((r["ecs"], r["ocsf"], "known_mismatch_class", rv, uv))
                continue
        if how == "lower" and r["ecs"] == "network.direction":
            a, b = str(a)[:2], str(b)[:2]
        if how == "suffix":
            a, b = str(rv), str(uv)[-len(str(rv)):] if str(uv).endswith(str(rv)) else str(uv)
        out.append((r["ecs"], r["ocsf"], "agree" if a == b else "disagree", rv, uv))
    return out


def load_expected(path: Path) -> dict[str, dict]:
    docs = json.loads(path.read_text(encoding="utf-8"))
    by_line = {}
    for d in docs:
        line = d.get("event.original") or d.get("message") or get(d, "event.original") or get(d, "message")
        if line is not None:
            by_line[line.strip()] = d
    return by_line


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--normalized", required=True)
    ap.add_argument("--expected", required=True, action="append")
    ap.add_argument("--raw", help="the raw input the runtime consumed (to pair events with reference lines by payload)")
    ap.add_argument("--crosswalk", default=str(ROOT / "library" / "crosswalk" / "ecs-ocsf.yaml"))
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    rows = yaml.safe_load(Path(a.crosswalk).read_text(encoding="utf-8"))["rows"]
    ref = {}
    for e in a.expected:
        ref.update(load_expected(Path(e)))
    raw_lines = [l.rstrip(b"\r").decode("utf-8", "replace") for l in Path(a.raw).read_bytes().split(b"\n") if l.strip()] if a.raw else None
    events = [json.loads(l) for l in Path(a.normalized).read_text(encoding="utf-8").splitlines() if l.strip()]
    tally: dict[str, Counter] = defaultdict(Counter)
    disagreements = []
    paired = 0
    for i, ev in enumerate(events):
        key = None
        if raw_lines is not None:
            # the evidence offset order equals the input order for a file replay; the raw line's payload
            # is what the reference indexed under event.original
            seq = ev["_lineage"].get("ingest_sequence")
            idx = seq if isinstance(seq, int) and seq < len(raw_lines) else i
            key = raw_lines[idx].strip()
            # the reference stores the message after its own header strip; try the tail forms
            cands = [key] + [key[j:].strip() for j in range(len(key)) if key[j] in "%<1d" and key[j:].strip() in ref]
            key = next((c for c in cands if c in ref), None)
        r = ref.get(key) if key else None
        if r is None:
            tally["_unpaired"]["events"] += 1
            continue
        paired += 1
        for ecs, ocsf, verdict, rv, uv in compare(rows, r, ev):
            tally[f"{ecs} -> {ocsf}"][verdict] += 1
            if verdict == "disagree":
                disagreements.append({"event_id": ev["_lineage"]["event_id"], "ecs": ecs, "ocsf": ocsf, "reference": rv, "ulpf": uv})
    print(f"events {len(events)}  paired with reference {paired}")
    print(f"{'attribute (ecs -> ocsf)':<58} {'agree':>6} {'disagr':>6} {'ref-only':>8} {'ulpf-only':>9} {'known-class':>11}")
    for k in sorted(tally):
        if k == "_unpaired":
            continue
        c = tally[k]
        print(f"{k:<58} {c['agree']:>6} {c['disagree']:>6} {c['reference_only']:>8} {c['ulpf_only']:>9} {c['known_mismatch_class']:>11}")
    tot = Counter()
    for k, c in tally.items():
        if k != "_unpaired":
            tot.update(c)
    comparable = tot["agree"] + tot["disagree"]
    print(f"\ncomparable pairs {comparable}: agree {tot['agree']}, disagree {tot['disagree']} "
          f"({(tot['agree'] / comparable if comparable else 0):.1%} agreement — an effort metric about two parsers reading alike, not correctness)")
    print(f"reference-only {tot['reference_only']}, ulpf-only {tot['ulpf_only']}, known mismatch classes {tot['known_mismatch_class']}, unpaired events {tally['_unpaired']['events']}")
    if a.json:
        Path(a.json).write_text(json.dumps({"events": len(events), "paired": paired, "tally": {k: dict(v) for k, v in tally.items()}, "disagreements": disagreements}, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
