"""Family discovery ranking (plan §4 item 8, architecture §8.1 item 5a; the P8 demo opens with it).

    python tools/discover.py CAPTURE [CAPTURE...] [--json OUT]

Clusters a raw capture — no parser, no pack — by the same surface the runtime router reads: L1
envelope kind, L2 surface class, L3 anchor values located by the vendor tables' DECLARED anchors
(domain violations counted separately, as the drift signal they are), and an L4 sketch (arity, or the
token-class sequence for whitespace records). Ranks the clusters by volume, descending: the order in
which an operator onboards them buys the most coverage per evidence request. Reports what each cluster
looks like (a sample line, the located anchor) so the operator recognises it; it decides nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ulpf_learn import envelope, surface  # noqa: E402
from ulpf_learn.discriminators import VENDOR_TABLES, load_vendor_table  # noqa: E402


_SURFACE = {"csv": "csv", "kv": "kv", "json": "json"}


def declared_anchors() -> list[tuple[str, dict]]:
    """(vendor, anchor) pairs; each anchor carries the surface classes its vendor's families live in, so a
    slot/key locator is never read against another vendor's surface (the runtime router scopes the same way)."""
    out = []
    for vendor in VENDOR_TABLES:
        t = load_vendor_table(vendor)
        l2s = {_SURFACE.get(f.get("l2", "positional"), "tokens") for f in (t.get("families") or {}).values()} or {"tokens"}
        for a in t.get("anchors", []):
            out.append((vendor, {**a, "_l2s": sorted(l2s)}))
    return out


def signature(raw: bytes, anchors: list[tuple[str, dict]]) -> tuple[str, dict]:
    e = envelope.unwrap(raw)
    payload = raw[e["payload_offset"]:e["payload_offset"] + e["payload_length"]]
    s = surface.detect(payload)
    l1 = e["kind"] if e["kind"] != "none" else "raw"
    located, drift = [], []
    for vendor, a in anchors:
        if s.l2 not in a["_l2s"] and a["locator"]["kind"] != "envelope_header":
            continue
        v = surface.locate(a, payload, s, e)
        if v is None:
            continue
        (located if surface.in_domain(a, v) else drift).append(f"{a['anchor_id']}={v}")
    if s.l2 == "tokens":
        l4 = ",".join(surface.classify(t) for t in s.toks)
        sketch = f"{s.arity}:{l4}"
    else:
        sketch = str(s.arity)
    key = f"{l1}|{s.l2}|{','.join(sorted(located))}|{sketch if s.l2 == 'tokens' else s.l2 + ':' + bucket(s.arity)}"
    return key, {"l1": l1, "l2": s.l2, "anchors": sorted(located), "drift": sorted(drift), "arity": s.arity, "payload": payload}


def bucket(n: int) -> str:
    """Coarse arity bucket for csv/kv so version-dependent field counts (PAN-OS 46/65/75/105) cluster together."""
    lo = (n // 20) * 20
    return f"{lo}-{lo + 19}"


def rank(paths: list[Path]) -> list[dict]:
    anchors = declared_anchors()
    clusters: dict[str, dict] = {}
    for path in paths:
        for raw in path.read_bytes().split(b"\n"):
            raw = raw.rstrip(b"\r")
            if not raw.strip():
                continue
            key, info = signature(raw, anchors)
            c = clusters.setdefault(key, {"key": key, "count": 0, "l1": info["l1"], "l2": info["l2"], "anchors": info["anchors"],
                                          "arities": Counter(), "drift": Counter(), "sample": info["payload"][:160].decode("utf-8", "replace"), "files": Counter()})
            c["count"] += 1
            c["arities"][info["arity"]] += 1
            c["files"][path.name] += 1
            for d in info["drift"]:
                c["drift"][d] += 1
    out = sorted(clusters.values(), key=lambda c: (-c["count"], c["key"]))
    total = sum(c["count"] for c in out)
    cum = 0
    for i, c in enumerate(out, 1):
        cum += c["count"]
        c["rank"], c["share"], c["cumulative_share"] = i, round(c["count"] / total, 4), round(cum / total, 4)
        c["arities"] = dict(sorted(c["arities"].items()))
        c["drift"] = dict(c["drift"])
        c["files"] = dict(c["files"])
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--json", help="write the ranking as JSON")
    ap.add_argument("--top", type=int, default=25)
    a = ap.parse_args(argv)
    ranking = rank([Path(p) for p in a.captures])
    print(f"{'#':>3} {'events':>7} {'share':>6} {'cum':>6}  {'L1':<8} {'L2':<7} anchors / arity                     sample")
    for c in ranking[:a.top]:
        anchors = ",".join(c["anchors"]) or "-"
        ar = "/".join(str(k) for k in list(c["arities"])[:3])
        print(f"{c['rank']:>3} {c['count']:>7} {c['share']:>6.1%} {c['cumulative_share']:>6.1%}  {c['l1']:<8} {c['l2']:<7} {anchors[:22]:<22} {ar:<12} {c['sample'][:60]}")
        if c["drift"]:
            print(f"{'':>34}drift signals: {c['drift']}")
    if a.json:
        Path(a.json).write_text(json.dumps(ranking, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
