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

    python tools/drift.py --watch RUN_DIR [RUN_DIR ...] --json watch.json     # live: a windowed monitor over a RUNNING stream
    python tools/drift.py --quarantine Q.jsonl --evidence EVDIR --extract-signature 'raw|tokens||9|…' --out samples.log

`--watch` is the same monitor over a stream that has not ended: it re-reads the normalized output and the quarantine
file of every run directory (out.jsonl, q.jsonl — a restarted runtime is a new run directory over the same evidence
log), orders the records by event id, and reports PARSE SUCCESS over the last --window frames: usable events over
frames. Below --threshold it FIRES and names what the window's quarantine consists of (unknown signature / routed and
refused / domain violation); back above it, it says RECOVERED. It still decides nothing and onboards nothing.

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


def extract_signature(q: list[dict], sig: str, evidence: Path, limit: int) -> list[bytes]:
    """The raw bytes of quarantined events of ONE unknown signature, out of the evidence store, raw_hash checked:
    the onboarding samples for a source (or a changed format) that nothing could read when it arrived."""
    out = []
    for r in q:
        if r["stage"] != "routing" or r.get("routing_signature") != sig or _UNOWNED.search(r["reason"]):
            continue
        raw = (evidence / f"{r['segment_id']}.raw").read_bytes()[r["offset"]:r["offset"] + r["length"]]
        if "sha256:" + hashlib.sha256(raw).hexdigest() != r["raw_hash"]:
            raise SystemExit(f"evidence bytes of {r['event_id']} do not match the quarantine record's raw_hash — refusing to use them as samples")
        out.append(raw)
        if limit and len(out) >= limit:
            break
    return out


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    if path.exists():
        for l in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rows.append(json.loads(l))
            except ValueError:
                pass   # the last line of a file that is being written
    return rows


def watch_once(run_dirs: list[Path], window: int, threshold: float, min_frames: int) -> dict:
    recs = []
    for d in run_dirs:
        for e in _read_jsonl(d / "out.jsonl"):
            lin = e.get("_lineage", {})
            recs.append((lin.get("event_id", ""), True, {"family": lin.get("family_id")}))
        for r in _read_jsonl(d / "q.jsonl"):
            recs.append((r.get("event_id", ""), False, r))
    recs.sort(key=lambda x: x[0])   # event ids are time-ordered
    win = recs[-window:]
    usable = sum(1 for _, ok, _ in win if ok)
    share = usable / len(win) if win else None
    qwin = [r for _, ok, r in win if not ok]
    sig = signals(qwin, {"frames": len(win), "emitted": usable, "quarantined": len(qwin)})
    fired = bool(win) and len(win) >= min_frames and share < threshold
    kind = None
    if fired:
        kinds = [(k, sum(r["events"] for r in sig[k])) for k in ("unknown_signatures", "parse_success_drop", "domain_violations", "reonboard_candidates")]
        kind = max(kinds, key=lambda kv: kv[1])[0]
    return {"frames_total": len(recs), "usable_total": sum(1 for _, ok, _ in recs if ok), "quarantined_total": sum(1 for _, ok, _ in recs if not ok),
            "window": len(win), "window_usable": usable, "parse_success": round(share, 4) if share is not None else None, "threshold": threshold,
            "fired": fired, "dominant_signal": kind, "signals": {k: sig[k][:3] for k in ("unknown_signatures", "parse_success_drop", "domain_violations", "reonboard_candidates")},
            "by_family": dict(Counter(r["family"] for _, ok, r in recs if ok))}


def watch(run_dirs: list[Path], out_json: Path | None, window: int, threshold: float, min_frames: int, interval: float, stop_file: Path | None) -> int:
    import os
    import time
    state, events = None, []
    while not (stop_file and stop_file.exists()):
        dirs = sorted({x for d in run_dirs for x in (d.parent.glob(d.name) if "*" in d.name else [d])})
        w = watch_once(dirs, window, threshold, min_frames)
        new = "fired" if w["fired"] else ("ok" if w["window"] >= min_frames else "warming")
        if new != state and not (state is None and new == "warming"):
            top = next((r for k in ("unknown_signatures", "parse_success_drop", "domain_violations", "reonboard_candidates") for r in w["signals"][k] if k == w["dominant_signal"]), None)
            msg = (f"DRIFT MONITOR FIRED: parse success {w['parse_success']:.0%} over the last {w['window']} frames (threshold {threshold:.0%}); {w['dominant_signal']}: {top['key'][:90] if top else '?'} ({top['events'] if top else 0} events)"
                   if new == "fired" else f"drift monitor: parse success {w['parse_success']:.0%} over the last {w['window']} frames — {'RECOVERED' if state == 'fired' else 'ok'}" if new == "ok" else "drift monitor: warming up")
            print(msg, flush=True)
            events.append({"at": time.time(), "state": new, "frames_total": w["frames_total"], "parse_success": w["parse_success"], "message": msg})
            state = new
        if out_json:
            tmp = out_json.with_suffix(".tmp"); tmp.write_text(json.dumps({**w, "state": new, "events": events, "at": time.time()}, indent=1), encoding="utf-8"); os.replace(tmp, out_json)
        time.sleep(interval)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--quarantine"); ap.add_argument("--stats", help="the run's final stats; without it (a stream still running) only --extract-signature is allowed")
    ap.add_argument("--watch", nargs="+", help="run directories (out.jsonl + q.jsonl); a name with * is re-globbed every tick"); ap.add_argument("--window", type=int, default=40)
    ap.add_argument("--threshold", type=float, default=0.8); ap.add_argument("--min-frames", type=int, default=20); ap.add_argument("--interval", type=float, default=1.0); ap.add_argument("--stop-file")
    ap.add_argument("--extract-signature", help="routing signature of an UNKNOWN-signature group: its raw bytes come back out of the evidence store as samples"); ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--json"); ap.add_argument("--evidence"); ap.add_argument("--extract", help="anchor=value of a re-onboard candidate"); ap.add_argument("--out")
    a = ap.parse_args(argv)
    if a.watch:
        return watch([Path(d) for d in a.watch], Path(a.json) if a.json else None, a.window, a.threshold, a.min_frames, a.interval, Path(a.stop_file) if a.stop_file else None)
    if not a.quarantine:
        ap.error("--quarantine is required")
    if a.extract_signature:
        if not (a.evidence and a.out):
            ap.error("--extract-signature needs --evidence and --out")
        lines = extract_signature(_read_jsonl(Path(a.quarantine)), a.extract_signature, Path(a.evidence), a.limit)
        if not lines:
            print(f"no quarantined event carries the unknown signature {a.extract_signature}", file=sys.stderr)
            return 1
        Path(a.out).write_bytes(b"".join(l.rstrip(b"\r\n") + b"\n" for l in lines))
        print(f"extracted {len(lines)} quarantined event(s) of signature {a.extract_signature[:80]} from the evidence store (raw_hash checked) -> {a.out}")
        return 0
    if not a.stats:
        ap.error("--stats is required (only --watch and --extract-signature work on a stream that is still running)")
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
