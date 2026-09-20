"""The coverage curve under the DECLARED replay mix (plan §5.3, §7 P8): cumulative share of replayed traffic the
runtime makes analytics-ready, against cumulative onboarding decisions, families onboarded in descending volume.

    python tools/coverage_curve.py --work /tmp/ulpf-coverage --json ../docs/metrics/coverage.json --svg ../docs/metrics/coverage.svg
    python tools/coverage_curve.py --work /tmp/ulpf-coverage --check ../docs/metrics/coverage.json      # regenerate, compare, never write

What is MEASURED: the pool line counts; every y value (the runtime replays a constructed stream with the packs of
the first k families loaded and reports what it made usable — nothing is credited to a family by label); every x
value (operator responses + certificates read, from the session records; the hand-authoring baseline is one
mapping decision per semantic field, by definition); evidence requests and the fields each resolved; the routing
candidate-set sizes of every replay.
What is ASSUMED: the mix — the weight of each traffic stratum. Fixtures carry no volume distribution. Every mix in
metrics/replay-mix.json is a stated assumption and is printed beside every figure derived from it.
NOT measured anywhere: minutes. The x-axis is counted decisions.

Two splits are run. `in_sample`: families are onboarded from all the corpus lines of their stratum and the same
lines are replayed — what the demo does, and an upper bound. `held_out`: onboarded from the even-numbered lines
of the stratum, replayed over the odd-numbered ones only. Squid's two families are onboarded from OUR samples (the
worked trace's, and a synthetic 11-slot fixture) under the fixture provider and cannot be split; the corpus's
Squid files are out-of-sample for them in both splits.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from effort import family as session_effort  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
LEARN = ROOT / "learning"
RUNTIME = ROOT / "runtime/bin/ulpf-runtime"
RECORDINGS = ROOT / "spike/results/desktop-5060ti"
BANDS = (25, 50, 75, 90, 100)


def rmtree(p: Path) -> None:
    def onerr(fn, path, _):
        os.chmod(path, stat.S_IRWXU); fn(path)
    if p.exists():
        for d, _, _ in os.walk(p):
            os.chmod(d, stat.S_IRWXU)
        shutil.rmtree(p, onerror=onerr)


def learn(*args: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-m", "ulpf_learn", *args], cwd=LEARN, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)


def read_pool(stratum: dict) -> list[bytes]:
    out: list[bytes] = []
    for part in stratum["pool"]:
        lines = [l.rstrip(b"\r") for l in (ROOT / part["file"]).read_bytes().split(b"\n")]
        lines = [l for l in lines if l.strip(b"\x00 ")]
        if "include" in part:
            rx = re.compile(part["include"].encode()); lines = [l for l in lines if rx.search(l)]
        out += lines
    return out


def stratum_weights(cfg: dict, mix: dict, full_counts: dict[str, int]) -> dict[str, float]:
    strata = {s["id"]: s for s in cfg["strata"]}
    w = mix["weights"]
    if w == "pool_lines":
        return {sid: float(n) for sid, n in full_counts.items() if not strata[sid].get("ours")}
    if "strata" in w:
        return {sid: float(v) for sid, v in w["strata"].items()}
    out: dict[str, float] = {}
    total_src = sum(w["source"].values())
    for src, sw in w["source"].items():
        mine = [s for s in cfg["strata"] if s["source"] == src and not s.get("ours")]
        if "class" in w:
            present = {c: cw for c, cw in w["class"].items() if any(s["class"] == c for s in mine)}
            for c, cw in present.items():
                group = [s for s in mine if s["class"] == c]; lines = sum(full_counts[s["id"]] for s in group)
                for s in group:
                    out[s["id"]] = sw / total_src * cw / sum(present.values()) * full_counts[s["id"]] / lines
        else:
            lines = sum(full_counts[s["id"]] for s in mine)
            for s in mine:
                out[s["id"]] = sw / total_src * full_counts[s["id"]] / lines
    return out


def apportion(weights: dict[str, float], n: int) -> dict[str, int]:
    """Largest remainder: counts sum to exactly n, deterministically."""
    tot = sum(weights.values())
    exact = {k: v / tot * n for k, v in weights.items()}
    counts = {k: int(e) for k, e in exact.items()}
    for k in sorted(exact, key=lambda k: (-(exact[k] - counts[k]), k))[: n - sum(counts.values())]:
        counts[k] += 1
    return counts


def build_stream(counts: dict[str, int], pools: dict[str, list[bytes]], path: Path) -> int:
    rows = []
    for si, (sid, c) in enumerate(sorted(counts.items())):
        pool = pools[sid]
        if not pool or not c:
            continue
        rows += [((i + 0.5) / c, si, pool[i % len(pool)]) for i in range(c)]   # even interleave, no RNG
    rows.sort(key=lambda r: (r[0], r[1]))
    path.write_bytes(b"".join(r[2] + b"\n" for r in rows))
    return len(rows)


def replay(packs: list[Path], stream: Path, work: Path) -> dict:
    rmtree(work); work.mkdir(parents=True)
    cmd = [str(RUNTIME), "run"]
    for p in packs:
        cmd += ["--pack", str(p)]
    cmd += ["--source-id", "coverage-replay", "--input", str(stream), "--evidence", str(work / "ev"), "--out", str(work / "out.jsonl"),
            "--quarantine", str(work / "q.jsonl"), "--fixed-clock-ms", "1734567890481"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    stats = [l for l in r.stderr.splitlines() if l.startswith("{")]
    if r.returncode != 0 or not stats:
        raise SystemExit(f"runtime replay failed rc={r.returncode}: {r.stderr[-600:]}")
    st = json.loads(stats[-1])
    rmtree(work)
    return st


class Split:
    def __init__(self, cfg: dict, name: str, work: Path):
        self.cfg, self.name, self.work = cfg, name, work / name
        rmtree(self.work); (self.work / "samples").mkdir(parents=True)
        self.strata = {s["id"]: s for s in cfg["strata"]}
        self.full = {sid: read_pool(s) for sid, s in self.strata.items()}
        sampled = {f["samples_stratum"] for f in cfg["families"] if f.get("samples_stratum")}
        self.replay_pool = {sid: (p[1::2] if name == "held_out" and sid in sampled else p) for sid, p in self.full.items()}
        self.families: dict[str, dict] = {}
        self._merged: dict[tuple, Path] = {}

    def onboard_all(self) -> None:
        store = self.work / "propagation.json"
        for f in self.cfg["families"]:
            sess, pack = self.work / f"s-{f['id']}", self.work / "packs" / f["id"]
            rec = {"id": f["id"], "source_id": f["source_id"], "promoted": False, "log": []}
            if f["kind"] == "spec":
                lines = self.full[f["samples_stratum"]]
                if f.get("samples_exclude"):
                    rx = re.compile(f["samples_exclude"].encode()); lines = [l for l in lines if not rx.search(l)]
                if self.name == "held_out":
                    lines = lines[0::2]
                sp = self.work / "samples" / f"{f['id']}.log"; sp.write_bytes(b"".join(l + b"\n" for l in lines))
                rec["onboarding_samples"] = len(lines); rec["samples_origin"] = "corpus"
                steps = [("onboard-spec", "--samples", str(sp), "--spec", str(ROOT / "drafts/sufficiency" / f"{f['spec']}.json"), "--source-id", f["source_id"], "--operator", "op-014",
                          "--session", str(sess), "--vendor", f["vendor"], "--family-id", f["id"], "--unwrap-envelope", "--provider", "recorded",
                          "--recording", str(RECORDINGS / f"granite-4.1-8b-q4_k_m__gpu__{f['recording']}__whole.json"), "--propagation-store", str(store))]
            else:
                rec["onboarding_samples"] = len(read_pool({"pool": [{"file": f["samples_path"]}]})); rec["samples_origin"] = "ours (not corpus; never split)"
                steps = [("onboard", "--provider", "fixture", "--samples", str(ROOT / f["samples_path"]), "--source-id", f["source_id"], "--operator", "op-014", "--session", str(sess), "--propagation-store", str(store))]
            if f.get("discriminator"):
                steps.append(("respond", "--session", str(sess), "--discriminator", f["discriminator"], "--input", f["evidence"]))
            steps.append(("promote", "--session", str(sess), "--out", str(pack), "--pack-id", f["id"]))
            for st in steps:
                rc, out = learn(*st)
                if rc != 0:
                    rec["log"].append(f"{st[0]} failed: {out.strip().splitlines()[-1][:300] if out.strip() else rc}")
                    break
            if (sess / "session.json").exists():
                e = session_effort(sess)
                rec.update({k: e[k] for k in ("fields", "certificates", "certificates_retained", "evidence_requests", "operator_responses", "fields_resolved_by_responses", "slots_propagated", "provider", "promoted")})
                rec["ulpf_decisions"] = e["operator_responses"] + e["certificates"]; rec["baseline_decisions"] = e["fields"]
            rec["pack"] = str(pack) if rec["promoted"] and (pack / "pack.json").exists() else None
            self.families[f["id"]] = rec

    def source_packs(self, fams: list[str]) -> list[Path]:
        by_src: dict[str, list[str]] = {}
        for fid in fams:
            if self.families[fid]["pack"]:
                by_src.setdefault(next(f["source_pack"] for f in self.cfg["families"] if f["id"] == fid), []).append(fid)
        out = []
        for src, ids in sorted(by_src.items()):
            key = (src, tuple(sorted(ids)))
            if key not in self._merged:
                dest = self.work / "source-packs" / f"{src}--{'+'.join(sorted(ids))}"
                vendor = next(f["vendor"] for f in self.cfg["families"] if f["id"] == ids[0])
                args = ["merge", *[self.families[i]["pack"] for i in sorted(ids)], "--out", str(dest), "--pack-id", src] + (["--vendor", vendor] if vendor else [])
                rc, o = learn(*args)
                if rc != 0:
                    raise SystemExit(f"merge {key} failed: {o[-500:]}")
                self._merged[key] = dest
            out.append(self._merged[key])
        return out


def curve_for(split: Split, mix: dict, n_frames: int) -> dict:
    cfg = split.cfg
    full_counts = {sid: len(p) for sid, p in split.full.items()}
    weights = stratum_weights(cfg, mix, full_counts)
    counts = apportion(weights, n_frames)
    stream = split.work / f"stream-{mix['id']}.log"
    frames = build_stream(counts, split.replay_pool, stream)
    all_ids = [f["id"] for f in cfg["families"]]
    final = replay(split.source_packs(all_ids), stream, split.work / "run")
    rt = {f["id"]: f["runtime_family"] for f in cfg["families"]}
    vol = {fid: final["emitted_by_family"].get(rt[fid], 0) for fid in all_ids}
    order = sorted(all_ids, key=lambda fid: (-vol[fid], all_ids.index(fid)))
    for f in cfg["families"]:   # costs were measured with `after` onboarded first; an order that contradicts it would misstate them
        if f.get("after") and order.index(f["id"]) < order.index(f["after"]) and abs(vol[f["id"]] - vol[f["after"]]) <= 1:
            i, j = order.index(f["id"]), order.index(f["after"]); order[i], order[j] = order[j], order[i]   # equal declared weight, one frame of rounding: a tie
        if f.get("after") and order.index(f["id"]) < order.index(f["after"]):
            raise SystemExit(f"mix {mix['id']}: {f['id']} would be onboarded before {f['after']}, but its cost was measured after it")
    steps, cum_u, cum_b, cum_req, cum_resp, cum_res, cum_cert, cum_cres, max_cs = [], 0, 0, 0, 0, 0, 0, 0, 0
    cs_final = None
    for k, fid in enumerate(order, 1):
        fam = split.families[fid]
        st = final if k == len(order) else replay(split.source_packs(order[:k]), stream, split.work / "run")
        if st["emitted"] != st["usable"]:
            raise SystemExit(f"emitted {st['emitted']} != usable {st['usable']}: coverage counts usable events only; look before trusting this")
        cum_u += fam.get("ulpf_decisions", 0); cum_b += fam.get("baseline_decisions", 0); cum_req += fam.get("evidence_requests", 0)
        cum_resp += fam.get("operator_responses", 0); cum_res += fam.get("fields_resolved_by_responses", 0); cum_cert += fam.get("certificates", 0)
        cum_cres += fam.get("certificates", 0) - fam.get("certificates_retained", 0) - fam.get("certificates_resolved_by_propagation", 0)
        max_cs = max([max_cs] + [int(s) for s in st["candidate_set_sizes"]])
        steps.append({"k": k, "family": fid, "family_usable_frames_final": vol[fid], "usable_frames": st["usable"], "coverage_pct": round(100 * st["usable"] / frames, 2),
                      "ulpf_decisions": fam.get("ulpf_decisions", 0), "baseline_decisions": fam.get("baseline_decisions", 0),
                      "cum_ulpf_decisions": cum_u, "cum_baseline_decisions": cum_b, "cum_evidence_requests": cum_req, "cum_operator_responses": cum_resp,
                      "cum_fields_resolved_by_responses": cum_res, "cum_certificates": cum_cert, "cum_certificates_resolved_by_responses": cum_cres, "candidate_set_sizes": st["candidate_set_sizes"], "quarantine_reasons": st["quarantine_reasons"]})
        cs_final = st["candidate_set_sizes"]
    plateau = steps[-1]["coverage_pct"]
    bands = []
    for b in BANDS:
        hit = next((s for s in steps if s["coverage_pct"] >= b), None)
        bands.append({"coverage_at_least_pct": b, "reached": bool(hit), **({"families": hit["k"], "ulpf_decisions": hit["cum_ulpf_decisions"], "baseline_decisions": hit["cum_baseline_decisions"],
                      "evidence_requests": hit["cum_evidence_requests"], "operator_responses": hit["cum_operator_responses"], "certificates_resolved_by_those_responses": hit["cum_certificates_resolved_by_responses"], "fields_given_provenance_by_those_responses": hit["cum_fields_resolved_by_responses"]} if hit else {})})
    return {"mix": mix["id"], "label": mix["label"], "ASSUMPTION": mix["assumption"], "frames": frames,
            "stratum_frames": {k: v for k, v in sorted(counts.items()) if v}, "plateau_coverage_pct": plateau, "order": order, "steps": steps, "bands": bands,
            "candidate_set_sizes_all_families_loaded": cs_final, "max_candidate_set_size_any_step": max_cs}


def stratum_table(split: Split) -> list[dict]:
    """Each stratum's replay pool once, all families loaded: what is routable and usable, by stratum, by measurement."""
    packs = split.source_packs([f["id"] for f in split.cfg["families"]])
    rows = []
    for sid, pool in split.replay_pool.items():
        p = split.work / "stratum.log"; p.write_bytes(b"".join(l + b"\n" for l in pool))
        st = replay(packs, p, split.work / "run")
        rows.append({"stratum": sid, "source": split.strata[sid]["source"], "class": split.strata[sid]["class"], "ours_not_corpus": bool(split.strata[sid].get("ours")),
                     "corpus_lines": len(split.full[sid]), "replayed_lines": st["frames"], "usable": st["usable"], "usable_pct": round(100 * st["usable"] / st["frames"], 1) if st["frames"] else None,
                     "by_family": st["emitted_by_family"], "quarantine_reasons": st["quarantine_reasons"]})
    return rows


def svg(result: dict) -> str:
    """Small multiples, one panel per mix, shared axes. Steps: the cost of a family is paid (move right), then its traffic
    becomes usable (move up). Blue = ULPF, orange = hand-authoring, both held-out; thin dashed blue = ULPF in-sample."""
    mixes = [c["mix"] for c in result["splits"]["held_out"]["curves"]]
    xmax = max(c["steps"][-1]["cum_baseline_decisions"] for s in result["splits"].values() for c in s["curves"])
    xmax = (int(xmax / 50) + 1) * 50
    PW, PH, L, T, GX, GY = 400, 210, 56, 132, 64, 96
    W, H = L + 2 * PW + GX + 24, T + 2 * PH + GY + 70
    same = all([s["coverage_pct"] for s in a["steps"]] == [s["coverage_pct"] for s in b["steps"]] for a, b in zip(result["splits"]["in_sample"]["curves"], result["splits"]["held_out"]["curves"]))
    ink, mute, grid, blue, orange = "#0b0b0b", "#52514e", "#e4e3df", "#2a78d6", "#eb6834"
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="system-ui, -apple-system, Segoe UI, sans-serif" font-size="11" fill="{ink}">',
         f'<rect width="{W}" height="{H}" fill="#fcfcfb"/>',
         f'<text x="{L}" y="24" font-size="15" font-weight="600">Coverage against counted onboarding decisions, under four DECLARED replay mixes</text>',
         f'<text x="{L}" y="42" fill="{mute}">Every mix is a stated assumption: the fixtures carry no traffic distribution.</text>',
         f'<text x="{L}" y="57" fill="{mute}">y is measured by replaying the constructed stream through the runtime; x is counted from the session records, not timed.</text>',
         f'<g transform="translate({L},80)"><line x1="0" y1="0" x2="22" y2="0" stroke="{blue}" stroke-width="2"/><text x="28" y="4">ULPF: responses + certificates read (held-out lines)</text>'
         f'<line x1="300" y1="0" x2="322" y2="0" stroke="{orange}" stroke-width="2"/><text x="328" y="4">hand-authoring: one decision per field (same coverage)</text>'
         + (f'<line x1="640" y1="0" x2="662" y2="0" stroke="{blue}" stroke-width="1.2" stroke-dasharray="4 3"/><text x="668" y="4">ULPF, in-sample replay</text>' if not same else "") + "</g>"]

    def path(steps, xkey, x0, y0):
        pts, px, py = [(0.0, 0.0)], 0.0, 0.0
        for s in steps:
            pts.append((s[xkey], py)); pts.append((s[xkey], s["coverage_pct"])); py = s["coverage_pct"]
        return " ".join(f"{'M' if i == 0 else 'L'}{x0 + x / xmax * PW:.1f},{y0 + PH - y / 100 * PH:.1f}" for i, (x, y) in enumerate(pts))

    for i, mid in enumerate(mixes):
        x0, y0 = L + (i % 2) * (PW + GX), T + (i // 2) * (PH + GY)
        ho = next(c for c in result["splits"]["held_out"]["curves"] if c["mix"] == mid)
        ins = next(c for c in result["splits"]["in_sample"]["curves"] if c["mix"] == mid)
        o.append(f'<text x="{x0}" y="{y0 - 22}" font-weight="600">{mid}</text><text x="{x0}" y="{y0 - 8}" fill="{mute}" font-size="10">ASSUMED: {ho["label"]}</text>')
        for yv in (0, 25, 50, 75, 100):
            yy = y0 + PH - yv / 100 * PH
            o.append(f'<line x1="{x0}" y1="{yy:.1f}" x2="{x0 + PW}" y2="{yy:.1f}" stroke="{grid}"/><text x="{x0 - 6}" y="{yy + 4:.1f}" text-anchor="end" fill="{mute}">{yv}%</text>')
        for xv in range(0, xmax + 1, 50):
            xx = x0 + xv / xmax * PW
            o.append(f'<text x="{xx:.1f}" y="{y0 + PH + 14}" text-anchor="middle" fill="{mute}">{xv}</text>')
        if not same:
            o.append(f'<path d="{path(ins["steps"], "cum_ulpf_decisions", x0, y0)}" fill="none" stroke="{blue}" stroke-width="1.2" stroke-dasharray="4 3"/>')
        o.append(f'<path d="{path(ho["steps"], "cum_baseline_decisions", x0, y0)}" fill="none" stroke="{orange}" stroke-width="2" stroke-linejoin="round"/>')
        o.append(f'<path d="{path(ho["steps"], "cum_ulpf_decisions", x0, y0)}" fill="none" stroke="{blue}" stroke-width="2" stroke-linejoin="round"/>')
        for s in ho["steps"]:
            for key, col in (("cum_baseline_decisions", orange), ("cum_ulpf_decisions", blue)):
                cx, cy = x0 + s[key] / xmax * PW, y0 + PH - s["coverage_pct"] / 100 * PH
                o.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="3.5" fill="{col}" stroke="#fcfcfb" stroke-width="1.5"><title>{s["k"]}. {s["family"]}: {s["coverage_pct"]}% after {s[key]} decisions</title></circle>')
        last = ho["steps"][-1]
        ly = y0 + PH - last["coverage_pct"] / 100 * PH
        ly = y0 + PH - 10 if last["coverage_pct"] > 85 else ly - 9
        o.append(f'<text x="{x0 + PW}" y="{ly:.1f}" text-anchor="end" fill="{mute}">ends at {last["coverage_pct"]}% of the stream: {last["cum_ulpf_decisions"]} decisions (ULPF) vs {last["cum_baseline_decisions"]} (by hand)</text>')
    o.append(f'<text x="{L + PW + GX / 2}" y="{H - 32}" text-anchor="middle" fill="{mute}">x: cumulative onboarding decisions (counted; nobody was timed). Nine families, four sources; each dot is one family, in descending volume under that mix.</text>')
    o.append(f'<text x="{L + PW + GX / 2}" y="{H - 14}" text-anchor="middle" fill="{mute}">y: share of the replayed stream emitted as usable events{" (held-out and in-sample replay agree at every step)" if same else ""}. A step is a family, not a trend: nine points do not support a fitted curve.</text>')
    o.append("</svg>")
    return "\n".join(o) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mix", default=str(ROOT / "metrics/replay-mix.json")); ap.add_argument("--work")
    ap.add_argument("--json"); ap.add_argument("--svg"); ap.add_argument("--check", help="regenerate and compare with this committed result; write nothing")
    ap.add_argument("--render", help="draw --svg from this existing result; measure nothing")
    a = ap.parse_args(argv)
    if a.render:
        Path(a.svg).write_text(svg(json.loads(Path(a.render).read_text(encoding="utf-8"))), encoding="utf-8", newline="\n"); return 0
    cfg = json.loads(Path(a.mix).read_text(encoding="utf-8"))
    if not RUNTIME.exists():
        print(f"{RUNTIME} not built", file=sys.stderr); return 2
    result = {"note": "Generated by learning/tools/coverage_curve.py from metrics/replay-mix.json. EVERY MIX IS A STATED ASSUMPTION (plan §5.3); coverage is measured by runtime replay; decisions are counted, never timed.",
              "frames_per_stream": cfg["frames_per_stream"], "sample": {"families": len(cfg["families"]), "sources": len({f["source_id"] for f in cfg["families"]})}, "splits": {}}
    for name in ("in_sample", "held_out"):
        sp = Split(cfg, name, Path(a.work)); sp.onboard_all()
        fams = [{k: v for k, v in f.items() if k != "pack"} for f in sp.families.values()]
        result["splits"][name] = {"families": fams, "strata": stratum_table(sp), "curves": [curve_for(sp, m, cfg["frames_per_stream"]) for m in cfg["mixes"]]}
        print(f"== {name}")
        for f in fams:
            print(f"  {f['id']:<18} samples {f['onboarding_samples']:>3}  promoted {str(f['promoted']):<5} decisions {f.get('ulpf_decisions', '-'):>3} vs {f.get('baseline_decisions', '-'):>3}  requests {f.get('evidence_requests', '-')}  "
                  f"fields given provenance by responses {f.get('fields_resolved_by_responses', '-')}  propagated {f.get('slots_propagated', '-')}  {'; '.join(f['log'])}")
        for c in result["splits"][name]["curves"]:
            print(f"  [{c['mix']}] ASSUMED: {c['label']}")
            print("    " + "  ".join(f"{s['k']}.{s['family']} {s['coverage_pct']}%@{s['cum_ulpf_decisions']}/{s['cum_baseline_decisions']}" for s in c["steps"]))
            print(f"    plateau {c['plateau_coverage_pct']}%  candidate sets {json.dumps(c['candidate_set_sizes_all_families_loaded'])}  max any step {c['max_candidate_set_size_any_step']}")
    text = json.dumps(result, indent=1) + "\n"
    if a.check:
        committed = Path(a.check).read_text(encoding="utf-8")
        if committed != text:
            import difflib
            sys.stdout.writelines(list(difflib.unified_diff(committed.splitlines(True), text.splitlines(True), "committed", "regenerated"))[:60])
            print("coverage --check: FAIL (the committed figures are not what the code and corpus produce)"); return 1
        print("coverage --check: PASS (committed figures regenerate byte for byte)"); return 0
    if a.json:
        Path(a.json).write_text(text, encoding="utf-8", newline="\n")
    if a.svg:
        Path(a.svg).write_text(svg(result), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
