#!/usr/bin/env python3
"""Markdown tables from docs/metrics/capacity.json (scripts/bench/capacity.py): A, B, C, as written into docs/throughput.md.

    python3 scripts/bench/capacity_report.py [--json docs/metrics/capacity.json]
"""
import argparse
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = 1e9 / 86400


def cores(spec):
    out = set()
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out |= {c // 2 for c in range(int(a), int(b or a) + 1)}
    return sorted(out)


def lay(l):
    return "; ".join(f"{k} {'+'.join(map(str, cores(v)))} (CPUs {v})" for k, v in l.items())


def f(n):
    return f"{n:,.0f}"


def med(runs, key, sub=None):
    v = [r[key][sub] if sub else r[key] for r in runs]
    return statistics.median(v)


def spread(runs, key, sub=None):
    return " · ".join(f(r[key][sub] if sub else r[key]) for r in runs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=str(ROOT / "docs/metrics/capacity.json"))
    a = ap.parse_args()
    d = json.load(open(a.json))
    m = d["_meta"]["machine"]
    print(f"Machine: {m['cpu']}, {m['logical_cpus']} logical CPUs ({m['topology']}), {m['memory_gb']} GB visible to WSL2; commit {m['commit']}.\n")
    dv = d["_meta"]["devices"]
    print(f"Input: {', '.join(f'{k} {v} lines' for k, v in dv['device_formats'].items())}; packs {', '.join(dv['packs'])}.\n")
    if "A" in d:
        for key, cell in d["A"].items():
            r = cell["runs"][0]
            print("### A\n")
            print(f"Layout: {lay(r['layout'])}. Senders: {r['senders']} ({r['distinct_sender_addresses']} addresses). Window {r['window'][0]}–{r['window'][1]} s "
                  f"({r['window_s']} s), {f(r['events_in_window'])} events in it; {f(r['accepted'])} in the run.\n")
            print("| what | value |\n|---|---|")
            print(f"| **events/s, one ULPF process** (sustained, window) | **{f(r['eps_accepted'])}** |")
            print(f"| 30-second slices | {' · '.join(map(f, r['steadiness_30s_eps']))} |")
            print(f"| ULPF cores (runtime + committer) | {r['cores_in_window']['ulpf']} |")
            print(f"| **events per ULPF core-second** | **{f(r['ulpf_events_per_core_second_in_window'])}** |")
            print(f"| SIEM stand-in acknowledged | {f(r['eps_siem_in_window'])}/s ({r['cores_in_window']['siem']} cores) |")
            print(f"| lake writer acknowledged | {f(r['eps_lake_in_window'])}/s ({r['cores_in_window']['lake_writers']} cores); backlog at the window's end {f(r['backlog_at_window_end']['lake'])} |")
            print(f"| senders | {r['cores_in_window']['senders']} cores |")
            print(f"| exactly-once / affinity | {r['exactly_once']} / {r['affinity']} (sent {f(r['sent'])} = accepted {f(r['accepted'])} = SIEM {f(r['siem_documents'])} ({f(r['siem_distinct'])} distinct) = lake {f(r['lake_rows'])} ({f(r['lake_distinct'])} distinct), quarantined {r['quarantined']}) |")
            print(f"| disk per million events | {r['disk_per_million_gb']} GB |")
            print()
    if "B" in d:
        base = {}
        for key, cell in d["B"].items():
            if "runs" in cell and cell["runs"][0]["processes"] == 1:
                base[cell["runs"][0]["senders"]] = cell.get("median_eps_per_process") or med(cell["runs"], "eps_per_process")
        print("### B\n")
        first = next(c for c in d["B"].values() if "runs" in c)["runs"][0]
        print(f"Layout (every cell): {lay(first['layout'])}. Window {first['duration_s'] - first['window'][0]:.0f} s per run after the warm-up; three runs per cell, median; "
              f"scaling efficiency = events/s per process ÷ the one-process figure with the same senders.\n")
        print("| processes | senders | events/s (median; runs) | per process | efficiency | ULPF cores | events per ULPF core-s | lake acknowledged in window | senders per process | exactly-once · affinity | events in window |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
        for key, cell in sorted(d["B"].items(), key=lambda kv: (int(kv[0].split("_")[0][1:]), int(kv[0].split("_S")[1]))):
            if "runs" not in cell:
                print(f"| {key} | | not started: {cell.get('not_started')} |")
                continue
            rs = cell["runs"]
            P, S = rs[0]["processes"], rs[0]["senders"]
            pp = med(rs, "eps_per_process")
            eff = pp / base[S] if S in base else None
            spp = [sorted(r["senders_per_process"].values()) for r in rs]
            print(f"| {P} | {S} | **{f(med(rs, 'eps_accepted'))}** ({spread(rs, 'eps_accepted')}) | {f(pp)} | {eff:.0%} | {med(rs, 'cores_in_window', 'ulpf'):.2f} | "
                  f"{f(med(rs, 'ulpf_events_per_core_second_in_window'))} | {f(med(rs, 'eps_lake_in_window'))}/s | {', '.join('–'.join(map(str, (s[0], s[-1]))) for s in spp)} | "
                  f"{all(r['exactly_once'] for r in rs)} · {all(r['affinity'] for r in rs)} | {f(med(rs, 'events_in_window'))} |")
        print()
    if "C" in d:
        print("### C\n")
        for key, cell in d["C"].items():
            for r in cell.get("runs", []):
                print(f"{key}: layout {lay(r['layout'])}; offered {r['offered_rate']}/s; window {r['window_s']} s")
                print(f"  ULPF {f(r['eps_accepted'])}/s, SIEM {f(r['eps_siem_in_window'])}/s, lake {f(r['eps_lake_in_window'])}/s; backlog {r['backlog_at_window_end']}; cores {r['cores_in_window']}; "
                      f"exactly-once {r['exactly_once']} affinity {r['affinity']}; disk per million {r['disk_per_million_gb']}")


if __name__ == "__main__":
    main()
