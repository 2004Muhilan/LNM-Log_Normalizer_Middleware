#!/usr/bin/env python3
"""The lake writer alone, before and after the 2026-09-27 fixes, on the SAME rows (three runs each, median).

    python3 scripts/bench/lake_bench.py --jsonl NORMALIZED.jsonl

  before  100-event batches (the forwarder's old default), rotation 8 MiB / 30 s, insertion order preserved
  after   1,000-event batches (?batch=1000), production rotation 128 MiB / 300 s, preserve_insertion_order=false
Timed from the first batch to the end of the final flush (every row in a Parquet file). Each run in its own directory,
deleted afterwards.
"""
import argparse
import glob
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = {"before": {"batch": 100, "args": ["--rotate-bytes", "8MiB", "--rotate-seconds", "30", "--keep-insertion-order"]},
           "after": {"batch": 1000, "args": []}}


def proc_cpu(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except OSError:
        return None


def one(lines, cfg, work, port):
    run = Path(tempfile.mkdtemp(dir=work, prefix="lakebench-"))
    lw = subprocess.Popen([sys.executable, str(ROOT / "adapters/lake/lakewriter.py"), "--lake", str(run / "lake"), "--listen", f"127.0.0.1:{port}", *cfg["args"]],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=1); break
            except OSError:
                time.sleep(0.1)
        c0 = proc_cpu(lw.pid); t0 = time.time(); off = 0
        for i in range(0, len(lines), cfg["batch"]):
            b = b"".join(lines[i:i + cfg["batch"]])
            r = urllib.request.Request(f"http://127.0.0.1:{port}/ingest", data=b, method="POST",
                                       headers={"X-ULPF-Spool-Id": "bench", "X-ULPF-Spool-Start": str(off), "X-ULPF-Spool-End": str(off + len(b))})
            urllib.request.urlopen(r, timeout=120).read(); off += len(b)
        t_ack = time.time() - t0
        urllib.request.urlopen(f"http://127.0.0.1:{port}/flush", timeout=900).read()
        wall = time.time() - t0; cpu = proc_cpu(lw.pid) - c0
        fs = glob.glob(str(run / "lake" / "ext" / "*" / "*" / "*" / "*" / "*.parquet"))
        import duckdb
        rows = duckdb.connect().execute(f"SELECT count(*) FROM read_parquet({fs!r})").fetchone()[0]
        pq = sum(os.path.getsize(f) for f in fs)
        return {"rows": rows, "wall_s": round(wall, 2), "eps": round(len(lines) / wall), "eps_acknowledged": round(len(lines) / t_ack), "cpu_s": round(cpu, 1),
                "eps_per_core": round(len(lines) / cpu), "files": len(fs), "parquet_bytes": pq, "parquet_vs_jsonl": round(pq / off, 4)}
    finally:
        lw.terminate(); lw.wait(60); shutil.rmtree(run, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True); ap.add_argument("--work", default=str(Path.home() / "ulpf-bench")); ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default=str(ROOT / "docs" / "metrics" / "lake-bench.json"))
    a = ap.parse_args()
    Path(a.work).mkdir(parents=True, exist_ok=True)
    lines = Path(a.jsonl).read_bytes().splitlines(keepends=True)
    res = {"rows_in": len(lines), "jsonl_bytes": sum(map(len, lines)), "configs": {k: {"batch": v["batch"], "writer_args": v["args"]} for k, v in CONFIGS.items()}, "runs": {}}
    for name, cfg in CONFIGS.items():
        runs = [one(lines, cfg, a.work, 8895) for _ in range(a.reps)]
        for r in runs:
            assert r["rows"] == len(lines), f"{name}: {r['rows']} rows in the lake for {len(lines)} sent"
        res["runs"][name] = {"runs": runs, "median": {k: statistics.median(r[k] for r in runs) for k in ("eps", "eps_acknowledged", "wall_s", "cpu_s", "eps_per_core", "files", "parquet_vs_jsonl")}}
        print(name, json.dumps(res["runs"][name]["median"]), flush=True)
    Path(a.out).write_text(json.dumps(res, indent=1) + "\n")


if __name__ == "__main__":
    main()
