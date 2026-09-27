#!/usr/bin/env python3
"""Where the lake writer's time goes (laptop branch, 2026-09-27) — measured before anything is changed.

    python3 scripts/bench/lake_profile.py --jsonl NORMALIZED.jsonl [--work DIR]

The input is the runtime's normalized output for the four-vendor mixed capture (what the throughput harness feeds the
writer). Measured separately, on the same rows:
  A  ingest    the acknowledged path: 100-row batches staged, each with an fsync of the staging file and of the state
  B  group     reading the staging file back and grouping rows by (spool, class, event day) — Python json per row
  C  convert   one DuckDB COPY per group into Parquet with the full fixed schema (the pinned OCSF table)
  C' the same COPY with only the lineage columns (to isolate the cost of the ~3,600-element schema)
  C" the same rows as ONE group per class (as if files rotated on size instead of every few seconds)
  P  cProfile of one full flush (the top functions)
Nothing here is kept: every run directory is deleted.
"""
import argparse
import cProfile
import io
import json
import os
import pstats
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "adapters" / "lake"))
import lakewriter  # noqa: E402
import schema  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True); ap.add_argument("--work", default=str(Path.home() / "ulpf-bench"))
    ap.add_argument("--out", default=str(ROOT / "docs" / "metrics" / "lake-profile.json"))
    a = ap.parse_args()
    import duckdb
    lines = Path(a.jsonl).read_bytes().splitlines(keepends=True)
    n = len(lines)
    Path(a.work).mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(dir=a.work, prefix="lakeprof-"))
    res = {"rows": n, "jsonl_bytes": sum(len(l) for l in lines)}
    pinned = ROOT / "ocsf" / "pinned"
    try:
        # A: the acknowledged ingest path, as the HTTP handler calls it
        lk = lakewriter.Lake(run / "lake", pinned, 1 << 40, 1e9, "local", "000000000000")
        t0 = time.time(); off = 0
        for i in range(0, n, 100):
            b = b"".join(lines[i:i + 100])
            lk.ingest(b, "prof", off, off + len(b)); off += len(b)
        res["A_ingest_s"] = time.time() - t0
        # B: group (json per row), exactly as flush() does
        t0 = time.time(); groups = {}
        with open(lk.staging, "rb") as f:
            for line in f:
                spool, o, ev = line.split(b" ", 2)
                e = json.loads(ev)
                import datetime as dt
                ms = e.get("time") or (e.get("_lineage") or {}).get("ingest_time") or 0
                day = dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y%m%d")
                groups.setdefault((spool.decode(), e.get("class_uid"), day), []).append(ev)
        res["B_group_s"] = time.time() - t0
        res["groups"] = len(groups)
        classes = schema.pinned_classes(str(pinned))
        con = duckdb.connect()

        def copy(rows, cu, select, tag):
            src, dst = run / f"src-{tag}.jsonl", run / f"out-{tag}.parquet"
            src.write_bytes(b"".join(r.rstrip(b"\n") + b"\n" for r in rows))
            reader = f"read_json('{src}', format='newline_delimited', columns={schema.read_columns(str(pinned), cu)})"
            t = time.time()
            con.execute(f"COPY (SELECT {select} FROM {reader}) TO '{dst}' (FORMAT parquet, COMPRESSION zstd)")
            dt_ = time.time() - t
            sz = dst.stat().st_size
            src.unlink(); dst.unlink()
            return dt_, sz
        # C: one COPY per group, full schema
        t0 = time.time(); per = []; pq = 0
        for (sp, cu, day), rows in groups.items():
            if cu not in classes:
                continue
            d, sz = copy(rows, cu, schema.select_list(str(pinned), cu), "c")
            per.append({"class_uid": cu, "day": day, "rows": len(rows), "copy_s": round(d, 4), "bytes": sz}); pq += sz
        res["C_convert_s"] = time.time() - t0
        res["C_parquet_bytes"] = pq
        res["C_files"] = len(per)
        small = [p for p in per if p["rows"] < 50]
        res["C_small_files"] = {"files": len(small), "s": round(sum(p["copy_s"] for p in small), 3), "rows": sum(p["rows"] for p in small)}
        res["C_fixed_cost_per_file_s"] = round(sorted(p["copy_s"] for p in per)[0], 4) if per else None
        # C': the schema width isolated — (a) the full typed read, only the lineage columns written; (b) a narrow read
        # (each row as one JSON object) writing the lineage columns
        lin_only = ", ".join(f"CAST(json_extract_string(_lineage, '$.{src}') AS {t}) AS {schema.q(n)}" for n, t, src in schema.LINEAGE)
        t0 = time.time()
        for (sp, cu, day), rows in groups.items():
            if cu in classes:
                copy(rows, cu, lin_only, "w")
        res["C2a_full_read_lineage_write_s"] = time.time() - t0
        t0 = time.time()
        for (sp, cu, day), rows in groups.items():
            if cu not in classes:
                continue
            src, dst = run / "src-n.jsonl", run / "out-n.parquet"
            src.write_bytes(b"".join(r.rstrip(b"\n") + b"\n" for r in rows))
            narrow = ", ".join(f"CAST(json_extract_string(json, '$._lineage.{src_}') AS {t}) AS {schema.q(n_)}" for n_, t, src_ in schema.LINEAGE)
            con.execute(f"COPY (SELECT {narrow} FROM read_json_objects('{src}', format='newline_delimited')) TO '{dst}' (FORMAT parquet, COMPRESSION zstd)")
            src.unlink(); dst.unlink()
        res["C2b_narrow_read_lineage_write_s"] = time.time() - t0
        # C": one group per class (size rotation)
        by_class = {}
        for (sp, cu, day), rows in groups.items():
            by_class.setdefault(cu, []).extend(rows)
        t0 = time.time(); files = 0
        for cu, rows in by_class.items():
            if cu in classes:
                copy(rows, cu, schema.select_list(str(pinned), cu), "k"); files += 1
        res["C3_convert_one_file_per_class_s"] = time.time() - t0
        res["C3_files"] = files
        # P: cProfile of one full flush (with the day partitioning, as the writer does it)
        pr = cProfile.Profile(); pr.enable(); written = lk.flush(force=True); pr.disable()
        s = io.StringIO(); pstats.Stats(pr, stream=s).sort_stats("cumulative").print_stats(12)
        res["P_flush_rows"] = written
        res["P_profile_top"] = [l for l in s.getvalue().splitlines() if l.strip()][:30]
        con.close()
    finally:
        shutil.rmtree(run, ignore_errors=True)
    res["total_A_B_C_s"] = res["A_ingest_s"] + res["B_group_s"] + res["C_convert_s"]
    for k in ("A_ingest_s", "B_group_s", "C_convert_s"):
        res[k.replace("_s", "_share")] = round(res[k] / res["total_A_B_C_s"], 3)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps({k: v for k, v in res.items() if k != "P_profile_top"}, indent=1))
    print("\n".join(res["P_profile_top"]))


if __name__ == "__main__":
    main()
