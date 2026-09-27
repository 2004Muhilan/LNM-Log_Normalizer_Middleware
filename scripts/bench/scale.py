#!/usr/bin/env python3
"""Scale-out across processes, measured end to end (laptop branch, 2026-09-27). Standard library + DuckDB; OpenSearch
must be reachable.

    python3 scripts/bench/scale.py --mixed ~/ulpf-demo/p6/mixed.log --packs ~/ulpf-demo/p6/source-packs [--quick] [--death]

Per run: P runtime processes share ONE TCP port (SO_REUSEPORT; the kernel hashes each connection to one process). Each
has its own evidence store WITH THE EVIDENCE ARCHIVE ON (a committer per store ships to one shared archive; the store
deletes shipped segments after a short grace), its own spool, and forwards to the SIEM (OpenSearch, bulk) and to its
own lake writer (one lake root). G independent generators — separate processes, each from its own source address
127.0.0.(10+g), one TCP connection — send their share of N events. Timed from the first byte sent until BOTH
destinations have acknowledged every event (the runtimes' cursors), then:
  exactly-once   events generated = SIEM documents (distinct ids) = lake rows (distinct event ids), none rejected
  affinity       every sender's events were all handled by ONE process (read off every store's evidence, local + archive)
The input: the four-vendor mixed capture's lines that parse (the quarantined ones left out, so every generated event
is expected in both destinations), repeated. The matrix: 1, 2, 4, 8 generators x 1, 2, 4 processes, three runs each,
median reported. --death: P=2, G=4 — one process is killed (SIGKILL) mid-run; its senders reconnect, and the report
says where they went, what was accepted by the dead process, and that after it is restarted on its own evidence and
spool nothing accepted is lost.
Disk: every run in its own directory, deleted afterwards with its OpenSearch indices; a guard stops a run past the
budget or the free-space floor.
"""
import argparse
import glob
import hashlib
import json
import os
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import throughput as tp  # noqa: E402

ROOT = tp.ROOT
BIN = Path(os.environ.get("ULPF_BENCH_BIN", str(ROOT / "runtime/bin")))   # a frozen copy: rebuilding runtime/bin mid-matrix cannot change what is measured
RT, CM = BIN / "ulpf-runtime", BIN / "ulpf-committer"
tp.IDX = "ulpf-scale-"
PORT, LAKE_BASE = 7614, 8900

GEN = r'''
import socket, sys, time, json
src, port, path, first, count, out, rate = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6], float(sys.argv[7])
lines = [l for l in open(path, "rb").read().splitlines() if l.strip()]
frames = [str(len(l)).encode() + b" " + l for l in lines]
sent, reconnects, t0 = 0, 0, time.time()
def connect():
    for _ in range(200):
        try:
            s = socket.socket(); s.bind((src, 0)); s.connect(("127.0.0.1", port)); return s
        except OSError:
            time.sleep(0.05)
    raise SystemExit("could not connect")
s = connect(); ports = [s.getsockname()[1]]
i = first
while sent < count:
    n = min(100 if rate else 500, count - sent)
    if rate:   # paced (the process-death run): the stream is still flowing when the process dies
        time.sleep(max(0.0, t0 + sent / rate - time.time()))
    chunk = b"".join(frames[(i + k) % len(frames)] for k in range(n))
    try:
        s.sendall(chunk)
        sent += n; i += n
    except OSError:
        reconnects += 1; s.close(); s = connect(); ports.append(s.getsockname()[1])   # the chunk counts as not sent: sent again
s.close()
json.dump({"src": src, "sent": sent, "reconnects": reconnects, "source_ports": ports, "t0": t0, "t1": time.time()}, open(out, "w"))
'''


def parseable_subset(a, work):
    """The mixed capture's lines that parse: run it once, leave out every line whose raw hash was quarantined."""
    d = Path(tempfile.mkdtemp(dir=work, prefix="subset-"))
    try:
        lines = [l for l in Path(a.mixed).read_bytes().splitlines() if l.strip()]
        (d / "in.log").write_bytes(b"\n".join(lines) + b"\n")
        subprocess.run([str(RT), "run", "--dev-no-evidence-archive", *tp.pack_args(a), "--source-id", "scale-01", "--input", str(d / "in.log"), "--evidence", str(d / "ev"),
                        "--out", "/dev/null", "--quarantine", str(d / "q.jsonl")], check=True, capture_output=True)
        bad = {json.loads(l)["raw_hash"] for l in open(d / "q.jsonl")}
        keep = [l for l in lines if "sha256:" + hashlib.sha256(l).hexdigest() not in bad]
        out = Path(work) / "parseable.log"
        out.write_bytes(b"\n".join(keep) + b"\n")
        return out, len(lines), len(keep)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def cursors(run, P):
    got = {"siem": 0, "lake": 0}
    for i in range(1, P + 1):
        for c in glob.glob(str(run / f"spool-{i}" / "cursor-*.json")):
            try:
                d = json.load(open(c))
            except (OSError, ValueError):
                continue
            got["siem" if d["sink"].startswith("bulk+") else "lake"] += d.get("delivered_events", 0)
    return got


def start_proc(a, run, i, P, archive):
    ev, spool, cdir = run / f"ev-{i}", run / f"spool-{i}", run / f"commit-{i}"
    cdir.mkdir(parents=True, exist_ok=True)
    lw = subprocess.Popen([sys.executable, str(ROOT / "adapters/lake/lakewriter.py"), "--lake", str(run / "lake"), "--listen", f"127.0.0.1:{LAKE_BASE + i}", "--writer-id", str(i)],
                          stdout=subprocess.DEVNULL, stderr=open(run / f"lw-{i}.err", "wb"))
    rt = subprocess.Popen([str(RT), "run", *tp.pack_args(a), "--source-id", f"scale-{i:02d}", "--listen", f"tcp:127.0.0.1:{PORT}", "--reuse-port", "--idle-timeout", "600s",
                           "--evidence", str(ev), "--spool", str(spool), "--spool-cap", "4GiB", "--quarantine", "/dev/null",
                           "--evidence-archive", str(archive), "--commit-dir", str(cdir), "--evidence-grace", "10s", "--evidence-buffer-cap", "4GiB",
                           "--forward", f"bulk+{tp.OS_URL}?index={tp.IDX}{{class_uid}}", "--forward", f"http://127.0.0.1:{LAKE_BASE + i}/ingest?batch=1000",
                           "--forward-drain", "300s"], stdout=subprocess.DEVNULL, stderr=open(run / f"rt-{i}.err", "wb"))
    cm = subprocess.Popen([str(CM), "commit", "--evidence", str(ev), "--commit", str(cdir), "--key", str(ROOT / "keys/dev/ulpf-committer-dev.json"), "--every", "2s", "--archive", str(archive)],
                          env={**os.environ, "ULPF_COMMIT_SEALED": "1"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"i": i, "rt": rt, "lw": lw, "cm": cm}


def wait_listening(run, i, t=15):
    for _ in range(int(t * 10)):
        try:
            if "listening for syslog over TCP" in (run / f"rt-{i}.err").read_text(errors="replace"):
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def affinity(run, P, archive):
    """sender address -> the processes whose evidence holds its events; connection (addr:port) -> processes."""
    by_src, by_conn, per_proc = {}, {}, {}
    for i in range(1, P + 1):
        ev = run / f"ev-{i}"
        sid = json.load(open(ev / "store.json"))["store_id"] if (ev / "store.json").exists() else None
        idx = {}
        if sid:
            idx.update({os.path.basename(p): p for p in glob.glob(str(archive / sid / "segments" / "seg_*.idx.jsonl"))})
        idx.update({os.path.basename(p): p for p in glob.glob(str(ev / "seg_*.idx.jsonl"))})
        n = 0
        for p in idx.values():
            for l in open(p, encoding="utf-8"):
                r = json.loads(l)
                if r.get("framing", {}).get("method") == "gap_record" or not r.get("peer"):
                    continue
                n += 1
                by_conn.setdefault(r["peer"], set()).add(i)
                by_src.setdefault(r["peer"].rsplit(":", 1)[0], set()).add(i)
        per_proc[i] = n
    return by_src, by_conn, per_proc


def lake_rows(run):
    import duckdb
    fs = glob.glob(str(run / "lake" / "ext" / "*" / "*" / "*" / "*" / "*.parquet"))
    if not fs:
        return 0, 0
    return duckdb.connect().execute(f"SELECT count(*), count(DISTINCT event_id) FROM read_parquet({fs!r})").fetchone()


def os_docs():
    tp.http("POST", f"/{tp.IDX}*/_refresh")
    st, r = tp.http("POST", f"/{tp.IDX}*/_search", {"size": 0, "track_total_hits": True, "aggs": {"u": {"cardinality": {"field": "_lineage.event_id", "precision_threshold": 40000}}}})
    return r.get("hits", {}).get("total", {}).get("value", 0), r.get("aggregations", {}).get("u", {}).get("value", 0)


def one_run(a, subset, P, G, N, death=False):
    tp.os_clear()
    run = Path(tempfile.mkdtemp(dir=a.work, prefix=f"scale-p{P}g{G}-"))
    archive = run / "archive"; archive.mkdir()
    procs = []
    gens = []
    try:
        for i in range(1, P + 1):
            procs.append(start_proc(a, run, i, P, archive))
        for p in procs:
            if not wait_listening(run, p["i"]):
                raise RuntimeError(f"process {p['i']} did not start listening: " + (run / f"rt-{p['i']}.err").read_text()[-400:])
        for i in range(1, P + 1):   # the lake writers
            for _ in range(100):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{LAKE_BASE + i}/status", timeout=1); break
                except OSError:
                    time.sleep(0.1)
        pids = lambda: [x.pid for p in procs for x in (p["rt"], p["lw"], p["cm"]) if x.poll() is None] + [g.pid for g in gens if g.poll() is None]
        guard = tp.Guard(a, run, pids)
        cpu0 = {k: [tp.proc_cpu_s(p[k].pid) for p in procs] for k in ("rt", "lw", "cm")}; os0 = tp.os_cpu_s()
        per = N // G
        t0 = time.time()
        for g in range(G):
            gens.append(subprocess.Popen([sys.executable, "-c", GEN, f"127.0.0.{10 + g}", str(PORT), str(subset), str(g * 7), str(per if g < G - 1 else N - per * (G - 1)), str(run / f"gen-{g}.json"),
                                          str(a.death_rate if death else 0)]))
        killed = None
        if death:   # kill the process that holds the most connections, at ~40 % of the stream
            while cursors(run, P)["siem"] < N * 0.4 and time.time() - t0 < 300:
                time.sleep(0.05)
            by_src, _, per_now = affinity(run, P, archive)
            vi = max(per_now, key=per_now.get)
            victim = procs[vi - 1]
            victim["rt"].send_signal(signal.SIGKILL); victim["rt"].wait()
            killed = {"process": vi, "at_s": round(time.time() - t0, 2), "delivered_by_all_at_kill": cursors(run, P),
                      "its_senders_before": sorted(s_ for s_, ps in by_src.items() if vi in ps)}
        for g in gens:
            g.wait(600)
        t_sent = time.time()
        if death:   # restart the dead process on ITS OWN evidence and spool: it resumes and delivers what it had accepted
            time.sleep(1)
            vi = killed["process"]
            killed["accepted_by_dead_process"] = count_evidence(run / f"ev-{vi}", archive)
            killed["undelivered_in_its_spool_before_restart"] = killed["accepted_by_dead_process"] - sum(
                json.load(open(c)).get("delivered_events", 0) for c in glob.glob(str(run / f"spool-{vi}" / "cursor-*.json")) if "bulk+" in open(c).read())
            procs[vi - 1]["rt"] = start_proc_rt_only(a, run, vi, archive)
            wait_listening(run, vi)
        target = N
        deadline = time.time() + a.timeout
        last_check = 0
        t_siem = t_lake = None
        settled = not death
        while time.time() < deadline:
            c = cursors(run, P)
            if t_siem is None and c["siem"] >= target and (settled if death else True):
                t_siem = time.time()
            if t_lake is None and c["lake"] >= target and (settled if death else True):
                t_lake = time.time()
            if death and time.time() - last_check >= 1:   # what was ACCEPTED (committed to some evidence store) is the target
                prev, target, last_check = target, expected_total(run, P, archive), time.time()
                settled = prev == target
            elif not death:
                settled = True
            if settled and c["siem"] >= target and c["lake"] >= target:
                break
            if guard.tripped:
                raise RuntimeError("STOPPED BY THE DISK GUARD: " + guard.tripped)
            time.sleep(0.1)
        t_ack = time.time()
        c = cursors(run, P)
        cpu1 = {k: [tp.proc_cpu_s(p[k].pid) for p in procs] for k in ("rt", "lw", "cm")}; os1 = tp.os_cpu_s()
        for p in procs:
            p["rt"].send_signal(signal.SIGTERM)
        for p in procs:
            p["rt"].wait(120)
        # every row into Parquet: the writers' final flushes, in parallel, TIMED (the lake acknowledges on durable staging;
        # the conversion to Parquet is the rest of its work — with one process it happens during the run, when the staged
        # bytes pass the rotation size; with more, each writer stages less and converts at the end)
        fl = [threading.Thread(target=lambda i=i: urllib.request.urlopen(f"http://127.0.0.1:{LAKE_BASE + i}/flush", timeout=900).read()) for i in range(1, P + 1)]
        [x.start() for x in fl]; [x.join() for x in fl]
        t_parquet = time.time()
        guard.stop.set()
        gen_out = [json.load(open(run / f"gen-{g}.json")) for g in range(G)]
        sent = sum(x["sent"] for x in gen_out)
        docs, _approx = os_docs()   # the SIEM's _id IS the event id: one document per id by construction
        rows, rows_distinct = lake_rows(run)
        by_src, by_conn, per_proc = affinity(run, P, archive)
        evidence_events = sum(per_proc.values())
        wall = t_ack - t0
        n_ok = evidence_events if death else N
        res = {"processes": P, "generators": G, "events": N, "sent": sent, "wall_s": round(wall, 2), "eps": round(N / wall), "send_s": round(t_sent - t0, 2),
               "siem_acknowledged_s": round((t_siem or t_ack) - t0, 2), "lake_acknowledged_s": round((t_lake or t_ack) - t0, 2), "in_parquet_s": round(t_parquet - t0, 2),
               "eps_into_siem": round(n_ok / ((t_siem or t_ack) - t0)), "eps_until_parquet": round(n_ok / (t_parquet - t0)),
               "acknowledged": c, "siem_docs": docs, "target": target, "timed_out": t_ack >= deadline, "lake_rows": rows, "lake_distinct": rows_distinct, "evidence_events": evidence_events,
               "per_process_events": per_proc, "senders_per_process": {i: sorted(s for s, ps in by_src.items() if i in ps) for i in range(1, P + 1)},
               "senders_on_more_than_one_process": {s: sorted(ps) for s, ps in by_src.items() if len(ps) > 1},
               "connections_on_more_than_one_process": {c_: sorted(ps) for c_, ps in by_conn.items() if len(ps) > 1},
               "cpu_s": {k: round(sum((x1 or 0) - (x0 or 0) for x0, x1 in zip(cpu0[k], cpu1[k])), 1) for k in cpu0},
               "opensearch_cpu_s": round(os1 - os0, 1) if os0 and os1 else None, "peak_run_bytes": guard.peak,
               "archived_segments": len(glob.glob(str(archive / "*" / "receipts" / "*.json"))), "deleted_locally": len(glob.glob(str(run / "ev-*" / "catalog" / "*.ids")))}
        if death:
            after = {s_: sorted(ps) for s_, ps in by_src.items()}
            res["death"] = {**killed, "generators": gen_out, "evidence_events_total": evidence_events,
                            "sent_total": sent, "lost_in_flight": sent - evidence_events,
                            "moved_senders": {x["src"]: {"reconnects": x["reconnects"], "source_ports": x["source_ports"], "processes": after.get(x["src"])} for x in gen_out if x["reconnects"]}}
            res["exactly_once"] = docs == rows == rows_distinct == evidence_events   # nothing ACCEPTED lost or duplicated
            try:   # what the restarted process recovered: committed by it before the kill, never interpreted
                st_ = [l for l in (run / f"rt-{killed['process']}-restart.err").read_text().splitlines() if l.startswith("{")][-1]
                res["death"]["recovered_after_crash"] = json.loads(st_).get("recovered_after_crash", 0)
            except (OSError, IndexError, ValueError):
                res["death"]["recovered_after_crash"] = None
        else:
            res["exactly_once"] = docs == rows == rows_distinct == N == sent == evidence_events
            res["affinity_ok"] = not res["senders_on_more_than_one_process"]
        return res
    finally:
        for p in procs:
            for k in ("rt", "lw", "cm"):
                if p[k].poll() is None:
                    p[k].terminate()
                    try:
                        p[k].wait(30)
                    except subprocess.TimeoutExpired:
                        p[k].kill()
        for g in gens:
            if g.poll() is None:
                g.kill()
        shutil.rmtree(run, ignore_errors=True)
        tp.os_clear()


def start_proc_rt_only(a, run, i, archive):
    return subprocess.Popen([str(RT), "run", *tp.pack_args(a), "--source-id", f"scale-{i:02d}", "--listen", f"tcp:127.0.0.1:{PORT}", "--reuse-port", "--idle-timeout", "600s",
                             "--evidence", str(run / f"ev-{i}"), "--spool", str(run / f"spool-{i}"), "--spool-cap", "4GiB", "--quarantine", "/dev/null",
                             "--evidence-archive", str(archive), "--commit-dir", str(run / f"commit-{i}"), "--evidence-grace", "10s", "--evidence-buffer-cap", "4GiB",
                             "--forward", f"bulk+{tp.OS_URL}?index={tp.IDX}{{class_uid}}", "--forward", f"http://127.0.0.1:{LAKE_BASE + i}/ingest?batch=1000",
                             "--forward-drain", "300s"], stdout=subprocess.DEVNULL, stderr=open(run / f"rt-{i}-restart.err", "wb"))


def count_evidence(ev, archive):
    sid = json.load(open(ev / "store.json"))["store_id"]
    idx = {os.path.basename(p): p for p in glob.glob(str(archive / sid / "segments" / "seg_*.idx.jsonl"))}
    idx.update({os.path.basename(p): p for p in glob.glob(str(ev / "seg_*.idx.jsonl"))})
    return sum(1 for p in idx.values() for l in open(p, encoding="utf-8") if '"gap_record"' not in l)


def expected_total(run, P, archive):
    return sum(count_evidence(run / f"ev-{i}", archive) for i in range(1, P + 1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mixed", required=True); ap.add_argument("--packs", required=True)
    ap.add_argument("--work", default=str(Path.home() / "ulpf-bench")); ap.add_argument("--budget-gb", type=float, default=6); ap.add_argument("--floor-gb", type=float, default=40)
    ap.add_argument("--events", type=int, default=120000); ap.add_argument("--reps", type=int, default=3); ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--procs", default="1,2,4"); ap.add_argument("--gens", default="1,2,4,8")
    ap.add_argument("--quick", action="store_true"); ap.add_argument("--death", action="store_true"); ap.add_argument("--no-matrix", action="store_true")
    ap.add_argument("--death-rate", type=float, default=500, help="events/s per generator in the process-death run (below capacity: 4 x 500 = 2,000/s)")
    ap.add_argument("--out", default=str(ROOT / "docs" / "metrics" / "scale.json"))
    a = ap.parse_args()
    a.os = True
    if a.quick:
        a.events, a.reps = 20000, 1
    for p in ("/", "/mnt/c"):
        if tp.free_gb(p) < a.floor_gb + a.budget_gb:
            sys.exit(f"not enough free disk on {p}")
    Path(a.work).mkdir(parents=True, exist_ok=True)
    tp.os_prepare()
    subset, total_lines, kept = parseable_subset(a, a.work)
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    res = {"machine": {"cpu": cpu, "logical_cpus": os.cpu_count(), "memory_gb_visible_to_wsl": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9, 1),
                       "opensearch": "2.19.2, one node, 512 MB heap", "commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(),
                       "at": time.strftime("%Y-%m-%dT%H:%M:%S")},
           "input": {"lines_in_capture": total_lines, "parseable_lines_used": kept, "events_per_run": a.events},
           "config": {"archive": "on (committer per store every 2 s, grace 10 s)", "group_commit": "256 frames / 10 ms", "lake": "one writer per process, 1,000-event batches, rotation 128 MiB / 300 s, final flush timed",
                      "siem": "one bulk forwarder per process, 100 documents per request"},
           "disk_free_gb_before": {"/": tp.free_gb("/"), "/mnt/c": tp.free_gb("/mnt/c")}, "matrix": {}}
    try:
        if not a.no_matrix:
            for P in map(int, a.procs.split(",")):
                for G in map(int, a.gens.split(",")):
                    runs = [one_run(a, subset, P, G, a.events) for _ in range(a.reps)]
                    key = f"P{P}_G{G}"
                    res["matrix"][key] = {"runs": runs, "median_eps": statistics.median(r["eps"] for r in runs), "median_wall_s": statistics.median(r["wall_s"] for r in runs),
                                          "median_eps_into_siem": statistics.median(r["eps_into_siem"] for r in runs), "median_eps_until_parquet": statistics.median(r["eps_until_parquet"] for r in runs),
                                          "exactly_once_all": all(r["exactly_once"] for r in runs), "affinity_all": all(r["affinity_ok"] for r in runs)}
                    print(f"{key}: median {res['matrix'][key]['median_eps']} ev/s acknowledged by both ({[r['eps'] for r in runs]}), SIEM {res['matrix'][key]['median_eps_into_siem']}, until Parquet {res['matrix'][key]['median_eps_until_parquet']} ({[r['eps_until_parquet'] for r in runs]}), exactly-once {res['matrix'][key]['exactly_once_all']}, "
                          f"affinity {res['matrix'][key]['affinity_all']}, per process {[r['per_process_events'] for r in runs][0]}", flush=True)
                    Path(a.out).write_text(json.dumps(res, indent=1, default=str) + "\n")
        if a.death:
            res["death"] = one_run(a, subset, 2, 4, a.events, death=True)
            print("death:", json.dumps({k: res["death"][k] for k in ("exactly_once", "death", "siem_docs", "lake_rows", "evidence_events", "sent")}, default=str)[:1500], flush=True)
    finally:
        tp.http("DELETE", "/_index_template/ulpf-bench"); tp.os_clear()
        res["disk_free_gb_after"] = {"/": tp.free_gb("/"), "/mnt/c": tp.free_gb("/mnt/c")}
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(res, indent=1, default=str) + "\n")
        print("written:", a.out)


if __name__ == "__main__":
    main()
