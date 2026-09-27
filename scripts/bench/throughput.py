#!/usr/bin/env python3
"""Throughput of ULPF, measured (laptop branch, 2026-09-27). Standard library only; OpenSearch must be reachable for 3 and 4.

    python3 scripts/bench/throughput.py --mixed ~/ulpf-demo/p6/mixed.log --packs ~/ulpf-demo/p6/source-packs [--quick]

Input: the four-vendor mixed capture built by demo/reset.sh (ASA, PAN-OS, FortiGate, Squid — relay-wrapped, with the
adversarial and not-onboarded lines it was built with), REPEATED to the sample size: routing across several packs is part
of what is measured; the content repeats (98 distinct lines), which a real stream would not.

  1  parse     ulpf-bench: framing -> unwrap -> route -> parse -> normalize -> JSON, no evidence store, no egress;
               1, 4 and 8 independent pipelines (the scaling model: one stream per runtime process)
  2  evidence  the real runtime binary, `run --input`: raw bytes hashed and staged, committed in batches (group commit,
               invariant 3: no event parsed or delivered before its batch is durable; defaults 256 frames / 10 ms), then
               parsed; on the ext4 disk (how it runs) and on tmpfs (the fsync cost isolated); 2c: the same with
               --commit-events 1 (an fsync per event, as built before 2026-09-27) for the before/after on the same commit
  3  bulk      `ulpf-runtime forward` of N normalized events into OpenSearch through the bulk sink alone
  4  e2e       the real runtime: evidence (ext4) -> spool -> OpenSearch (bulk) AND the Parquet lake writer, timed until
               BOTH have acknowledged every event; then the lake is flushed and counted
Every measurement runs three times; the median is reported with all three runs beside it.

Disk: a dedicated directory per run under --work, deleted after it (and the OpenSearch indices it created). A guard
thread stops a run when the run's files exceed --budget-gb or free space on / or on /mnt/c (where Docker's disk lives)
falls below --floor-gb. Every run is bounded by an event count.
"""
import argparse
import datetime as dt
import glob
import json
import os
import platform
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RT, BENCH = ROOT / "runtime/bin/ulpf-runtime", ROOT / "runtime/bin/ulpf-bench"
OS_URL = "http://127.0.0.1:9200"
IDX = "ulpf-bench-"
DAY = 86400
TARGET = 1e9 / DAY   # events per second for one billion a day


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


def free_gb(path):
    s = os.statvfs(path)
    return s.f_bavail * s.f_frsize / 1e9


def du(path):
    tot = 0
    for dp, _, fs in os.walk(path):
        for f in fs:
            try:
                tot += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return tot


def http(method, path, body=None, ctype="application/json"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(OS_URL + path, data=data, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def os_index_bytes():
    st, r = http("GET", f"/{IDX}*/_stats/store,docs")
    if st != 200:
        return 0, 0
    a = r.get("_all", {}).get("primaries", {})
    return a.get("store", {}).get("size_in_bytes", 0), a.get("docs", {}).get("count", 0)


def os_cpu_s():
    r = sh(["docker", "exec", "ulpf-opensearch", "cat", "/sys/fs/cgroup/cpu.stat"])
    for l in r.stdout.splitlines():
        if l.startswith("usage_usec"):
            return int(l.split()[1]) / 1e6
    return None


def proc_cpu_s(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError):
        return None


def proc_rss_mb(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmHWM"):
                return int(l.split()[1]) / 1024
    except OSError:
        return None


class Guard:
    """Stops the run (kills the given pids) when its files pass the budget or free space passes the floor."""
    def __init__(self, a, run_dir, pids):
        self.a, self.run_dir, self.pids, self.tripped, self.peak, self.stop = a, run_dir, pids, None, 0, threading.Event()
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stop.wait(0.5):
            used = du(self.run_dir) + (os_index_bytes()[0] if self.a.os else 0)
            self.peak = max(self.peak, used)
            why = (f"run files {used / 1e9:.2f} GB > budget {self.a.budget_gb} GB" if used > self.a.budget_gb * 1e9 else
                   f"free on / {free_gb('/'):.0f} GB < floor" if free_gb("/") < self.a.floor_gb else
                   f"free on /mnt/c {free_gb('/mnt/c'):.0f} GB < floor" if free_gb("/mnt/c") < self.a.floor_gb else None)
            if why:
                self.tripped = why
                for p in self.pids():
                    try:
                        os.kill(p, signal.SIGKILL)
                    except OSError:
                        pass
                return


def replicate(mixed, n, dest):
    lines = [l for l in Path(mixed).read_bytes().splitlines(keepends=True) if l.strip()]
    with open(dest, "wb") as f:
        full, rest = divmod(n, len(lines))
        blob = b"".join(lines)
        for _ in range(full):
            f.write(blob)
        f.write(b"".join(lines[:rest]))
    return n


def children_rusage():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime, r.ru_maxrss / 1024


def pack_args(a):
    out = ["--pack", str(ROOT / "contracts/golden/squid-native")]
    for v in ("cisco-asa", "panos", "fortigate"):
        out += ["--pack", str(Path(a.packs) / v)]
    return out


# ------------------------------------------------------------------ 1 parse
def m_parse(a, workers, repeat):
    """W independent PROCESSES (one pipeline each), started together: the scaling model is one runtime per stream."""
    procs = [subprocess.Popen([str(BENCH), *pack_args(a), "--input", a.mixed, "--repeat", str(repeat), "--workers", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env={**os.environ, "GOMAXPROCS": "2"}) for _ in range(workers)]
    outs = []
    for pr in procs:
        o, e = pr.communicate()
        if pr.returncode:
            raise RuntimeError(e[-400:])
        outs.append(json.loads(o))
    ev = sum(d["frames"] for d in outs); wall = max(d["wall_s"] for d in outs); cpu = sum(d["cpu_s"] for d in outs)
    return {"events": ev, "emitted": sum(d["emitted"] for d in outs), "wall_s": wall, "cpu_s": cpu, "eps": ev / wall, "eps_per_core": ev / cpu,
            "max_rss_mb": max(d["max_rss_mb"] for d in outs), "processes": workers, "normalized_bytes_per_event": outs[0]["normalized_bytes_per_event"]}


# ------------------------------------------------------------------ 2 evidence
def m_evidence(a, n, where, extra=()):
    run = Path(tempfile_dir(a, where))
    try:
        inp = run / "input.log"; replicate(a.mixed, n, inp)
        ev = run / "ev"
        c0, _ = children_rusage()
        t0 = time.time()
        p = subprocess.Popen([str(RT), "run", *pack_args(a), "--source-id", "bench-mixed-01", "--input", str(inp), "--evidence", str(ev),
                              "--out", "/dev/null", "--quarantine", "/dev/null", *extra], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        g = Guard(a, run, lambda: [p.pid])
        _, err = p.communicate()
        wall = time.time() - t0
        g.stop.set()
        c1, rss = children_rusage()
        if g.tripped:
            raise RuntimeError("STOPPED BY THE DISK GUARD: " + g.tripped)
        st = json.loads([l for l in err.splitlines() if l.startswith("{")][-1])
        evb = du(ev)
        return {"events": st["frames"], "emitted": st["emitted"], "wall_s": wall, "cpu_s": c1 - c0, "eps": st["frames"] / wall, "eps_per_core": st["frames"] / max(c1 - c0, 1e-9),
                "max_rss_mb": rss, "evidence_bytes": evb, "evidence_bytes_per_event": evb / st["frames"], "input_bytes": inp.stat().st_size, "where": where,
                "evidence_commits": st.get("evidence_commits"), "events_per_commit": st["frames"] / max(st.get("evidence_commits") or 1, 1)}
    finally:
        shutil.rmtree(run, ignore_errors=True)


def tempfile_dir(a, where):
    base = Path("/dev/shm/ulpf-bench") if where == "tmpfs" else Path(a.work)
    base.mkdir(parents=True, exist_ok=True)
    d = base / f"run-{int(time.time() * 1000)}"
    d.mkdir()
    return d


# ------------------------------------------------------------------ OpenSearch helpers
def os_prepare():
    sys.path.insert(0, str(ROOT / "demo" / "siem"))
    import setup
    t = json.loads(json.dumps(setup.TEMPLATE)); t["index_patterns"] = [IDX + "*"]; t["priority"] = 300
    st, _ = http("PUT", "/_index_template/ulpf-bench", t)
    if st != 200:
        raise RuntimeError("could not put the bench index template")
    os_clear()


def os_clear():
    http("DELETE", f"/{IDX}*")


def os_count():
    http("POST", f"/{IDX}*/_refresh"); http("POST", f"/{IDX}*/_flush")
    return os_index_bytes()


# ------------------------------------------------------------------ 3 bulk sink alone
def m_bulk(a, jsonl, n):
    os_clear()
    run = Path(tempfile_dir(a, "ext4"))
    try:
        spool = run / "normalized.jsonl"; shutil.copyfile(jsonl, spool)
        cpu0 = os_cpu_s(); c0, _ = children_rusage()
        t0 = time.time()
        p = subprocess.Popen([str(RT), "forward", "--from", str(spool), "--to", f"bulk+{OS_URL}?index={IDX}{{class_uid}}", "--wait", "600s"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        g = Guard(a, run, lambda: [p.pid])
        mem = []; th = threading.Thread(target=lambda: sample_mem(p, mem), daemon=True); th.start()
        _, err = p.communicate()
        wall = time.time() - t0
        g.stop.set()
        c1, rss = children_rusage(); cpu1 = os_cpu_s()
        if g.tripped:
            raise RuntimeError("STOPPED BY THE DISK GUARD: " + g.tripped)
        st = json.loads([l for l in err.splitlines() if l.startswith("{")][-1])
        size, docs = os_count()
        return {"events": st["delivered_events"], "docs_in_index": docs, "wall_s": wall, "eps": st["delivered_events"] / wall, "forwarder_cpu_s": c1 - c0,
                "opensearch_cpu_s": (cpu1 - cpu0) if cpu0 is not None and cpu1 is not None else None, "opensearch_mem_max_mb": max(mem) if mem else None,
                "index_bytes": size, "index_bytes_per_event": size / max(docs, 1), "rejected": st.get("rejected_events", 0)}
    finally:
        shutil.rmtree(run, ignore_errors=True)
        os_clear()


def sample_mem(p, out):
    while p.poll() is None:
        r = sh(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", "ulpf-opensearch"])
        try:
            v = r.stdout.split("/")[0].strip()
            out.append(float(v[:-3]) * (1024 if v.endswith("GiB") else 1) if v.endswith(("GiB", "MiB")) else 0)
        except ValueError:
            pass
        time.sleep(1)


# ------------------------------------------------------------------ 3b the lake writer alone
def m_lake(a, jsonl):
    run = Path(tempfile_dir(a, "ext4")); lake = run / "lake"
    lw = subprocess.Popen([sys.executable, str(ROOT / "adapters/lake/lakewriter.py"), "--lake", str(lake), "--listen", "127.0.0.1:8894", "--rotate-bytes", "8MiB", "--rotate-seconds", "30"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen("http://127.0.0.1:8894/status", timeout=1); break
            except OSError:
                time.sleep(0.1)
        lines = Path(jsonl).read_bytes().splitlines(keepends=True)
        g = Guard(a, run, lambda: [lw.pid])
        c0 = proc_cpu_s(lw.pid); t0 = time.time(); off = 0
        for i in range(0, len(lines), 100):   # the forwarder's batch size
            b = b"".join(lines[i:i + 100])
            r = urllib.request.Request("http://127.0.0.1:8894/ingest", data=b, method="POST", headers={"X-ULPF-Spool-Id": "bench", "X-ULPF-Spool-Start": str(off), "X-ULPF-Spool-End": str(off + len(b))})
            urllib.request.urlopen(r, timeout=60).read(); off += len(b)
        t_ack = time.time() - t0
        urllib.request.urlopen("http://127.0.0.1:8894/flush", timeout=600).read()
        wall = time.time() - t0; c1 = proc_cpu_s(lw.pid); g.stop.set()
        if g.tripped:
            raise RuntimeError("STOPPED BY THE DISK GUARD: " + g.tripped)
        fs = sorted(glob.glob(str(lake / "ext" / "*" / "*" / "*" / "*" / "*.parquet")))
        days = len({f.split("eventDay=")[1].split("/")[0] for f in fs})
        pq = sum(os.path.getsize(f) for f in fs)
        return {"events": len(lines), "wall_s": wall, "eps": len(lines) / wall, "eps_acknowledged": len(lines) / t_ack, "lakewriter_cpu_s": c1 - c0,
                "eps_per_core": len(lines) / max(c1 - c0, 1e-9), "lakewriter_rss_mb": proc_rss_mb(lw.pid), "files": len(fs), "event_days": days,
                "parquet_bytes": pq, "jsonl_bytes": off, "parquet_vs_jsonl": pq / off}
    finally:
        lw.terminate(); lw.wait(30); shutil.rmtree(run, ignore_errors=True)


# ------------------------------------------------------------------ 4 end to end
def m_e2e(a, n):
    os_clear()
    run = Path(tempfile_dir(a, "ext4"))
    lake = run / "lake"
    lw = None
    try:
        inp = run / "input.log"; replicate(a.mixed, n, inp)
        lw = subprocess.Popen([sys.executable, str(ROOT / "adapters/lake/lakewriter.py"), "--lake", str(lake), "--listen", "127.0.0.1:8893", "--rotate-bytes", "8MiB", "--rotate-seconds", "30"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen("http://127.0.0.1:8893/status", timeout=1); break
            except OSError:
                time.sleep(0.1)
        cpu0 = os_cpu_s(); c0, _ = children_rusage(); lw0 = proc_cpu_s(lw.pid)
        t0 = time.time()
        p = subprocess.Popen([str(RT), "run", *pack_args(a), "--source-id", "bench-mixed-01", "--input", str(inp), "--evidence", str(run / "ev"),
                              "--spool", str(run / "spool"), "--spool-cap", "4GiB", "--forward", f"bulk+{OS_URL}?index={IDX}{{class_uid}}", "--forward", "http://127.0.0.1:8893/ingest",
                              "--forward-drain", "900s", "--quarantine", "/dev/null"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        g = Guard(a, run, lambda: [p.pid, lw.pid])
        mem, track = [], {}
        threading.Thread(target=lambda: sample_mem(p, mem), daemon=True).start()
        def cursors():   # when did each destination acknowledge its last event
            while p.poll() is None:
                for c in glob.glob(str(run / "spool" / "cursor-*.json")):
                    try:
                        d = json.load(open(c)); track.setdefault(d["sink"], []).append((time.time() - t0, d["delivered_events"]))
                    except (OSError, ValueError, KeyError):
                        pass
                time.sleep(0.25)
        threading.Thread(target=cursors, daemon=True).start()
        _, err = p.communicate()
        t_rt = time.time() - t0
        c1, rss = children_rusage()
        urllib.request.urlopen("http://127.0.0.1:8893/flush", timeout=300).read()
        t_lake = time.time() - t0
        lw1 = proc_cpu_s(lw.pid); lw_rss = proc_rss_mb(lw.pid); cpu1 = os_cpu_s()
        g.stop.set()
        if g.tripped:
            raise RuntimeError("STOPPED BY THE DISK GUARD: " + g.tripped)
        st = json.loads([l for l in err.splitlines() if l.startswith("{")][-1])
        emitted = st["emitted"]
        done = {k: next((t for t, v in pts if v >= emitted), t_rt) for k, pts in track.items()}
        size, docs = os_count()
        import duckdb
        fs = sorted(glob.glob(str(lake / "ext" / "*" / "*" / "*" / "*" / "*.parquet")))
        rows = duckdb.connect().execute(f"SELECT count(*) FROM read_parquet({fs!r})").fetchone()[0] if fs else 0
        pq = sum(os.path.getsize(f) for f in fs)
        jsonl = max((json.load(open(c))["offset"] for c in glob.glob(str(run / "spool" / "cursor-*.json"))), default=0)
        evb = du(run / "ev")
        return {"events": st["frames"], "emitted": emitted, "runtime_exit_s": t_rt, "wall_s": t_lake, "eps_end_to_end": st["frames"] / t_lake,
                "eps_ingest_until_all_acknowledged": st["frames"] / t_rt,
                "acknowledged_at_s": {("opensearch" if k.startswith("bulk+") else "lake"): round(v, 1) for k, v in done.items()},
                "runtime_cpu_s": c1 - c0, "runtime_max_rss_mb": rss, "lakewriter_cpu_s": (lw1 - lw0) if lw0 is not None and lw1 is not None else None, "lakewriter_rss_mb": lw_rss,
                "opensearch_cpu_s": (cpu1 - cpu0) if cpu0 is not None and cpu1 is not None else None, "opensearch_mem_max_mb": max(mem) if mem else None,
                "opensearch_docs": docs, "opensearch_index_bytes": size, "lake_rows": rows, "lake_parquet_bytes": pq, "lake_files": len(fs), "normalized_jsonl_bytes": jsonl,
                "evidence_bytes": evb, "peak_run_bytes": g.peak, "evidence_commits": st.get("evidence_commits"), "rejected": sum(e.get("rejected_events", 0) for e in st.get("egress", []))}
    finally:
        if lw and lw.poll() is None:
            lw.terminate(); lw.wait(30)
        shutil.rmtree(run, ignore_errors=True)
        os_clear()


def median_of(runs, key):
    vals = [r[key] for r in runs if r.get(key) is not None]
    return statistics.median(vals) if vals else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mixed", required=True); ap.add_argument("--packs", required=True)
    ap.add_argument("--work", default=str(Path.home() / "ulpf-bench")); ap.add_argument("--budget-gb", type=float, default=8); ap.add_argument("--floor-gb", type=float, default=40)
    ap.add_argument("--os", action="store_true", default=True); ap.add_argument("--quick", action="store_true", help="smaller samples, one run each (harness check)")
    ap.add_argument("--out", default=str(ROOT / "docs" / "metrics" / "throughput.json"))
    a = ap.parse_args()
    reps = 1 if a.quick else 3
    for p in ("/", "/mnt/c"):
        if free_gb(p) < a.floor_gb + a.budget_gb:
            sys.exit(f"not enough free disk on {p}: {free_gb(p):.0f} GB < floor {a.floor_gb} + budget {a.budget_gb} GB")
    Path(a.work).mkdir(parents=True, exist_ok=True)
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
    mem_gb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9
    osv = http("GET", "/")[1].get("version", {}).get("number")
    machine = {"cpu": cpu, "logical_cpus": os.cpu_count(), "memory_gb_visible_to_wsl": round(mem_gb, 1), "kernel": platform.release(), "disk": "WSL2 ext4 virtual disk (evidence, spool, lake); OpenSearch data in Docker Desktop's disk",
               "opensearch": osv, "opensearch_heap": "512 MB", "go": sh(["go", "version"]).stdout.strip(), "commit": sh(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"]).stdout.strip(),
               "at": dt.datetime.now().isoformat(timespec="seconds"), "group_commit": "runtime defaults: --commit-events 256, --commit-wait 10ms"}
    print("machine:", json.dumps(machine))
    res = {"machine": machine, "input": {"file": "the four-vendor mixed capture (demo/reset.sh -> scripts/p6-build-packs.sh)", "distinct_lines": sum(1 for l in open(a.mixed) if l.strip()),
                                         "packs": ["squid-native (golden)", "cisco-asa", "panos", "fortigate"], "note": "repeated to the sample size; content repeats"}, "runs": {}}
    free0 = {"/": free_gb("/"), "/mnt/c": free_gb("/mnt/c")}

    def record(name, runs, keys):
        res["runs"][name] = {"runs": runs, "median": {k: median_of(runs, k) for k in keys}}
        print(f"{name}: " + ", ".join(f"{k}={res['runs'][name]['median'][k]:.4g}" for k in keys if res["runs"][name]["median"][k] is not None), flush=True)

    rep = 300 if a.quick else 2000                        # 98 lines x 2000 = 196 000 events per pipeline
    for w in (1, 4, 8):
        record(f"1_parse_{w}_workers", [m_parse(a, w, rep) for _ in range(reps)], ["events", "wall_s", "eps", "eps_per_core", "cpu_s", "max_rss_mb"])
    cal = m_evidence(a, 3000, "ext4")                      # calibrate: size each evidence run to ~30 s
    n_ev = int(min(1_000_000, max(20_000, cal["eps"] * (8 if a.quick else 30))))
    record("2_evidence_ext4", [m_evidence(a, n_ev, "ext4") for _ in range(reps)], ["events", "wall_s", "eps", "eps_per_core", "cpu_s", "max_rss_mb", "evidence_bytes_per_event", "events_per_commit"])
    record("2b_evidence_tmpfs", [m_evidence(a, n_ev, "tmpfs") for _ in range(reps)], ["events", "wall_s", "eps", "eps_per_core", "cpu_s", "max_rss_mb", "events_per_commit"])
    record("2c_evidence_ext4_fsync_per_event", [m_evidence(a, 3000 if a.quick else 6000, "ext4", ("--commit-events", "1")) for _ in range(reps)], ["events", "wall_s", "eps", "eps_per_core", "cpu_s", "events_per_commit"])
    # a normalized JSONL for the bulk sink alone: the parse path's output, from the real binary
    run = Path(tempfile_dir(a, "ext4")); inp = run / "in.log"; n_bulk = 30_000 if a.quick else 150_000
    replicate(a.mixed, int(n_bulk / 0.9) + 100, inp)
    sh([str(RT), "run", *pack_args(a), "--source-id", "bench-mixed-01", "--input", str(inp), "--evidence", "/dev/shm/ulpf-bench/ev-jsonl", "--out", str(run / "normalized.jsonl"), "--quarantine", "/dev/null"])
    shutil.rmtree("/dev/shm/ulpf-bench/ev-jsonl", ignore_errors=True)
    os_prepare()
    try:
        record("3_bulk_into_opensearch", [m_bulk(a, run / "normalized.jsonl", n_bulk) for _ in range(reps)], ["events", "wall_s", "eps", "forwarder_cpu_s", "opensearch_cpu_s", "opensearch_mem_max_mb", "index_bytes_per_event"])
        record("3b_lake_writer_alone", [m_lake(a, run / "normalized.jsonl") for _ in range(reps)], ["events", "wall_s", "eps", "eps_per_core", "lakewriter_cpu_s", "files", "event_days", "parquet_vs_jsonl"])
        shutil.rmtree(run, ignore_errors=True)
        # bounded: the lake writer (~1,700/s alone) sets the end-to-end pace once the evidence is batched; 200 000 events is
        # ~2 minutes of it and ~1.3 GB of run files at most (evidence, spool, index, lake)
        n_e2e = int(min(20_000 if a.quick else 200_000, max(20_000, res["runs"]["2_evidence_ext4"]["median"]["eps"] * (10 if a.quick else 45))))
        record("4_end_to_end", [m_e2e(a, n_e2e) for _ in range(reps)], ["events", "wall_s", "eps_end_to_end", "runtime_cpu_s", "lakewriter_cpu_s", "opensearch_cpu_s", "opensearch_mem_max_mb",
                                                                        "opensearch_index_bytes", "lake_parquet_bytes", "normalized_jsonl_bytes", "evidence_bytes"])
    finally:
        http("DELETE", "/_index_template/ulpf-bench"); os_clear()
        shutil.rmtree(run, ignore_errors=True); shutil.rmtree("/dev/shm/ulpf-bench", ignore_errors=True)
    res["disk_free_gb_before"] = free0; res["disk_free_gb_after"] = {"/": free_gb("/"), "/mnt/c": free_gb("/mnt/c")}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1) + "\n")
    print("written:", a.out)


if __name__ == "__main__":
    main()
