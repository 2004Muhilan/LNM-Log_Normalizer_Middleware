#!/usr/bin/env python3
"""What ULPF itself can handle, on one machine, with the work pinned to cores (laptop branch, 2026-09-28). Standard library
+ DuckDB (the lake count); OpenSearch only for suite C.

    python3 scripts/bench/capacity.py baseline                    # the batch's starting disk sizes (free space, WSL and Docker virtual disks)
    python3 scripts/bench/capacity.py prepare --mixed M --packs P --flowtap F
    python3 scripts/bench/capacity.py run --suite A|B|C|probe [--procs 1,2,4,6] [--senders 8,16,32] [--duration 180] [--reps 3] [--rate 0]

WHAT RUNS. P ULPF processes (`ulpf-runtime run`, one committer each: the evidence log AND the evidence archive on in every
run) share one TCP port with SO_REUSEPORT. Each forwards to two destinations: a SIEM — the gate's fake bulk receiver in its
measurement mode (suites A, B, probe) or real OpenSearch (C) — and its own lake writer (Parquet). S replay senders
(scripts/bench/replay.py), each from its own loopback address and port, replay pre-built log files of five device formats:
the four-vendor capture split by device (Cisco ASA, PAN-OS, FortiGate, Squid) and the demo generator's format (flowtap,
positional) — so routing across five packs is part of every run.

PINNED. Every process is started under `taskset` on a fixed set of logical CPUs (the layout is printed and recorded with
every result); OpenSearch's container gets `docker update --cpuset-cpus`. WSL2 shows 16 logical CPUs as 8 cores of 2
threads: CPUs 2k and 2k+1 are one core (core id k). They are virtual processors: Hyper-V runs each pair on one physical core
(the core scheduler) but which physical core it is may change, and Windows shares the machine.

MEASURED. CPU per component from /proc/<pid>/stat (all threads) and OpenSearch's cgroup: ULPF (runtimes + committers), lake
writers, the SIEM (fake receiver or OpenSearch), senders. Throughput: what the senders sent and ULPF accepted over the
window, what each destination acknowledged by the window's end (the runtimes' spool cursors), and the time to drain the
rest. A per-second series gives the steadiness (every 30 s slice). Exactly-once: sent = accepted (evidence records, local
+ archive) = SIEM (ids and distinct ids, or OpenSearch documents — `_id` is the event id) = lake rows = distinct lake event
ids, nothing quarantined. Affinity: every sender's records in ONE process's evidence.

DISK. Before a run: its size is estimated from the per-million figures and the run is not started over its budget. During
it: a watcher (every second) measures the run's evidence buffers, archive, spools, lake, SIEM ids / OpenSearch index,
free space on / and on C: (where both virtual disks live), and the two virtual disk files; it kills the run past the
budget or the floor, and stops the BATCH once the virtual disks have grown past --batch-growth-gb since `baseline`.
After it: everything deleted (and the OpenSearch indices).
"""
import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("ULPF_BENCH_BIN", str(ROOT / "runtime/bin")))   # a frozen copy: a rebuild mid-batch cannot change what is measured
RT, CM = BIN / "ulpf-runtime", BIN / "ulpf-committer"
WORK = Path(os.environ.get("ULPF_CAPACITY_WORK", str(Path.home() / "ulpf-capacity")))
OUT = ROOT / "docs" / "metrics" / "capacity.json"
PORT, LAKE_BASE, SIEM_BASE = 7700, 8900, 9300
OS_URL, IDX = "http://127.0.0.1:9200", "ulpf-cap-"
WIN = "/mnt/c/Users/g2con/AppData/Local"
VHDX = {"wsl": glob.glob(WIN + "/wsl/*/ext4.vhdx"), "docker": [WIN + "/Docker/wsl/disk/docker_data.vhdx"]}
PER_MILLION_GB = {"evidence": 0.844, "spool": 1.919, "opensearch": 0.66, "parquet": 0.54, "siem_ids": 0.03}   # docs/throughput.md, "Disk per million events"
TARGET = 1e9 / 86400


# ------------------------------------------------------------------ small helpers
def free_gb(p):
    s = os.statvfs(p)
    return s.f_bavail * s.f_frsize / 1e9


def vhdx_gb():
    return {k: round(sum(os.stat(f).st_size for f in fs if os.path.exists(f)) / 1e9, 3) for k, fs in VHDX.items()}


def du(p):
    if os.path.isfile(p):
        return os.lstat(p).st_blocks * 512
    tot = 0
    for dp, _, fs in os.walk(p):
        for f in fs:
            try:
                tot += os.lstat(os.path.join(dp, f)).st_blocks * 512
            except OSError:
                pass
    return tot


def http(method, path, body=None, base=OS_URL, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except OSError:
        return 0, {}


def os_bytes_docs():
    st, r = http("GET", f"/{IDX}*/_stats/store,docs")
    a = r.get("_all", {}).get("primaries", {}) if st == 200 else {}
    return a.get("store", {}).get("size_in_bytes", 0), a.get("docs", {}).get("count", 0)


def os_cpu_s():
    r = subprocess.run(["docker", "exec", "ulpf-opensearch", "cat", "/sys/fs/cgroup/cpu.stat"], capture_output=True, text=True)
    for l in r.stdout.splitlines():
        if l.startswith("usage_usec"):
            return int(l.split()[1]) / 1e6
    return None


def cpu_s(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError):
        return None


def cpus(spec):
    out = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b or a) + 1))
    return out


def cores_of(spec):
    return sorted({c // 2 for c in cpus(spec)})


def pinned(spec, cmd):
    return ["taskset", "-c", spec, *cmd]


def load(p, default=None):
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return default


# ------------------------------------------------------------------ layouts
def layout(a, P, suite):
    """The cores each component runs on (logical CPUs; core k = CPUs 2k, 2k+1). Chosen from the calibration (docs/throughput.md)."""
    if a.layout:
        return json.loads(a.layout)
    if suite in ("A", "probe"):   # one process uses ~1.1 cores: four are more than it can use; the lake writer gets three, enough to keep pace
        return {"ulpf": "0-7", "lake": "8-13", "senders": "14-15", "siem": "14-15"}
    if suite == "B":              # the same layout in every cell: six cores for ULPF, one for the lake writers, one for senders + SIEM stand-in
        return {"ulpf": "0-11", "lake": "12-13", "senders": "14-15", "siem": "14-15"}
    sys.exit("suite C needs --layout (chosen from B)")


# ------------------------------------------------------------------ prepare
def pack_dirs():
    d = WORK / "packs"
    return [str(ROOT / "contracts/golden/squid-native")] + [str(d / v) for v in ("cisco-asa", "panos", "fortigate", "flowtap")]


def pack_args():
    out = []
    for p in pack_dirs():
        out += ["--pack", p]
    return out


def vendor_of(parser_id):
    p = parser_id.lower()
    for k, v in (("squid", "squid"), ("asa", "asa"), ("cisco", "asa"), ("pan", "panos"), ("forti", "fortigate"), ("flowtap", "flowtap"), ("positional", "flowtap")):
        if k in p:
            return v
    return p


def prepare(a):
    WORK.mkdir(parents=True, exist_ok=True)
    pd = WORK / "packs"
    shutil.rmtree(pd, ignore_errors=True)
    for v in ("cisco-asa", "panos", "fortigate"):
        shutil.copytree(Path(a.packs) / v, pd / v)
    shutil.copytree(a.flowtap, pd / "flowtap")   # the generator's format, onboarded by the demo (logged in the transparency log)
    dv = WORK / "devices"
    shutil.rmtree(dv, ignore_errors=True); dv.mkdir()
    gen = subprocess.run([sys.executable, str(ROOT / "demo/live/flowgen.py"), "--sample", str(a.flowtap_lines), "--shape", "positional", "--format", "1"],
                         capture_output=True, check=True).stdout
    mixed = [l for l in Path(a.mixed).read_bytes().splitlines() if l.strip()]
    lines = mixed + [l for l in gen.splitlines() if l.strip()]
    t = Path(tempfile.mkdtemp(dir=WORK, prefix="prep-"))
    try:
        (t / "in.log").write_bytes(b"\n".join(lines) + b"\n")
        subprocess.run([str(RT), "run", "--dev-no-evidence-archive", *pack_args(), "--source-id", "prep-01", "--input", str(t / "in.log"), "--evidence", str(t / "ev"),
                        "--out", str(t / "out.jsonl"), "--quarantine", str(t / "q.jsonl")], check=True, capture_output=True)
        by_hash = {}
        for l in open(t / "out.jsonl"):
            lin = json.loads(l)["_lineage"]
            by_hash[lin["raw_hash"]] = vendor_of(lin["parser_id"])
        per = {}
        dropped = 0
        for l in lines:
            v = by_hash.get("sha256:" + hashlib.sha256(l).hexdigest())
            if v is None:
                dropped += 1   # quarantined (adversarial / not onboarded): left out, so every sent line is expected in both destinations
                continue
            per.setdefault(v, []).append(l)
        files = {}
        for v, ls in sorted(per.items()):
            f = dv / f"{v}.log"
            f.write_bytes(b"\n".join(ls) + b"\n")
            files[v] = str(f)
        # every device file, on its own, parses completely
        for v, f in files.items():
            q = t / f"q-{v}.jsonl"
            subprocess.run([str(RT), "run", "--dev-no-evidence-archive", *pack_args(), "--source-id", "prep-02", "--input", f, "--evidence", str(t / f"ev-{v}"),
                            "--out", "/dev/null", "--quarantine", str(q)], check=True, capture_output=True)
            if q.exists() and q.stat().st_size:
                sys.exit(f"device file {v} does not parse completely")
        json.dump(files, open(WORK / "devices.json", "w"), indent=1)
        info = {"device_formats": {v: len(ls) for v, ls in sorted(per.items())}, "left_out_quarantined_lines": dropped, "packs": [Path(p).name for p in pack_dirs()],
                "bytes_per_line": {v: round(sum(map(len, ls)) / len(ls)) for v, ls in per.items()}}
        json.dump(info, open(WORK / "devices-info.json", "w"), indent=1)
        print(json.dumps(info))
    finally:
        shutil.rmtree(t, ignore_errors=True)


# ------------------------------------------------------------------ disk
def baseline(a):
    WORK.mkdir(parents=True, exist_ok=True)
    b = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "free_gb": {"/": round(free_gb("/"), 1), "/mnt/c": round(free_gb("/mnt/c"), 1)}, "vhdx_gb": vhdx_gb()}
    json.dump(b, open(WORK / "batch.json", "w"), indent=1)
    print(json.dumps(b))


class Watcher:
    """Every second: the run's files per component (+ OpenSearch's index), free space, the virtual disks. Kills the run past a limit."""
    def __init__(self, a, run, pids, with_os):
        self.a, self.run, self.pids, self.with_os = a, run, pids, with_os
        self.batch = load(WORK / "batch.json")
        self.tripped, self.peak, self.peak_parts, self.last = None, 0, {}, {}
        self.stop = threading.Event()
        threading.Thread(target=self.loop, daemon=True).start()

    def parts(self):
        r = self.run
        p = {"evidence_buffer": sum(du(x) for x in r.glob("ev-*")), "archive": du(r / "archive"), "spool": sum(du(x) for x in r.glob("spool-*")),
             "lake": du(r / "lake"), "siem_ids": sum(du(x) for x in r.glob("siem-ids-*")), "other": 0}
        p["other"] = du(r) - sum(p.values())
        if self.with_os:
            p["opensearch"] = os_bytes_docs()[0]
        return p

    def loop(self):
        while not self.stop.wait(1.0):
            p = self.parts()
            used = sum(p.values())
            self.last = p
            if used > self.peak:
                self.peak, self.peak_parts = used, p
            vh = vhdx_gb()
            grown = {k: vh[k] - self.batch["vhdx_gb"][k] for k in vh} if self.batch else {}
            why = (f"run files {used / 1e9:.2f} GB > budget {self.a.budget_gb} GB" if used > self.a.budget_gb * 1e9 else
                   f"free on / {free_gb('/'):.0f} GB < floor {self.a.floor_gb}" if free_gb("/") < self.a.floor_gb else
                   f"free on C: {free_gb('/mnt/c'):.0f} GB < floor {self.a.floor_gb}" if free_gb("/mnt/c") < self.a.floor_gb else
                   f"virtual disks grew {grown} GB since the batch began > {self.a.batch_growth_gb}" if grown and max(grown.values()) > self.a.batch_growth_gb else None)
            if why:
                self.tripped = why
                for pid in self.pids():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                return


def estimate_gb(n_events, with_os, spool_frac):
    """The run's peak on disk: the archive holds every event's evidence; the spool holds what the slower destination has
    not yet acknowledged (spool_frac of the events); the lake and the SIEM hold what they received."""
    m = n_events / 1e6
    g = PER_MILLION_GB
    return m * (g["evidence"] + g["parquet"] + (g["opensearch"] if with_os else g["siem_ids"]) + g["spool"] * spool_frac)


# ------------------------------------------------------------------ one run
def cursors(run, P):
    got = {"siem": 0, "lake": 0}
    for i in range(1, P + 1):
        for c in glob.glob(str(run / f"spool-{i}" / "cursor-*.json")):
            d = load(c)
            if d:
                got["siem" if d["sink"].startswith("bulk+") else "lake"] += d.get("delivered_events", 0)
    return got


PEER = re.compile(rb'"peer":"([0-9.]+):(\d+)"')


def evidence(run, P):
    """Per process: its records (local buffer + archive), and the peers they came from."""
    per, by_src, by_conn = {}, {}, {}
    for i in range(1, P + 1):
        ev = run / f"ev-{i}"
        sid = (load(ev / "store.json") or {}).get("store_id")
        idx = {}
        if sid:
            idx.update({os.path.basename(p): p for p in glob.glob(str(run / "archive" / sid / "segments" / "seg_*.idx.jsonl"))})
        idx.update({os.path.basename(p): p for p in glob.glob(str(ev / "seg_*.idx.jsonl"))})
        n = 0
        for p in idx.values():
            data = open(p, "rb").read()
            for src, port in set(PEER.findall(data)):
                by_src.setdefault(src.decode(), set()).add(i)
                by_conn.setdefault(src.decode() + ":" + port.decode(), set()).add(i)
            n += data.count(b"\n") - data.count(b'"gap_record"')
        per[i] = n
    return per, by_src, by_conn


def lake_rows(run):
    import duckdb
    fs = glob.glob(str(run / "lake" / "ext" / "*" / "*" / "*" / "*" / "*.parquet"))
    if not fs:
        return 0, 0
    return duckdb.connect().execute(f"SELECT count(*), count(DISTINCT event_id) FROM read_parquet({fs!r})").fetchone()


def siem_ids(run, P):
    total, seen = 0, set()
    for i in range(1, P + 1):
        f = run / f"siem-ids-{i}.txt"
        if f.exists():
            with open(f, "rb") as fh:
                for l in fh:
                    total += 1
                    seen.add(l)
    return total, len(seen)


def wait_for(pred, t, step=0.1):
    end = time.time() + t
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def idx_bytes(run, P):
    """Bytes of evidence index written so far (local buffer + archive, each segment once): ULPF's accepted count as it
    grows, read without parsing (scaled to records by the final exact count). The senders' own count runs ahead of it
    by whatever sits in the socket buffers (up to several MB per connection)."""
    tot = 0
    for i in range(1, P + 1):
        ev = run / f"ev-{i}"
        sid = (load(ev / "store.json") or {}).get("store_id")
        sizes = {}
        for p in glob.glob(str(ev / "seg_*.idx.jsonl")) + (glob.glob(str(run / "archive" / sid / "segments" / "seg_*.idx.jsonl")) if sid else []):
            try:
                sizes[os.path.basename(p)] = max(sizes.get(os.path.basename(p), 0), os.path.getsize(p))
            except OSError:
                pass
        tot += sum(sizes.values())
    return tot


def one_run(a, P, S, D, rate, with_os, lay, label):
    os.sched_setaffinity(0, cpus(lay["senders"]))   # the harness itself (sampling, the watcher) stays off ULPF's cores
    run = Path(tempfile.mkdtemp(dir=WORK, prefix=f"run-{label}-"))
    archive = run / "archive"; archive.mkdir()
    procs, sender = [], None
    try:
        if with_os:
            http("DELETE", f"/{IDX}*")
        for i in range(1, P + 1):
            ev, spool, cdir = run / f"ev-{i}", run / f"spool-{i}", run / f"commit-{i}"
            cdir.mkdir()
            p = {"i": i}
            if not with_os:
                p["siem"] = subprocess.Popen(pinned(lay["siem"], [sys.executable, str(ROOT / "demo/siem/fake_bulk.py"), "--listen", f"127.0.0.1:{SIEM_BASE + i}", "--ids", str(run / f"siem-ids-{i}.txt")]),
                                             stdout=subprocess.DEVNULL, stderr=open(run / f"siem-{i}.err", "wb"))
            p["lw"] = subprocess.Popen(pinned(lay["lake"], [sys.executable, str(ROOT / "adapters/lake/lakewriter.py"), "--lake", str(run / "lake"), "--listen", f"127.0.0.1:{LAKE_BASE + i}", "--writer-id", str(i)]),
                                       stdout=subprocess.DEVNULL, stderr=open(run / f"lw-{i}.err", "wb"))
            siem = (f"bulk+{OS_URL}" if with_os else f"bulk+http://127.0.0.1:{SIEM_BASE + i}") + f"?index={IDX}{{class_uid}}&batch={a.batch}"
            p["rt"] = subprocess.Popen(pinned(lay["ulpf"], [str(RT), "run", *pack_args(), "--source-id", f"cap-{i:02d}", "--listen", f"tcp:127.0.0.1:{PORT}", "--reuse-port",
                                                             "--idle-timeout", "900s", "--evidence", str(ev), "--spool", str(spool), "--spool-cap", a.spool_cap,
                                                             "--quarantine", str(run / f"q-{i}.jsonl"), "--evidence-archive", str(archive), "--commit-dir", str(cdir),
                                                             "--evidence-grace", "10s", "--evidence-buffer-cap", "4GiB",
                                                             "--forward", siem, "--forward", f"http://127.0.0.1:{LAKE_BASE + i}/ingest?batch={a.batch}", "--forward-drain", "1200s"]),
                                       stdout=subprocess.DEVNULL, stderr=open(run / f"rt-{i}.err", "wb"))
            p["cm"] = subprocess.Popen(pinned(lay["ulpf"], [str(CM), "commit", "--evidence", str(ev), "--commit", str(cdir), "--key", str(ROOT / "keys/dev/ulpf-committer-dev.json"),
                                                             "--every", "2s", "--archive", str(archive)]),
                                       env={**os.environ, "ULPF_COMMIT_SEALED": "1"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p)
        for p in procs:
            f = run / f"rt-{p['i']}.err"
            if not wait_for(lambda: "listening for syslog over TCP" in f.read_text(errors="replace") if f.exists() else False, 20):
                raise RuntimeError(f"process {p['i']} did not listen: " + f.read_text(errors="replace")[-600:])
            for port in ([LAKE_BASE + p["i"]] + ([] if with_os else [SIEM_BASE + p["i"]])):
                if not wait_for(lambda: http("GET", "/ulpf/stats" if port >= SIEM_BASE else "/status", base=f"http://127.0.0.1:{port}", timeout=2)[0] == 200, 30):
                    raise RuntimeError(f"destination on {port} did not start")
        pids = lambda: ([sender.pid] if sender and sender.poll() is None else []) + [x.pid for p in procs for x in p.values() if hasattr(x, "pid") and x.poll() is None]
        watch = Watcher(a, run, pids, with_os)
        comp = {"ulpf": lambda: [x for p in procs for x in (p["rt"], p["cm"])], "lake_writers": lambda: [p["lw"] for p in procs],
                "siem": lambda: [p["siem"] for p in procs if "siem" in p]}
        last = {}

        def cpu_now():   # a process that has exited keeps its last reading
            c = {}
            for k, f in comp.items():
                tot = 0
                for x in f():
                    v = cpu_s(x.pid)
                    if v is not None:
                        last[x.pid] = v
                    tot += last.get(x.pid, 0)
                c[k] = tot
            if with_os:
                c["siem"] = os_cpu_s() or last.get("os", 0)
                last["os"] = c["siem"]
            return c
        st_path, out_path = run / "sender-status.json", run / "sender-out.json"
        sender = subprocess.Popen(pinned(lay["senders"], [sys.executable, str(ROOT / "scripts/bench/replay.py"), "--to", f"127.0.0.1:{PORT}", "--senders", str(S),
                                                          "--devices", str(WORK / "devices.json"), "--duration", str(D), "--rate", str(rate),
                                                          "--status", str(st_path), "--out", str(out_path)]), stderr=open(run / "sender.err", "wb"))
        if not wait_for(lambda: st_path.exists(), 60):
            raise RuntimeError("the senders did not start: " + (run / "sender.err").read_text()[-400:])
        t0 = load(st_path)["t0"]
        # one sample a second until both destinations have acknowledged everything the senders sent:
        # t, sent, evidence index bytes (-> accepted), SIEM acknowledged, lake acknowledged, CPU per component
        series, sent, out = [], None, None
        deadline, repinned = None, None
        while True:
            now = time.time()
            s, c = load(st_path) or {}, cursors(run, P)
            series.append({"t": round(now - t0, 1), "sent": s.get("sent", 0), "idx": idx_bytes(run, P), "siem": c["siem"], "lake": c["lake"], "cpu": cpu_now()})
            if watch.tripped:
                raise RuntimeError("STOPPED BY THE DISK WATCHER: " + watch.tripped)
            if out is None and sender.poll() is not None:
                out = load(out_path)
                if not out:
                    raise RuntimeError("the senders left no result: " + (run / "sender.err").read_text()[-600:])
                sent, deadline = out["sent"], time.time() + a.drain_timeout
            if out is not None and repinned is None and len(series) > 3 and series[-1]["idx"] == series[-4]["idx"] and c["lake"] < sent:
                # ULPF has taken in everything: the measurement is over; the lake writers' backlog is drained on every
                # core (only to verify exactly-once sooner — nothing after this point is a throughput figure)
                for p in procs:
                    subprocess.run(["taskset", "-a", "-p", "-c", f"0-{os.cpu_count() - 1}", str(p["lw"].pid)], capture_output=True)
                repinned = series[-1]["t"]
            if out is not None and ((c["siem"] >= sent and c["lake"] >= sent) or time.time() > deadline):
                break
            time.sleep(max(0.0, 1.0 - (time.time() - now)))
        for p in procs:
            p["rt"].send_signal(signal.SIGTERM)
        stats = {}
        for p in procs:
            p["rt"].wait(300)
            try:
                stats[p["i"]] = json.loads([l for l in (run / f"rt-{p['i']}.err").read_text().splitlines() if l.startswith("{")][-1])
            except (IndexError, ValueError):
                stats[p["i"]] = {}
        tf = time.time()
        fl = [threading.Thread(target=lambda i=p["i"]: urllib.request.urlopen(f"http://127.0.0.1:{LAKE_BASE + i}/flush", timeout=1800).read()) for p in procs]
        [x.start() for x in fl]; [x.join() for x in fl]
        flush_s = time.time() - tf
        c_end = cpu_now()
        disk_at_drain = watch.last
        watch.stop.set()
        time.sleep(3)   # the committers' last pass
        per_proc, by_src, by_conn = evidence(run, P)
        accepted = sum(per_proc.values())
        if with_os:
            http("POST", f"/{IDX}*/_refresh")
            os_bytes, siem_total = os_bytes_docs()
            siem_distinct = siem_total   # _id is the event id: a re-delivery overwrites, it cannot add a document
        else:
            for p in procs:
                p["siem"].send_signal(signal.SIGTERM); p["siem"].wait(60)
            siem_total, siem_distinct = siem_ids(run, P)
            os_bytes = None
        rows, rows_distinct = lake_rows(run)
        quarantined = sum(sum(1 for _ in open(q)) for q in run.glob("q-*.jsonl"))
        # accepted over time: index bytes scaled by the exact final count
        per_rec = (max(x["idx"] for x in series) or 1) / max(accepted, 1)
        for x in series:
            x["accepted"] = round(x["idx"] / per_rec)
        t_in = next(x["t"] for x in series if x["accepted"] >= accepted)   # ULPF had taken in everything (evidence committed)
        at = lambda t: next((x for x in series if x["t"] >= t), series[-1])
        # THE WINDOW: from the warm-up's end until the senders stop. The senders are pushing all through it (the kernel's
        # socket buffers are full: it is ULPF's rate, not the senders'); what the buffers still held at the end is taken
        # in after it, counted for exactly-once, and not in any rate
        w0 = a.warmup if a.warmup is not None else (30 if D >= 300 else 15)
        x0 = at(w0)
        x1 = [x for x in series if x["t"] <= D][-1]
        W = x1["t"] - x0["t"]
        rate_of = lambda k: (x1[k] - x0[k]) / W
        slices = []
        t = x0["t"]
        while t + 30 <= x1["t"] + 0.5:
            y0, y1 = at(t), at(t + 30)
            slices.append(round((y1["accepted"] - y0["accepted"]) / (y1["t"] - y0["t"])))
            t += 30
        cpu_w = {k: round(x1["cpu"][k] - x0["cpu"][k], 1) for k in x0["cpu"]}
        cpu_w["senders"] = round(out["cpu_s"] * W / max(out["t1"] - out["t0"], 1e-9), 1)
        s0 = series[0]
        cpu_all = {k: round(c_end[k] - s0["cpu"][k], 1) for k in s0["cpu"]}
        cpu_all["senders"] = round(out["cpu_s"], 1)
        t_siem = next((x["t"] for x in series if x["siem"] >= accepted), None)
        t_lake = next((x["t"] for x in series if x["lake"] >= accepted), None)
        eps = rate_of("accepted")
        res = {"label": label, "processes": P, "senders": S, "duration_s": D, "offered_rate": rate or "max", "batch": a.batch, "layout": lay,
               "cores_by_component": {k: cores_of(v) for k, v in lay.items()}, "siem": "OpenSearch" if with_os else "fake bulk receiver (measurement mode)",
               "window": [x0["t"], x1["t"]], "window_s": round(W, 1), "events_in_window": x1["accepted"] - x0["accepted"],
               "eps_accepted": round(eps), "eps_per_process": round(eps / P), "steadiness_30s_eps": slices,
               "sent": sent, "accepted": accepted, "intake_done_s": t_in, "eps_accepted_all_in": round(accepted / t_in),
               "eps_siem_in_window": round(rate_of("siem")), "eps_lake_in_window": round(rate_of("lake")),
               "backlog_at_window_end": {"siem": x1["accepted"] - x1["siem"], "lake": x1["accepted"] - x1["lake"]},
               "siem_all_acknowledged_s": t_siem, "lake_all_acknowledged_s": t_lake, "lake_final_flush_s": round(flush_s, 1), "lake_repinned_for_drain_at_s": repinned,
               "cpu_s_in_window": cpu_w, "cores_in_window": {k: round(v / W, 2) for k, v in cpu_w.items()},
               "ulpf_events_per_core_second_in_window": round(eps * W / max(cpu_w["ulpf"], 1e-9)),
               "cpu_s_total": cpu_all, "ulpf_events_per_core_second": round(accepted / max(cpu_all["ulpf"], 1e-9)),
               "siem_documents": siem_total, "siem_distinct": siem_distinct, "lake_rows": rows, "lake_distinct": rows_distinct, "quarantined": quarantined,
               "per_process_accepted": per_proc, "senders_per_process": {i: len([s for s, ps in by_src.items() if i in ps]) for i in range(1, P + 1)},
               "senders_on_more_than_one_process": {s: sorted(ps) for s, ps in by_src.items() if len(ps) > 1},
               "sender_reconnects": sum(s["reconnects"] for s in out["senders"]), "distinct_sender_addresses": len({s["src"] for s in out["senders"]}),
               "runtime_stats": {i: {k: v for k, v in st.items() if k in ("frames", "emitted", "quarantined", "evidence_commits", "recovered_after_crash")} for i, st in stats.items()},
               "disk_peak_bytes": watch.peak, "disk_peak_parts": watch.peak_parts, "disk_at_drain": disk_at_drain, "opensearch_bytes": os_bytes,
               "disk_final": {"archive": du(archive), "lake_parquet": sum(os.path.getsize(f) for f in glob.glob(str(run / "lake/ext/**/*.parquet"), recursive=True))},
               "series": [{k: x[k] for k in ("t", "sent", "accepted", "siem", "lake")} | {"cpu": {k: round(v, 1) for k, v in x["cpu"].items()}} for x in series[::5]]}
        res["exactly_once"] = (sent == accepted == siem_total == siem_distinct == rows == rows_distinct) and quarantined == 0
        res["affinity"] = not res["senders_on_more_than_one_process"] and res["sender_reconnects"] == 0
        m = accepted / 1e6
        res["disk_per_million_gb"] = {"evidence_archive": round(res["disk_final"]["archive"] / 1e9 / m, 3), "parquet": round(res["disk_final"]["lake_parquet"] / 1e9 / m, 3),
                                      "spool_peak": round(watch.peak_parts.get("spool", 0) / 1e9 / m, 3), "evidence_buffer_peak": round(watch.peak_parts.get("evidence_buffer", 0) / 1e9 / m, 3),
                                      "siem_ids": round(watch.peak_parts.get("siem_ids", 0) / 1e9 / m, 3), **({"opensearch": round(os_bytes / 1e9 / m, 3)} if os_bytes else {})}
        res["sustained"] = {"intake_held": bool(slices) and min(slices) >= 0.9 * statistics.median(slices),
                            "siem_kept_pace": res["backlog_at_window_end"]["siem"] <= 10 * eps,
                            "lake_kept_pace": res["backlog_at_window_end"]["lake"] <= 10 * eps}
        return res
    finally:
        if sender and sender.poll() is None:
            sender.kill()
        for p in procs:
            for k in ("rt", "cm", "lw", "siem"):
                x = p.get(k)
                if x and x.poll() is None:
                    x.terminate()
                    try:
                        x.wait(60)
                    except subprocess.TimeoutExpired:
                        x.kill()
        shutil.rmtree(run, ignore_errors=True)
        if with_os:
            http("DELETE", f"/{IDX}*")


def summary(r):
    return (f"{r['label']}: P{r['processes']} S{r['senders']}  window {r['window']} {r['eps_accepted']:,}/s ({r['eps_per_process']:,}/process)  accepted {r['accepted']:,}  "
            f"cores: ULPF {r['cores_in_window']['ulpf']} lake {r['cores_in_window']['lake_writers']} siem {r['cores_in_window']['siem']} senders {r['cores_in_window']['senders']}  "
            f"ULPF {r['ulpf_events_per_core_second_in_window']:,} ev/core-s  | in window: siem {r['eps_siem_in_window']:,}/s lake {r['eps_lake_in_window']:,}/s  backlog {r['backlog_at_window_end']}  "
            f"all acked: siem {r['siem_all_acknowledged_s']}s lake {r['lake_all_acknowledged_s']}s  | exactly-once {r['exactly_once']} affinity {r['affinity']}  "
            f"per process {r['per_process_accepted']}  30s slices {r['steadiness_30s_eps']}  peak disk {r['disk_peak_bytes'] / 1e9:.2f} GB")


def save(suite, key, value):
    d = load(OUT, {}) or {}
    d.setdefault(suite, {})[key] = value
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(d, indent=1, default=str) + "\n")


def os_prepare():
    """The demo's index template (demo/siem/setup.py: one shard, no replica, the OCSF mappings) on the measurement's indices."""
    sys.path.insert(0, str(ROOT / "demo" / "siem"))
    import setup
    t = json.loads(json.dumps(setup.TEMPLATE)); t["index_patterns"] = [IDX + "*"]; t["priority"] = 300
    if http("PUT", "/_index_template/ulpf-capacity", t)[0] != 200:
        sys.exit("could not put the index template")


def run_suite(a):
    with_os = a.suite.startswith("C")
    if with_os and http("GET", "/_cluster/health")[0] != 200:
        sys.exit("OpenSearch is not reachable on 9200")
    if with_os:
        os_prepare()
    if not (WORK / "batch.json").exists():
        sys.exit("run `capacity.py baseline` first: the batch's virtual-disk growth is measured from it")
    for p in ("/", "/mnt/c"):
        if free_gb(p) < a.floor_gb + a.budget_gb:
            sys.exit(f"not enough free disk on {p}: {free_gb(p):.0f} GB")
    machine = {"cpu": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?"), "logical_cpus": os.cpu_count(),
               "topology": "8 cores x 2 threads as WSL2 shows them: CPUs 2k and 2k+1 are core k (virtual processors under Hyper-V)",
               "memory_gb": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9, 1),
               "commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(), "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    save("_meta", "machine", machine)
    save("_meta", "devices", load(WORK / "devices-info.json"))
    for P in map(int, a.procs.split(",")):
        for S in map(int, a.senders.split(",")):
            lay = layout(a, P, a.suite)
            # the size, estimated from the per-million figures: ULPF at the calibrated rate per process (bounded by its
            # cores), the spool holding what the lake writers (the slower destination) have not yet taken
            est_rate = a.rate or a.est_rate or a.per_process_eps * min(P, len(cores_of(lay["ulpf"])))
            lake_rate = a.lake_eps_per_core * len(cores_of(lay["lake"]))
            frac = a.spool_frac if a.spool_frac is not None else max(0.05, 1 - lake_rate / est_rate)
            est = estimate_gb(est_rate * a.duration, with_os, frac)
            print(f"[{time.strftime('%H:%M:%S')}] {a.suite} P{P} S{S} {a.duration}s layout {lay}: estimated {est:.1f} GB at {est_rate:,.0f}/s, "
                  f"{frac:.0%} of it waiting in the spool (budget {a.budget_gb} GB)", flush=True)
            if est > a.budget_gb:
                print(f"  NOT STARTED: the estimate exceeds the budget", flush=True)
                save(a.suite, f"P{P}_S{S}", {"not_started": f"estimate {est:.1f} GB > budget {a.budget_gb} GB"})
                continue
            runs = []
            for k in range(a.reps):
                r = one_run(a, P, S, a.duration, a.rate, with_os, lay, f"{a.suite}-P{P}-S{S}-{k + 1}")
                print("  " + summary(r), flush=True)
                runs.append(r)
                save(a.suite, f"P{P}_S{S}", {"runs": runs})
            cell = {"runs": runs, "median_eps": statistics.median(r["eps_accepted"] for r in runs), "median_eps_per_process": statistics.median(r["eps_per_process"] for r in runs),
                    "median_ulpf_cores": statistics.median(r["cores_in_window"]["ulpf"] for r in runs),
                    "median_ulpf_events_per_core_second": statistics.median(r["ulpf_events_per_core_second"] for r in runs),
                    "median_eps_siem_in_window": statistics.median(r["eps_siem_in_window"] for r in runs), "median_eps_lake_in_window": statistics.median(r["eps_lake_in_window"] for r in runs),
                    "exactly_once_all": all(r["exactly_once"] for r in runs), "affinity_all": all(r["affinity"] for r in runs)}
            save(a.suite, f"P{P}_S{S}", cell)
            print(f"  => P{P} S{S}: median {cell['median_eps']:,}/s, {cell['median_eps_per_process']:,}/process, exactly-once {cell['exactly_once_all']}, affinity {cell['affinity_all']}", flush=True)
    b = load(WORK / "batch.json")
    print("virtual disks now", vhdx_gb(), "batch start", b["vhdx_gb"], flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["baseline", "prepare", "run"])
    ap.add_argument("--mixed"); ap.add_argument("--packs"); ap.add_argument("--flowtap"); ap.add_argument("--flowtap-lines", type=int, default=2000)
    ap.add_argument("--suite", default="probe"); ap.add_argument("--procs", default="1"); ap.add_argument("--senders", default="32")
    ap.add_argument("--duration", type=float, default=60); ap.add_argument("--reps", type=int, default=1); ap.add_argument("--rate", type=float, default=0)
    ap.add_argument("--layout", help="JSON {component: cpulist}; default: layout()")
    ap.add_argument("--budget-gb", type=float, default=10); ap.add_argument("--floor-gb", type=float, default=100); ap.add_argument("--batch-growth-gb", type=float, default=15)
    ap.add_argument("--est-rate", type=float, default=0); ap.add_argument("--spool-frac", type=float)
    ap.add_argument("--per-process-eps", type=float, default=6000, help="for the size estimate: ULPF events/s per process (the probe measured ~5,000; rounded up)")
    ap.add_argument("--lake-eps-per-core", type=float, default=2500, help="for the size estimate: lake writer rows/s per core (the probe measured ~2,900)")
    ap.add_argument("--warmup", type=float, help="seconds before the window opens (default 15; 30 for runs of 5 minutes or more)")
    ap.add_argument("--spool-cap", default="6GiB"); ap.add_argument("--batch", type=int, default=1000, help="events per batch to each destination (?batch=N)"); ap.add_argument("--drain-timeout", type=float, default=1500)
    a = ap.parse_args()
    if a.cmd == "baseline":
        baseline(a)
    elif a.cmd == "prepare":
        prepare(a)
    else:
        run_suite(a)


if __name__ == "__main__":
    main()
