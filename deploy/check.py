#!/usr/bin/env python3
"""The container deployment's check (2026-10-01), run by deploy/check.sh inside the app image with the state volume
mounted read-only. It drives the System console and the generator through their HTTP APIs — what the buttons call — and
reads the evidence from the volume. Fails loudly on the first deviation.

  1. two runtime processes, each a unit of containers; adding and removing them is available, limited by the CPUs
  2. the generator's format is onboarded live (fixture proposals) and parses at 100 %; both destinations UP
  3. ADD a process: it starts with every active pack, takes new connections, refuses an UNLOGGED pack (transparency log)
  4. REMOVE two processes (3 -> 1): each drains, seals, ships and retires with nothing left behind; ingestion goes on
  5. the minimum holds: removing the last process is refused
  6. accounting: every parsed event is in the SIEM once and in the lake once; nothing rejected
  7. Prove it on an event of a RETIRED process: the round trip and Proof of Derivation verify
  8. the evidence store's sealed segments carry the kernel's immutable flag (the runtime container's one capability)
"""
import argparse
import glob
import json
import subprocess
import sys
import time
import urllib.request

A = None


def http(method, url, body=None, timeout=30):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return json.loads(data) if data.strip().startswith((b"{", b"[")) else data.decode()


def st():
    return http("GET", A.console + "/api/state")


def gset(**kw):
    http("POST", A.generator + "/api/set", kw)


def fail(msg):
    print("FAIL:", msg, flush=True)
    try:
        s = st()
        print("  processes:", [(p["process"], p["state"], p["up"], p["events"]) for p in s["processes"]], "| scaling:", s.get("scaling"), flush=True)
        print("  jobs:", [(j["id"], j["state"], [x["text"][:100] for x in j["steps"][-3:]]) for j in s["jobs"]], flush=True)
    except Exception as ex:   # noqa: BLE001
        print("  (state unavailable:", ex, ")")
    sys.exit(1)


def until(seconds, cond, what):
    end = time.time() + seconds
    while time.time() < end:
        try:
            v = cond(st())
            if v:
                return v
        except Exception:   # noqa: BLE001
            pass
        time.sleep(1)
    fail(f"timed out after {seconds} s: {what}")


def scale(action, expect_ok=True):
    try:
        http("POST", A.console + "/api/scale", {"action": action})
    except urllib.error.HTTPError as ex:
        if expect_ok:
            fail(f"scale {action} refused: {ex.read().decode()}")
        return ex.read().decode() if False else str(ex.code)
    if not expect_ok:
        fail(f"scale {action} was accepted, it should have been refused")
    n0 = len(st()["scaling"]["history"])
    rec = until(240, lambda s: len(s["scaling"]["history"]) > n0 and not s["scaling"]["busy"] and s["scaling"]["history"][-1], f"scale {action} to finish")
    if not rec.get("ok"):
        fail(f"scale {action}: {rec.get('outcome')}")
    print(f"scale {action}: {rec['outcome']} ({rec['seconds']} s)", flush=True)
    return rec


def main():
    global A
    ap = argparse.ArgumentParser()
    ap.add_argument("--console", required=True); ap.add_argument("--generator", required=True); ap.add_argument("--os", required=True)
    ap.add_argument("--state", default="/state/app")
    A = ap.parse_args()
    t0 = time.time()
    until(180, lambda s: True, "the console answers")
    end = time.time() + 90
    while True:   # the generator starts after the console
        try:
            urllib.request.urlopen(A.generator + "/", timeout=2).read(); break
        except Exception:   # noqa: BLE001
            if time.time() > end:
                fail("the generator does not answer")
            time.sleep(1)
    s = st()
    live = [p for p in s["processes"] if p["state"] == "running" and p["up"]]
    sc = s["scaling"]
    if len(live) != 2 or not sc.get("available"):
        fail(f"wanted 2 running processes and scaling available, got {[(p['process'], p['state'], p['up']) for p in s['processes']]} / {sc}")
    print(f"start: 2 runtime processes ({', '.join(p['pid'] for p in live)}); limit {sc['limit']} (CPUs Docker reports); {sc.get('engine')}", flush=True)

    # 2. onboarding, live
    gset(connector="tcp", shape="positional", drift=False, running=True)
    until(240, lambda s: s["jobs"] and s["jobs"][0]["state"] == "done", "the generator's format onboarded (job 0 done)")
    until(60, lambda s: s["parse_success"] == 1.0, "parse success 100 % after onboarding")
    until(60, lambda s: all(e["up"] and e["ahead_by"] <= 25 for e in s["egress"]), "both destinations UP and current")
    print("onboarded live:", st()["jobs"][0]["steps"][-2]["text"][:110], flush=True)

    # 3. add a process; new connections reach it
    scale("add")
    s = st()
    p3 = next(p for p in s["processes"] if p["process"] == 3)
    if p3["state"] != "running" or not p3["up"]:
        fail(f"process 3 is {p3['state']}, up={p3['up']}")
    for k in range(40):   # each reconnect is a new connection; the kernel hashes it to one of the processes
        if next(p for p in st()["processes"] if p["process"] == 3)["events"] > 0:
            break
        gset(connector="none"); time.sleep(0.6); gset(connector="tcp"); time.sleep(2.5)
    else:
        fail("process 3 received no connection in 40 reconnects")
    until(30, lambda s: s["parse_success"] == 1.0, "process 3 parses with the packs it started with")
    print(f"process 3 takes connections and parses: {next(p for p in st()['processes'] if p['process'] == 3)['events']} events after {k + 1} reconnect(s)", flush=True)
    pu = http("POST", A.console + "/api/push-unlogged", {"process": 3}, timeout=60)
    if not pu.get("refused"):
        fail(f"process 3 accepted an UNLOGGED pack: {pu}")
    print(f"transparency log: {pu['pack']} pushed to process 3 — REFUSED", flush=True)

    # 4. remove two processes: 3 -> 1
    for i in (3, 2):
        rec = scale("remove")
        if rec["process"] != i or " 0 parsed event(s) not delivered" not in rec["outcome"] or " 0 segment(s) not shipped" not in rec["outcome"]:
            fail(f"removing process {i}: {rec['outcome']}")
    s = st()
    if [p["process"] for p in s["processes"] if p["state"] == "running"] != [1]:
        fail(f"wanted only process 1 running: {[(p['process'], p['state']) for p in s['processes']]}")
    n1 = next(p for p in s["processes"] if p["process"] == 1)["events"]
    until(60, lambda s: next(p for p in s["processes"] if p["process"] == 1)["events"] > n1 + 20, "ingestion goes on, on process 1")
    until(30, lambda s: s["parse_success"] == 1.0, "parse success 100 % on the one process left")
    print("ingestion continues on process 1 after both removals", flush=True)

    # 5. the minimum
    try:
        http("POST", A.console + "/api/scale", {"action": "remove"})
        fail("removing the last process was accepted")
    except urllib.error.HTTPError as ex:
        print("minimum:", ex.read().decode()[:100], flush=True)

    # 6. accounting
    gset(running=False)
    time.sleep(10)
    until(90, lambda s: all(e["up"] and e["ahead_by"] == 0 for e in s["egress"]), "every destination has every parsed event")
    s = st()
    usable = s["counts"]["usable"]
    for p in s["processes"]:
        if p["state"] == "running":
            urllib.request.urlopen(f"http://127.0.0.1:{p['lake_port']}/flush", timeout=60).read()
    http("POST", A.os + "/ulpf-ocsf-*/_refresh")
    docs = http("GET", A.os + "/ulpf-ocsf-*/_count")["count"]
    import duckdb
    fs = glob.glob(f"{A.state}/lake/ext/*/*/*/*/*.parquet")
    rows, distinct = duckdb.connect().execute(f"SELECT count(*), count(DISTINCT event_id) FROM read_parquet({fs!r})").fetchone()
    rej = sum(e["rejected"] for e in s["egress"])
    print(f"accounting: parsed {usable}; SIEM documents {docs}; lake rows {rows}, distinct {distinct}; rejected {rej}", flush=True)
    if not (docs == usable == rows == distinct and rej == 0):
        fail("every parsed event must be in the SIEM once and in the lake once")

    # 7. Prove it on an event of a retired process
    ids = []
    for f in sorted(glob.glob(f"{A.state}/ev-3/seg_*.idx.jsonl")) + sorted(glob.glob(f"{A.state}/evidence-archive/*/segments/seg_*.idx.jsonl")):
        ids += [json.loads(l)["event_id"] for l in open(f) if l.strip()]
    pid = None
    for eid in ids:
        d = http("GET", A.console + f"/api/log?id={eid}")
        if isinstance(d, dict) and d.get("parsed", {}).get("status") == "normalized":
            pid = eid
            break
    if not pid:
        fail("no parsed event of process 3 found")
    http("POST", A.console + "/api/prove", {"event_id": pid})
    end = time.time() + 180
    t = None
    while time.time() < end:
        t = http("GET", A.console + f"/api/trace?id={pid}")
        if isinstance(t, dict):
            break
        time.sleep(1)
    if not isinstance(t, dict):
        fail(f"no trace for {pid}")
    for x in t["steps"]:
        print(("  ✓ " if x["ok"] else "  ✗ ") + x["step"] + ": " + x["detail"][:120], flush=True)
    if not t.get("ok") or t.get("process") != 3 or not next((x["ok"] for x in t["steps"] if x["step"] == "Proof of Derivation"), False):
        fail(f"Prove it on {pid} (retired process 3): ok={t.get('ok')} process={t.get('process')}")
    print(f"Prove it on {pid}, an event of RETIRED process 3: round trip and Proof of Derivation verified", flush=True)

    # 8. the kernel immutable flag on sealed evidence
    seals = sorted(glob.glob(f"{A.state}/ev/seg_*.raw"))
    out = subprocess.run(["lsattr", *seals[:3]], capture_output=True, text=True).stdout
    if not seals or not all(l.split()[0].count("i") for l in out.splitlines() if l.strip()):
        fail(f"sealed segments without the immutable flag: {out[:300]}")
    print(f"evidence: sealed segments are IMMUTABLE (kernel flag set by the runtime container's one capability): {out.splitlines()[0][:80]}", flush=True)
    print(f"CONTAINER CHECK: PASS in {round(time.time() - t0)} s", flush=True)


if __name__ == "__main__":
    import urllib.error  # noqa: E402
    main()
