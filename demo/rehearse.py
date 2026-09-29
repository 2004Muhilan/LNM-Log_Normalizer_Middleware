#!/usr/bin/env python3
"""One full rehearsal of the demo, end to end, with both real devices running (docs/demo-runbook.md, in its order).
Every step goes through the same HTTP APIs the pages' buttons call; each is timed and its result recorded — and so is
every step that needed a hand (a "nudge"). Standard library.

    bash demo/llama-server.sh start
    wsl -d Containerlab -- bash demo/devices/fortigate/start.sh ; wsl -d Containerlab -- bash demo/devices/suricata/start.sh
    ULPF_REAL_DEVICES=1 bash demo/start-demo.sh
    python3 demo/rehearse.py --out ~/ulpf-rehearsal.json

Operator answers are given by this script through the page's API, on the operator's behalf, and say so.
"""
import argparse
import json
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S, G, OS, DB = "http://127.0.0.1:8765", "http://127.0.0.1:8780", "http://127.0.0.1:9200", "http://127.0.0.1:5601"
FGT, IDS, ATTACKER = "172.20.20.2", "172.20.20.11", "10.10.1.10"
SHEET_FGT = {"eventtime": ("time", None), "user": ("user.name", None), "status": ("status_id", {"success": 1, "failed": 2}),
             "action": ("activity_id", {"login": 1, "logout": 2}), "logdesc": ("message", None), "srcip": ("src_endpoint.ip", None), "dstip": ("dst_endpoint.ip", None)}
SHEET_IDS = {"timestamp": ("time", None), "src_ip": ("src_endpoint.ip", None), "src_port": ("src_endpoint.port", None), "dest_ip": ("dst_endpoint.ip", None),
             "dest_port": ("dst_endpoint.port", None), "proto": ("connection_info.protocol_name", None), "action": ("action_id", {"allowed": 1, "blocked": 2}),
             "signature": ("message", None)}
REPORT = {"started": time.strftime("%Y-%m-%dT%H:%M:%S"), "steps": []}


def http(url, data=None, timeout=60, raw=False):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, method="POST" if data is not None else "GET",
                                 headers={"Content-Type": "application/json"})
    b = urllib.request.urlopen(req, timeout=timeout).read()
    return b if raw else (json.loads(b) if b.strip() else None)


def st():
    return http(S + "/api/state")


def wait(pred, t, step=2):
    end = time.time() + t
    while time.time() < end:
        try:
            v = pred()
        except Exception:   # noqa: BLE001 — a page that is momentarily busy is retried, not a failure
            v = None
        if v:
            return v
        time.sleep(step)
    return None


def clab(*args):
    return subprocess.run(["wsl.exe", "-d", "Containerlab", "--", "bash", *args], capture_output=True, text=True, timeout=180).stdout.replace("\r", "")


def fgt(*cmds):
    return clab(str(ROOT / "demo" / "devices" / "fortigate" / "fgt-cli.sh").replace("\\", "/"), *cmds)


def step(name):
    def deco(fn):
        def run():
            t0 = time.time()
            rec = {"step": name, "ok": False, "nudges": []}
            try:
                rec.update(fn(rec) or {})
                rec["ok"] = rec.get("ok", True) if "ok" in rec else True
            except Exception as ex:   # noqa: BLE001 — recorded, the rehearsal goes on
                rec["error"] = f"{type(ex).__name__}: {ex}"[:500]
            rec["seconds"] = round(time.time() - t0, 1)
            REPORT["steps"].append(rec)
            print(f"[{rec['seconds']:6.1f}s] {'OK ' if rec['ok'] else 'FAIL'} {name}" + (f" — nudges: {rec['nudges']}" if rec["nudges"] else "")
                  + (f" — {rec.get('error')}" if rec.get("error") else ""), flush=True)
            return rec
        return run
    return deco


def job_for(host, pred=lambda j: True, since=0):
    return next((j for j in st()["jobs"][since:] if j["host"] == host and pred(j)), None)


def answer(j, sheet):
    done = {}
    for f in j["fields"]:
        if f["field"] in sheet and not f.get("evidenced"):
            attr, lk = sheet[f["field"]]
            http(S + "/api/answer", {"job": j["id"], "field": f["field"], "attribute": attr, **({"lookup": lk} if lk else {})})
            done[f["field"]] = attr
    time.sleep(6)
    http(S + "/api/promote", {"job": j["id"]})
    return done


def outcomes(host, n=40):
    out = {}
    for r in http(S + f"/api/logs?host={host}")[:n]:
        out[r["outcome"]] = out.get(r["outcome"], 0) + 1
    return out


@step("0. pages up; both real devices connected")
def s0(rec):
    s = wait(lambda: st(), 60)
    apps = {a["host"]: a for a in s["apps"]}
    if FGT not in apps or not apps[FGT].get("connected"):
        rec["nudges"].append("FortiGate not connected: syslog-format.sh default (re-commits its syslog; FortiOS backs off while nobody listens)")
        clab(str(ROOT / "demo/devices/fortigate/syslog-format.sh").replace("\\", "/"), "default")
        wait(lambda: next((a for a in st()["apps"] if a["host"] == FGT and a.get("connected")), None), 120)
    apps = {a["host"]: a for a in st()["apps"]}
    return {"ok": FGT in apps and IDS in apps, "apps": {h: {k: a.get(k) for k in ("name", "events", "usable", "quarantined", "connected")} for h, a in apps.items()},
            "egress": [(e["name"], e["up"]) for e in s["egress"]], "policy": s["policy"]}


@step("2. generator: kv over tcp -> onboarding by policy (model, prepared sheet) -> both destinations UP, SIEM and lake fill")
def s2(rec):
    n0 = len(st()["jobs"])
    http(G + "/api/set", {"connector": "tcp", "shape": "kv", "drift": False, "running": True})
    j = wait(lambda: job_for("127.0.0.1", lambda j: j["state"] in ("done", "failed", "answering", "asking"), n0), 600, 3)
    if j and j["state"] in ("answering", "asking"):
        rec["nudges"].append(f"generator job {j['id']} waited for answers ({j['state']}): Promote pressed")
        http(S + "/api/promote", {"job": j["id"]})
        j = wait(lambda: job_for("127.0.0.1", lambda x: x["id"] == j["id"] and x["state"] in ("done", "failed")), 180, 3)
    ok = wait(lambda: st()["parse_success"] == 1.0 or None, 60)
    s = st()
    dash = http(DB + "/api/saved_objects/dashboard/ulpf-overview", timeout=10)
    lake = http(S + "/api/lake")
    return {"ok": bool(j and j["state"] == "done" and all(e["up"] for e in s["egress"])), "job": j and {k: j[k] for k in ("id", "kind", "state")},
            "job_seconds": j and round(time.time() - j["started"]), "steps": j and [x["text"][:160] for x in j["steps"]][-4:],
            "egress": [(e["name"], e["up"], e["ahead_by"]) for e in s["egress"]], "parse_success_100": bool(ok),
            "dashboard": dash.get("attributes", {}).get("title") if dash else None, "lake": {k: lake.get(k) for k in list(lake)[:6]} if isinstance(lake, dict) else str(lake)[:200]}


@step("3. SIEM outage: SIEM ahead-by climbs, lake stays current; recovery drains the backlog")
def s3(rec):
    http(S + "/api/siem", {"action": "outage"})
    down = wait(lambda: not next(e for e in st()["egress"] if e["kind"] == "siem")["up"] or None, 90)
    time.sleep(15)
    e = {x["kind"]: x for x in st()["egress"]}
    during = {"siem_ahead": e["siem"]["ahead_by"], "lake_ahead": e["lake"]["ahead_by"], "lake_up": e["lake"]["up"]}
    http(S + "/api/siem", {"action": "recover"}, timeout=180)
    back = wait(lambda: (lambda x: x["up"] and x["ahead_by"] <= 25)(next(e for e in st()["egress"] if e["kind"] == "siem")) or None, 240, 3)
    return {"ok": bool(down and back and during["siem_ahead"] >= 40 and during["lake_ahead"] <= 25), "during": during, "recovered": bool(back)}


@step("4. attack burst -> a Security Analytics finding on the System page")
def s4(rec):
    http(G + "/api/set", {"burst": True})
    f = wait(lambda: http(S + "/api/findings") or None, 240, 3)
    return {"ok": bool(f), "finding": f and {k: f[0].get(k) for k in ("rule", "event_ids")}}


@step("5. Prove it on the finding: evidence, Merkle proof, Proof of Derivation, lake; bundle verified offline; certificate draft")
def s5(rec):
    f = http(S + "/api/findings")
    eid = f[0]["event_ids"][0]
    time.sleep(12)
    http(S + "/api/prove", {"event_id": eid})
    t = wait(lambda: http(S + "/api/trace?id=" + eid), 300, 1)
    b = http(S + "/api/bundle?id=" + eid, raw=True)
    bp = Path("/tmp") / f"rehearsal-bundle-{eid}.json"
    bp.write_bytes(b)
    v = subprocess.run([str(ROOT / "runtime/bin/ulpf-verify"), "derivation", "--bundle", str(bp), "--trust", str(ROOT / "keys/trust")], capture_output=True, text=True, cwd=ROOT)
    cert = http(S + "/certificate?id=" + eid, raw=True, timeout=180).decode("utf-8", "replace")
    return {"ok": bool(t and t.get("ok") and v.returncode == 0 and "NOT COMPLETE" in cert), "event_id": eid,
            "trace": t and [(s["step"], s["ok"]) for s in t["steps"]], "verify_offline": (v.stdout + v.stderr).strip().splitlines()[-1:],
            "certificate_marked_not_complete": "NOT COMPLETE" in cert}


@step("6. drift on the generator -> alert, healed in part, the withheld fields answered on the page")
def s6(rec):
    n0 = len(st()["jobs"])
    http(G + "/api/set", {"drift": True})
    j = wait(lambda: job_for("127.0.0.1", lambda j: j["state"] in ("asking", "done", "failed"), n0), 600, 3)
    if j and j["state"] == "asking":
        for f in j["fields"]:
            if not f["evidenced"]:
                http(S + "/api/answer", {"job": j["id"], "field": f["field"], "attribute": "connection_info.protocol_num" if f["field"] in ("proto", "pos_3") else "src_endpoint.zone"})
        time.sleep(3)
        http(S + "/api/promote", {"job": j["id"]})
        j = wait(lambda: job_for("127.0.0.1", lambda x: x["id"] == j["id"] and x["state"] in ("done", "failed")), 180, 3)
    return {"ok": bool(j and j["state"] == "done"), "alert": (j or {}).get("alert", {}).get("outcome", "")[:300]}


@step("7-9. scale-out, evidence archive, transparency log; an UNLOGGED pack pushed to process 1 is refused")
def s79(rec):
    s = st()
    pu = http(S + "/api/push-unlogged", {"process": 1}, timeout=60)
    ref = wait(lambda: len(http(S + "/api/tlog")["refusals"]) >= 1 or None, 30, 1)
    tl = http(S + "/api/tlog")
    return {"ok": bool(pu.get("refused") and ref), "processes": [(p["process"], p["up"]) for p in s["processes"]], "archive": s.get("archive", {}) and {k: s["archive"].get(k) for k in list(s["archive"])[:5]},
            "produced_by": sorted({e["ProducedBy"] for e in tl["entries"]})}


@step("F1. FortiGate: REAL DEVICE, default format parsed by the vendor pack; Prove it on one of its events")
def f1(rec):
    a = next(a for a in st()["apps"] if a["host"] == FGT)
    rows = [r for r in http(S + f"/api/logs?host={FGT}") if r.get("ok")]
    r = rows[min(40, len(rows) - 1)]   # an event old enough to be in a Parquet file (the lake rotates every 10 s)
    eid = r["event_id"]
    http(S + "/api/prove", {"event_id": eid})
    t = wait(lambda: http(S + "/api/trace?id=" + eid), 300, 1)
    return {"ok": bool(a.get("real_device") and t and t.get("ok")), "outcomes": outcomes(FGT), "event_id": eid, "trace": t and [(s["step"], s["ok"]) for s in t["steps"]]}


@step("F2. FortiGate: admin logins -> NEW EVENT FAMILY of a known source -> operator answers -> parsed")
def f2(rec):
    n0 = len(st()["jobs"])
    for _ in range(14):
        fgt("get system status")
    j = wait(lambda: job_for(FGT, lambda j: j["kind"] == "discovery" and j["state"] in ("answering", "asking", "done", "failed"), n0), 600, 3)
    answered = answer(j, SHEET_FGT) if j and j["state"] in ("answering", "asking") else {}
    j = wait(lambda: job_for(FGT, lambda x: x["id"] == j["id"] and x["state"] in ("done", "failed")), 180, 3) if j else None
    for _ in range(6):
        fgt("get system status")
    time.sleep(20)
    return {"ok": bool(j and j["state"] == "done"), "answered_by_this_script_as_operator": answered, "pack": j and j.get("pack", {}).get("pack_id"), "outcomes": outcomes(FGT)}


@step("F3. FortiGate: syslog format -> json: healed automatically (by name); then back to default")
def f3(rec):
    n0 = len(st()["jobs"])
    clab(str(ROOT / "demo/devices/fortigate/syslog-format.sh").replace("\\", "/"), "json")
    j = wait(lambda: job_for(FGT, lambda j: (j.get("signature") or "").split("|")[1:2] == ["json"] and j["state"] in ("asking", "answering", "done", "failed"), n0), 600, 3)
    time.sleep(40)
    out = outcomes(FGT)
    clab(str(ROOT / "demo/devices/fortigate/syslog-format.sh").replace("\\", "/"), "default")
    time.sleep(40)
    return {"ok": bool(j and j.get("auto_heal") and j["state"] in ("asking", "done")), "job": j and {k: j.get(k) for k in ("id", "kind", "state", "family")},
            "alert": (j or {}).get("alert", {}).get("outcome", "")[:400], "json_outcomes": out, "back_to_default": outcomes(FGT)}


@step("S1. Suricata: unknown source -> onboarded (model; operator answers) -> OpenSearch and the lake")
def s_1(rec):
    j = wait(lambda: job_for(IDS, lambda j: j["state"] in ("answering", "asking", "done", "failed")), 600, 3)
    answered = {}
    if j and j["state"] in ("answering", "asking"):
        answered = answer(j, SHEET_IDS)
        j = wait(lambda: job_for(IDS, lambda x: x["id"] == j["id"] and x["state"] in ("done", "failed")), 180, 3)
    time.sleep(40)
    q = {"size": 0, "track_total_hits": True, "query": {"match_phrase": {"metadata.product.vendor_name": "OISF"}}}
    n = http(OS + "/ulpf-ocsf-*/_search", q)["hits"]["total"]["value"]
    e = {x["kind"]: x for x in st()["egress"]}
    return {"ok": bool(j and j["state"] == "done" and n > 0 and e["siem"]["rejected"] == 0), "answered_by_this_script_as_operator": answered,
            "suricata_docs_in_opensearch": n, "rejected": {k: v["rejected"] for k, v in e.items()}, "outcomes": outcomes(IDS)}


@step("S2. cross-vendor search in OpenSearch: the attacker's address, FortiGate and Suricata")
def s_2(rec):
    q = {"size": 0, "query": {"term": {"src_endpoint.ip": ATTACKER}}, "aggs": {"v": {"terms": {"field": "metadata.product.vendor_name", "size": 10}}}}
    r = http(OS + "/ulpf-ocsf-*/_search", q)
    b = {x["key"]: x["doc_count"] for x in r["aggregations"]["v"]["buckets"]}
    return {"ok": {"Fortinet", "OISF"} <= set(b), "query": q, "by_vendor": b}


@step("S3. Prove it on a real Suricata alert")
def s_3(rec):
    rows = [r for r in http(S + f"/api/logs?host={IDS}") if r.get("ok")]
    r = rows[min(40, len(rows) - 1)]   # an event old enough to be in a Parquet file (the lake rotates every 10 s)
    eid = r["event_id"]
    http(S + "/api/prove", {"event_id": eid})
    t = wait(lambda: http(S + "/api/trace?id=" + eid), 300, 1)
    return {"ok": bool(t and t.get("ok")), "event_id": eid, "preview": r["preview"][:200], "trace": t and [(s["step"], s["ok"]) for s in t["steps"]]}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    for fn in (s0, s2, s3, s4, s5, s6, s79, f1, f2, f3, s_1, s_2, s_3):
        fn()
    REPORT["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    REPORT["jobs"] = [{k: j.get(k) for k in ("id", "host", "kind", "state", "signature", "family")} | {"seconds_to_last_step": None} for j in st()["jobs"]]
    Path(a.out).write_text(json.dumps(REPORT, indent=1, default=str) + "\n")
    print("written:", a.out, "|", sum(s["ok"] for s in REPORT["steps"]), "of", len(REPORT["steps"]), "steps OK")


if __name__ == "__main__":
    main()
