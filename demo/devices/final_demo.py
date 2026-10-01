#!/usr/bin/env python3
"""The final demo, walked end to end through the System page's own APIs (the presenter's buttons), with the real FortiGate
and Suricata (docs/demo-runbook.md, "The final demo"). Each step is timed and reported as WORKED, NUDGE (something beyond
the scripted button press was needed — named) or FAILED. Standard library + DuckDB for the lake check.

    bash demo/llama-server.sh start ; bash demo/start-demo.sh devices
    python3 demo/devices/final_demo.py --out ~/ulpf-final-demo-1.json
    # the container deployment (deploy/): run it in the app image, with the state volume read-only, and the scaling step
    docker run --rm --network host -v ulpf-state:/state:ro -v "$PWD:/out" -v "$PWD/demo/devices:/drv:ro" ulpf-app python /drv/final_demo.py --lake /state/app/lake --scale --out /out/final-demo.json

Operator answers (Suricata's fields) are given by this script through the page's API, on the operator's behalf, and say so.
"""
import argparse
import glob
import json
import os
import time
import urllib.request
from pathlib import Path

S, OS, OSD = "http://127.0.0.1:8765", "http://127.0.0.1:9200", "http://127.0.0.1:5601"
FGT, IDS, ATTACKER = "172.20.20.2", "172.20.20.11", "10.10.1.10"
SHEET = {"timestamp": ("time", None), "src_ip": ("src_endpoint.ip", None), "src_port": ("src_endpoint.port", None), "dest_ip": ("dst_endpoint.ip", None),
         "dest_port": ("dst_endpoint.port", None), "proto": ("connection_info.protocol_name", None), "action": ("action_id", {"allowed": 1, "blocked": 2}),
         "signature": ("message", None)}
R = {"started": time.strftime("%Y-%m-%dT%H:%M:%S"), "steps": []}
LAKE = os.path.expanduser("~/ulpf-demo/app/lake")


def http(url, data=None, timeout=60, raw=False, headers=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, method="POST" if data is not None else "GET",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    b = urllib.request.urlopen(req, timeout=timeout).read()
    return b if raw else (json.loads(b) if b.strip() else None)


def st():
    return http(S + "/api/state")


def wait(pred, t, step=2):
    end = time.time() + t
    while time.time() < end:
        try:
            v = pred()
        except Exception:   # noqa: BLE001
            v = None
        if v:
            return v
        time.sleep(step)
    return None


def app(h):
    return next((a for a in st()["apps"] if a["host"] == h), {})


def device(action, arg=None, t=240):
    """Press a device button and wait until the action (and the status re-read) is done; return the page's record of it."""
    n0 = st()["devices"]["actions"]
    http(S + "/api/device", {"action": action, **({"arg": arg} if arg is not None else {})})
    wait(lambda: not st()["devices"]["busy"] and st()["devices"]["actions"] > n0, t, 1)
    h = st()["devices"]["history"]
    return h[-1] if h else {}


def outcomes(host, n=30):
    out = {}
    for r in http(S + f"/api/logs?host={host}")[:n]:
        out[r["outcome"]] = out.get(r["outcome"], 0) + 1
    return out


def os_by_vendor(query=None):
    q = {"size": 0, "query": query or {"match_all": {}}, "aggs": {"v": {"terms": {"field": "metadata.product.vendor_name", "size": 10}},
                                                           "ids": {"cardinality": {"field": "_lineage.event_id", "precision_threshold": 40000}}}}
    r = http(OS + "/ulpf-ocsf-*/_search", q)
    return {b["key"]: b["doc_count"] for b in r["aggregations"]["v"]["buckets"]}, r["hits"]["total"]["value"], r["aggregations"]["ids"]["value"]


def step(name):
    def deco(fn):
        def run():
            t0 = time.time()
            rec = {"step": name, "result": "FAILED", "nudges": [], "notes": []}
            try:
                out = fn(rec) or {}
                rec.update(out)
                if out.get("ok"):
                    rec["result"] = "NUDGE" if rec["nudges"] else "WORKED"
            except Exception as ex:   # noqa: BLE001 — recorded; the run goes on
                rec["error"] = f"{type(ex).__name__}: {ex}"[:500]
            rec["seconds"] = round(time.time() - t0, 1)
            R["steps"].append(rec)
            print(f"[{rec['seconds']:6.1f}s] {rec['result']:7} {name}" + (f" — nudges: {rec['nudges']}" if rec["nudges"] else "") + (f" — {rec.get('error')}" if rec.get("error") else ""), flush=True)
        return run
    return deco


@step("1. connect ingress: FortiGate and Suricata through ULPF's syslog ingress connectors; both appear as sources")
def s1(rec):
    s = st()
    rec["before"] = {"apps": [a["host"] for a in s["apps"]], "fgt_syslog": s["devices"]["status"].get("syslog_status"), "ids_forwarder": s["devices"]["status"].get("container_fgt-ids-syslog")}
    f = device("fgt-connect")
    i = device("ids-connect")
    for h in (f, i):
        if "attempts: 2" in (h.get("output") or ""):
            rec["notes"].append(f"{h['action']}: connected on the AUTOMATIC second attempt (syslog re-committed by the page)")
    both = wait(lambda: app(FGT).get("connected") and app(IDS).get("events"), 90)
    a, b = app(FGT), app(IDS)
    return {"ok": bool(both and f.get("rc") == 0 and i.get("rc") == 0), "fortigate": {k: a.get(k) for k in ("name", "events", "connector", "channel", "bound_packs", "real_device")},
            "suricata": {k: b.get(k) for k in ("name", "events", "connector", "channel", "bound_packs")}, "device_actions": [f, i]}


@step("2. connect egress: OpenSearch and the Parquet lake as destinations, per-destination status")
def s2(rec):
    before = {e["name"]: (e["up"], e["ahead_by"]) for e in st()["egress"]}
    http(S + "/api/siem", {"action": "recover"})
    http(S + "/api/lake-control", {"action": "connect"})
    up = wait(lambda: all(e["up"] for e in st()["egress"]) or None, 240, 3)
    drained = wait(lambda: all(e["ahead_by"] <= 25 for e in st()["egress"]) or None, 180, 3)
    e = st()["egress"]
    return {"ok": bool(up and drained), "before": before, "after": [(x["name"], x["up"], x["ahead_by"], x["delivered"], x["rejected"]) for x in e], "lake_writers": st()["lake_writers"]}


@step("3. onboarding: FortiGate recognised by its existing pack; Suricata onboarded live from unknown (certificates, operator answers)")
def s3(rec):
    fo = outcomes(FGT)
    fgt_ok = any(k == "fortigate-traffic" for k in fo)
    j = wait(lambda: next((x for x in st()["jobs"] if x["host"] == IDS and x["state"] in ("waiting_approval", "answering", "done", "failed")), None), 300, 3)
    if j and j["state"] == "waiting_approval":
        http(S + "/api/approve", {"job": j["id"]})          # the presenter's "Onboard this application's format"
        j = wait(lambda: next((x for x in st()["jobs"] if x["id"] == j["id"] and x["state"] in ("answering", "done", "failed")), None), 600, 3)
    answered = {}
    if j and j["state"] == "answering":
        rec["certificates_before_answers"] = j.get("certificates")
        rec["model_proposed"] = {f["field"]: (f["mapped"] + f["candidates"])[:2] for f in j["fields"]}
        for f in j["fields"]:
            if f["field"] in SHEET and not f.get("evidenced"):
                attr, lk = SHEET[f["field"]]
                http(S + "/api/answer", {"job": j["id"], "field": f["field"], "attribute": attr, **({"lookup": lk} if lk else {})})
                answered[f["field"]] = attr
        time.sleep(6)
        http(S + "/api/promote", {"job": j["id"]})
        j = wait(lambda: next((x for x in st()["jobs"] if x["id"] == j["id"] and x["state"] in ("done", "failed")), None), 240, 3)
    parsed = wait(lambda: any(k.startswith("rfc3164-json") for k in outcomes(IDS, 20)), 120, 3)
    others = [{k: x.get(k) for k in ("id", "host", "kind", "state", "format")} for x in st()["jobs"] if x["host"] == FGT]
    if others:
        rec["notes"].append(f"FortiGate jobs open meanwhile (its admin logins from the device actions are system events no family owns): {others}")
    return {"ok": bool(fgt_ok and j and j["state"] == "done" and parsed), "fortigate_outcomes": fo, "suricata_job": j and {k: j.get(k) for k in ("id", "kind", "state", "event_class_uid", "pack", "certificates")},
            "answered_by_this_script_as_operator": answered, "suricata_outcomes": outcomes(IDS)}


@step("4. flow: both vendors side by side in OpenSearch Dashboards, the saved cross-vendor search, the lake view")
def s4(rec):
    device("attack")
    time.sleep(40)
    vend, total, distinct = os_by_vendor()
    att, _, _ = os_by_vendor({"term": {"src_endpoint.ip": ATTACKER}})
    ss = http(OSD + "/api/saved_objects/search/ulpf-lab-attacker", headers={"osd-xsrf": "true"})
    db = http(OSD + "/api/saved_objects/dashboard/ulpf-real-devices", headers={"osd-xsrf": "true"})
    import duckdb
    fs = [f for f in glob.glob(LAKE + "/**/*.parquet", recursive=True) if "network" in f]
    lake = dict(duckdb.connect().execute(f"select metadata.product.vendor_name, count(*) from read_parquet({fs!r}, union_by_name=true) where src_endpoint.ip='{ATTACKER}' group by 1").fetchall()) if fs else {}
    lv = http(S + "/api/lake")
    return {"ok": {"Fortinet", "OISF"} <= set(att) and {"Fortinet", "OISF"} <= set(lake) and bool(ss) and bool(db), "opensearch_by_vendor": vend,
            "saved_search": ss and ss["attributes"]["title"], "saved_search_query_by_vendor": att, "dashboard": db and db["attributes"]["title"],
            "lake_rows_from_attacker_by_vendor": lake, "lake_page_sources": [x.get("source") for x in (lv or {}).get("sources", [])]}


@step("4b. scale: a runtime process ADDED while both devices send, then REMOVED; nothing left behind; both devices go on parsing")
def s4b(rec):
    def scale(action):
        n0 = len(st()["scaling"]["history"])
        http(S + "/api/scale", {"action": action})
        return wait(lambda: (lambda c: c["history"][-1] if len(c["history"]) > n0 and not c["busy"] else None)(st()["scaling"]), 300, 2)
    where = lambda: {h: app(h).get("processes") for h in (FGT, IDS)}
    rec["before"] = where()
    add = scale("add") or {}
    device("attack")
    n = {h: app(h).get("events", 0) for h in (FGT, IDS)}
    rem = scale("remove") or {}
    rec["devices_on_processes_during"] = where()
    flowing = wait(lambda: all(app(h).get("events", 0) > n[h] for h in (FGT, IDS)) or None, 120, 3)
    device("attack")
    time.sleep(10)
    good = {h: [k for k in outcomes(h, 12) if not k.startswith("quarantined")] for h in (FGT, IDS)}
    procs = [(p["process"], p["state"], p["events"]) for p in st()["processes"]]
    return {"ok": bool(add.get("ok") and rem.get("ok") and " 0 parsed event(s) not delivered" in rem.get("outcome", "")
                       and " 0 segment(s) not shipped" in rem.get("outcome", "") and flowing and all(good.values())),
            "add": add, "remove": rem, "processes": procs, "after": where(), "parsed_after": good}


@step("5. egress outage: stop OpenSearch; the lake keeps flowing; restart; the backlog delivers with no duplicates")
def s5(rec):
    http(S + "/api/siem", {"action": "outage"})
    down = wait(lambda: not next(e for e in st()["egress"] if e["kind"] == "siem")["up"] or None, 90)
    device("attack")
    during = None
    for _ in range(25):   # the SIEM falls behind while the lake stays current, at the same moment
        e = {x["kind"]: x for x in st()["egress"]}
        during = {"siem_ahead": e["siem"]["ahead_by"], "lake_ahead": e["lake"]["ahead_by"], "lake_up": e["lake"]["up"]}
        if during["siem_ahead"] >= 40 and during["lake_ahead"] <= 25:
            break
        time.sleep(2)
    http(S + "/api/siem", {"action": "recover"})
    back = wait(lambda: (lambda x: x["up"] and x["ahead_by"] <= 25)(next(e for e in st()["egress"] if e["kind"] == "siem")) or None, 300, 3)
    time.sleep(8)
    vend, total, distinct = os_by_vendor()
    return {"ok": bool(down and back and during and during["siem_ahead"] >= 40 and during["lake_ahead"] <= 25 and total == distinct),
            "during": during, "documents": total, "distinct_event_ids": distinct, "duplicates": total - distinct}


@step("6. drift: FortiGate -> JSON live; most fields heal automatically, the unknown ones ask; Suricata keeps parsing throughout")
def s6(rec):
    n0 = len(st()["jobs"])
    device("fgt-format", "json")
    samples, j = [], None
    end = time.time() + 480
    while time.time() < end:
        samples.append(outcomes(IDS, 12))
        j = next((x for x in st()["jobs"][n0:] if x["host"] == FGT and (x.get("signature") or "").split("|")[1:2] == ["json"] and x["state"] in ("asking", "answering", "done", "failed")), None)
        if j and j["state"] in ("asking", "done"):
            break
        time.sleep(10)
    for _ in range(4):
        time.sleep(10); samples.append(outcomes(IDS, 12))
    fj = outcomes(FGT)
    ids_bad = [s for s in samples if any(k.startswith("quarantined") for k in s)]
    return {"ok": bool(j and j.get("auto_heal") and not ids_bad and any(k.startswith("rfc3164-json") for k in fj)),
            "job": j and {k: j.get(k) for k in ("id", "kind", "state", "family", "pack")}, "alert": (j or {}).get("alert", {}).get("outcome", "")[:400],
            "fortigate_outcomes_after": fj, "suricata_samples_during": samples, "suricata_quarantined_during": len(ids_bad)}


@step("7. Prove it on a real event, then the certificate draft")
def s7(rec):
    rows = [r for r in http(S + f"/api/logs?host={IDS}") if r.get("ok")]
    r = rows[min(20, len(rows) - 1)]   # old enough to be in a Parquet file (the lake rotates every 10 s)
    http(S + "/api/prove", {"event_id": r["event_id"]})
    t = wait(lambda: http(S + "/api/trace?id=" + r["event_id"]), 300, 1)
    cert = http(S + "/certificate?id=" + r["event_id"], raw=True, timeout=180).decode("utf-8", "replace")
    return {"ok": bool(t and t.get("ok") and "NOT COMPLETE" in cert), "event_id": r["event_id"], "preview": r["preview"][:160],
            "trace": t and [(x["step"], x["ok"]) for x in t["steps"]], "certificate_draft_not_complete": "NOT COMPLETE" in cert}


def main():
    global LAKE
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True)
    ap.add_argument("--lake", default=LAKE, help="the lake root (the container deployment: /state/app/lake, the state volume mounted)")
    ap.add_argument("--scale", action="store_true", help="step 4b: add a runtime process while the devices send, then remove it (container deployment)")
    a = ap.parse_args()
    LAKE = a.lake
    for fn in (s1, s2, s3, s4) + ((s4b,) if a.scale else ()) + (s5, s6, s7):
        fn()
    try:   # after the run: the FortiGate back to its default format (not a demo step)
        device("fgt-format", "default")
    except Exception:   # noqa: BLE001
        pass
    R["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    R["device_history"] = st()["devices"]["history"]
    Path(a.out).write_text(json.dumps(R, indent=1, default=str) + "\n")
    print("written:", a.out, "|", " ".join(f"{s['step'][:2]}{s['result']}" for s in R["steps"]))


if __name__ == "__main__":
    main()
