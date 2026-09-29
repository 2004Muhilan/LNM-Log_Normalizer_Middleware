#!/usr/bin/env python3
"""The live test on the real Suricata sensor (docs/real-device-suricata.md). Standard library.

    ULPF_REAL_DEVICES=1 bash demo/start-demo.sh                                   # first (model provider)
    wsl -d Containerlab -- bash demo/devices/suricata/start.sh                    # the sensor on the FortiGate's wire
    python3 demo/devices/suricata/live_onboard.py --out ~/ulpf-suricata/live.json

1. unknown source  Suricata's EVE alerts arrive from 172.20.20.11: every line quarantined; the console's onboarding job
                   drafts the JSON, the local model proposes a class and labels. The operator's answers are given through
                   the page's own API BY THIS DRIVER, and say so — only for the fields the class can hold (ANSWERS below).
2. flowing         later alerts are parsed: OpenSearch (index ulpf-ocsf-<class>) and the lake.
3. cross-vendor    one OpenSearch search for the attacker's address, 10.10.1.10, across every ULPF index: FortiGate (its
                   traffic log) and Suricata (its alert) — the same connections, seen by two devices.
4. prove it        the console's "Prove it" round trip on a real Suricata alert.
5. the label       what the System page says about the source and its events.
"""
import argparse
import json
import time
import urllib.request
from pathlib import Path

B, OS = "http://127.0.0.1:8765", "http://127.0.0.1:9200"
HOST, ATTACKER = "172.20.20.11", "10.10.1.10"
# the operator's answers, per class the model proposed. Detection Finding (2004): the attacker's and victim's addresses live
# only in `evidences[]` in OCSF 1.3 — an array the pack mapping cannot write — so they are NOT answered (carried unmapped).
ANSWERS = {
    2004: {"timestamp": ("time", None), "signature": ("finding_info.title", None), "signature_id": ("finding_info.uid", None),
           "category": ("finding_info.desc", None), "severity": ("severity_id", {"1": 4, "2": 3, "3": 2}), "action": ("action_id", {"allowed": 1, "blocked": 2})},
    4001: {"timestamp": ("time", None), "src_ip": ("src_endpoint.ip", None), "src_port": ("src_endpoint.port", None), "dest_ip": ("dst_endpoint.ip", None),
           "dest_port": ("dst_endpoint.port", None), "proto": ("connection_info.protocol_name", None), "action": ("action_id", {"allowed": 1, "blocked": 2}),
           "signature": ("message", None)},
}


def get(url):
    return json.loads(urllib.request.urlopen(url, timeout=30).read())


def post(url, d):
    r = urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(d).encode(), method="POST", headers={"Content-Type": "application/json"}), timeout=60)
    return json.loads(r.read() or b"null")


def wait(pred, t, step=3):
    end = time.time() + t
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


def jobs():
    return [j for j in get(B + "/api/state")["jobs"] if j["host"] == HOST]


def app():
    return next((a for a in get(B + "/api/state")["apps"] if a["host"] == HOST), {})


def outcomes():
    out = {}
    for r in get(B + f"/api/logs?host={HOST}")[:40]:
        out[r["outcome"]] = out.get(r["outcome"], 0) + 1
    return out


def search(vendor):
    q = {"size": 2, "track_total_hits": True, "sort": [{"_doc": "desc"}],
         "query": {"bool": {"must": [{"query_string": {"query": f'"{ATTACKER}"'}}], "filter": [{"match_phrase": {"metadata.product.vendor_name": vendor}}]}}}
    r = post(OS + "/ulpf-ocsf-*/_search", q)
    hits = r["hits"]["hits"]
    return {"vendor": vendor, "total": r["hits"]["total"]["value"], "indices": sorted({h["_index"] for h in hits}),
            "where_the_address_is": sorted({k for h in hits for k in paths(h["_source"], ATTACKER)}),
            "example": {k: hits[0]["_source"].get(k) for k in ("class_uid", "class_name", "time", "metadata", "src_endpoint", "finding_info", "unmapped", "_lineage")} if hits else None}


def paths(d, v, pre=""):
    if isinstance(d, dict):
        for k, x in d.items():
            yield from paths(x, v, f"{pre}.{k}" if pre else k)
    elif isinstance(d, list):
        for x in d:
            yield from paths(x, v, pre + "[]")
    elif d == v:
        yield pre


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); ap.add_argument("--phase-seconds", type=float, default=600)
    a = ap.parse_args()
    rep = {"started": time.strftime("%Y-%m-%dT%H:%M:%S"), "policy": get(B + "/api/state")["policy"]}
    first = wait(lambda: (lambda x: x if x.get("events") else None)(app()), 180)
    rep["before"] = {"app": {k: first.get(k) for k in ("name", "events", "usable", "quarantined")} if first else None, "outcomes": outcomes() if first else None}
    print("before:", rep["before"])
    j = wait(lambda: next((x for x in jobs() if x["state"] in ("answering", "asking", "failed", "done")), None), a.phase_seconds)
    if not j:
        rep["result"] = "no onboarding job within the phase"
    elif j["state"] == "failed":
        rep["result"] = "onboarding failed: " + j["steps"][-1]["text"][:600]
    else:
        cls = j.get("event_class_uid")
        table = ANSWERS.get(cls, {})
        answered = {}
        for f in j["fields"]:
            if f["field"] in table and not f.get("evidenced"):
                attr, lk = table[f["field"]]
                post(B + "/api/answer", {"job": j["id"], "field": f["field"], "attribute": attr, **({"lookup": lk} if lk else {})})
                answered[f["field"]] = attr + (f" {lk}" if lk else "")
        time.sleep(8)
        post(B + "/api/promote", {"job": j["id"]})
        j = wait(lambda: next((x for x in jobs() if x["id"] == j["id"] and x["state"] in ("done", "failed")), None), 240) or j
        rep["job"] = {k: j.get(k) for k in ("id", "kind", "state", "format", "signature", "family", "event_class_uid", "provider", "pack")} | {
            "steps": [s["text"][:500] for s in j["steps"]],
            "fields": [{k: f.get(k) for k in ("field", "cls", "mapped", "provenance", "candidates", "samples")} for f in j["fields"]],
            "answered_by_the_driver_as_operator": answered,
            "left_unanswered": [f["field"] for f in j["fields"] if f["field"] not in answered and not f.get("evidenced")]}
        print("job:", j["id"], j["state"], "class", cls, "answered", answered)
        time.sleep(45)   # alerts keep coming (every traffic loop); let them flow through the new pack to OpenSearch and the lake
        rep["after"] = {"app": {k: app().get(k) for k in ("name", "events", "usable", "quarantined", "real_device")}, "outcomes": outcomes()}
        print("after:", rep["after"])
        rep["cross_vendor_search"] = {"query": f'query_string "\\"{ATTACKER}\\"" over ulpf-ocsf-*, filtered by metadata.product.vendor_name',
                                      "results": [search("Fortinet"), search("OISF")]}
        print("search:", [(r["vendor"], r["total"], r["indices"], r["where_the_address_is"]) for r in rep["cross_vendor_search"]["results"]])
        rows = [r for r in get(B + f"/api/logs?host={HOST}") if r.get("ok")]
        if len(rows) > 3:
            eid = rows[3]["event_id"]   # not the newest: the SIEM and the lake must already have it
            post(B + "/api/prove", {"event_id": eid})
            t = wait(lambda: get(B + "/api/trace?id=" + eid), 300, 1)   # the console stores the trace when the round trip has finished
            rep["prove_it"] = {"event_id": eid, "preview": rows[3].get("preview"), "trace": t}
            print("prove it:", eid, (t or {}).get("ok"), [(s["step"], s["ok"]) for s in (t or {}).get("steps", [])])
        rep["result"] = "onboarded live" if j["state"] == "done" else f"job ended in state {j['state']}"
    rep["alerts"] = [x for x in get(B + "/api/state")["alerts"] if x.get("host") == HOST]
    rep["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(rep, indent=1, default=str) + "\n")
    print("written:", a.out)


if __name__ == "__main__":
    main()
