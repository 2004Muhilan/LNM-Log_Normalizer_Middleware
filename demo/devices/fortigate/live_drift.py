#!/usr/bin/env python3
"""The live test on the real FortiGate (docs/real-device-fortigate.md, "Live, after the fixes"). Standard library.

    ULPF_REAL_DEVICES=1 bash demo/start-demo.sh          # first (model provider; the four-vendor relay left ON)
    python3 demo/devices/fortigate/live_drift.py --out ~/ulpf-fortigate/live-drift.json

1. baseline   the FortiGate's default-format traffic is parsed by the vendor pack while the relay sends 8 events/s
              (the per-source trigger window: the relay can no longer starve the FortiGate's 1/s)
2. events     real admin logins/logouts (SSH sessions) -> system events no family owns -> the console's job for a NEW
              FAMILY of a KNOWN (bound) source. The operator's answers are given through the page's own API by this
              driver, and say so: eventtime -> time, user -> user.name, status -> status_id (success=1, failed=2),
              action -> activity_id (login=1, logout=2), logdesc -> message, srcip/dstip -> endpoints. Then more logins,
              which must now be parsed (OCSF Authentication, class 3002).
3. drift      default -> csv -> cef -> json -> default, switched on the device (syslog-format.sh). Per format: what the
              console did — healed automatically, asked the operator, or quarantined — and its own words why. The drift
              jobs' questions are NOT answered here: "asked" is the result being measured.
"""
import argparse
import json
import subprocess
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
B = "http://127.0.0.1:8765"
HOST = "172.20.20.2"
ANSWERS = {"eventtime": ("time", None), "user": ("user.name", None), "status": ("status_id", {"success": 1, "failed": 2}),
           "action": ("activity_id", {"login": 1, "logout": 2}), "logdesc": ("message", None), "srcip": ("src_endpoint.ip", None), "dstip": ("dst_endpoint.ip", None)}


def get(p):
    return json.loads(urllib.request.urlopen(B + p, timeout=30).read())


def post(p, d):
    urllib.request.urlopen(urllib.request.Request(B + p, data=json.dumps(d).encode(), method="POST", headers={"Content-Type": "application/json"}), timeout=30)


def clab(*args):
    return subprocess.run(["wsl.exe", "-d", "Containerlab", "--", "bash", *args], capture_output=True, text=True, timeout=120).stdout.replace("\r", "")


def fgt(*cmds):
    return clab(str(HERE / "fgt-cli.sh").replace("\\", "/"), *cmds)


def app():
    return next((a for a in get("/api/state")["apps"] if a["host"] == HOST), {})


def jobs(since=0):
    return [j for j in get("/api/state")["jobs"] if j["host"] == HOST][since:]


def labels():
    rows = get(f"/api/logs?host={HOST}")
    out = {}
    for r in rows[:40]:
        out[r["outcome"]] = out.get(r["outcome"], 0) + 1
    return out


def wait(pred, t, step=3):
    end = time.time() + t
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


def summary(j):
    return {k: j.get(k) for k in ("id", "kind", "state", "format", "signature")} | {
        "steps": [s["text"][:400] for s in j.get("steps", [])],
        "fields_asked": [f["field"] for f in j.get("fields", []) if not f.get("evidenced") and not f.get("propagated")],
        "fields_carried_over": [f["field"] for f in j.get("fields", []) if f.get("propagated")],
        "binding": j.get("binding"), "alert": (j.get("alert") or {}).get("outcome")}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); ap.add_argument("--phase-seconds", type=float, default=240)
    ap.add_argument("--skip-events", action="store_true")
    a = ap.parse_args()
    rep = {"started": time.strftime("%Y-%m-%dT%H:%M:%S"), "policy": get("/api/state")["policy"]}
    print(clab(str(HERE / "syslog-format.sh").replace("\\", "/"), "default").strip().splitlines()[-1])
    base = wait(lambda: (lambda x: x if x.get("usable", 0) >= 30 else None)(app()), 180)
    rep["baseline"] = {"app": {k: base.get(k) for k in ("name", "events", "usable", "quarantined", "processes")} if base else None, "relay_on": rep["policy"]["vendor_relay"]}
    print("baseline:", rep["baseline"])

    if not a.skip_events:
        n0 = len(jobs())
        for _ in range(14):   # each session: a login and a logout, both real system events
            fgt("get system status")
        disc = wait(lambda: next((j for j in jobs(n0) if j["kind"] == "discovery" and j["state"] in ("answering", "asking", "failed", "done")), None), a.phase_seconds)
        answered = {}
        if disc and disc["state"] in ("answering", "asking"):
            for f in disc["fields"]:
                if f["field"] in ANSWERS and not f.get("evidenced") and not f.get("propagated"):
                    attr, lk = ANSWERS[f["field"]]
                    post("/api/answer", {"job": disc["id"], "field": f["field"], "attribute": attr, **({"lookup": lk} if lk else {})})
                    answered[f["field"]] = attr + (f" {lk}" if lk else "")
            time.sleep(6)
            post("/api/promote", {"job": disc["id"]})
            disc = wait(lambda: next((j for j in jobs() if j["id"] == disc["id"] and j["state"] in ("done", "failed")), None), 180) or disc
        others = [j for j in jobs(n0) if j["kind"] == "discovery" and (not disc or j["id"] != disc["id"])]
        for _ in range(6):
            fgt("get system status")
        time.sleep(20)
        rep["events"] = {"job": summary(disc) if disc else None, "answered_by_the_driver_as_operator": answered, "other_event_jobs": [summary(j) for j in others],
                         "latest_outcomes": labels()}
        print("events:", json.dumps(rep["events"], default=str)[:1500])

    rep["drift"] = []
    for fmt in ("csv", "cef", "json", "default"):
        n0 = len(jobs())
        print(clab(str(HERE / "syslog-format.sh").replace("\\", "/"), fmt).strip().splitlines()[-1])
        t0 = time.time()
        if fmt == "default":
            time.sleep(60)
            rep["drift"].append({"format": fmt, "latest_outcomes": labels(), "app": {k: app().get(k) for k in ("events", "usable", "quarantined")}})
            continue
        mine = {"csv": lambda s: s.split("|")[1:2] == ["csv"], "cef": lambda s: s.startswith("cef|"), "json": lambda s: s.split("|")[1:2] == ["json"]}[fmt]
        j = wait(lambda: next((x for x in jobs(n0) if mine(x.get("signature") or "") and x["state"] in ("answering", "asking", "failed", "done", "waiting_approval")), None), a.phase_seconds)
        time.sleep(max(0, 60 - (time.time() - t0)))
        rec = {"format": fmt, "job": summary(j) if j else None, "latest_outcomes": labels(), "seconds_to_job_state": round(time.time() - t0) if j else None,
               "result": ("healed automatically" if j and j["state"] == "done" and j["kind"] == "heal" else
                          "asked the operator" if j and j["state"] in ("answering", "asking") else
                          "quarantined (the job failed: " + j["steps"][-1]["text"][:300] + ")" if j and j["state"] == "failed" else
                          "waiting for the operator's approval" if j and j["state"] == "waiting_approval" else
                          "quarantined (no job within the phase)")}
        rep["drift"].append(rec)
        print(fmt, "->", rec["result"], "|", (j or {}).get("kind"), "|", list(rec["latest_outcomes"].items())[:3])
    rep["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    rep["alerts"] = get("/api/state")["alerts"]
    Path(a.out).write_text(json.dumps(rep, indent=1, default=str) + "\n")
    print("written:", a.out)


if __name__ == "__main__":
    main()
