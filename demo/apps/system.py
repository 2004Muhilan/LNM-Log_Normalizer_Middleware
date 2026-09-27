#!/usr/bin/env python3
"""SYSTEM — ULPF's operator console for the demo (http://127.0.0.1:8765/): it runs ONE runtime, watches what it
writes, and drives onboarding and drift healing through the same CLIs as everything else. Standard library only, offline.
Demo assembly, not pipeline: it parses no log and decides no mapping; every step is `ulpf-runtime …` or `python -m ulpf_learn …`.

    system.py --state DIR            (started by demo/start-demo.sh, which exports what demo/lib.sh resolves)

  one runtime   ingress syslog/TCP + HTTP POST; egress to N DESTINATIONS from demo/apps/destinations.json (a list: a
                transport plus an encoding each — here the SIEM over the bulk encoding and the data lake over HTTP), through
                a BOUNDED spool with one cursor per destination: one dead destination never holds another back
  monitor       tails the evidence index, out.jsonl and q.jsonl; who is connected is read off the evidence records
                (ingest channel + peer), never off the generator
  NEW FORMAT    an unknown signature nobody has onboarded -> onboarding. Policy switch `auto_onboard`: ON = starts by itself
                (the record says: by policy, set by op-014); OFF = waits for the operator's "Onboard" (the Tier 1 decision).
                The operator's answers: `prepared_answers` ON = op-014's prepared sheet is applied (each one an operator
                assertion, marked prepared); OFF = the page asks.
  DRIFT         a changed format of an already onboarded (l1, l2) family of a BOUND source (same ingest channel and peer
                host) -> automatic healing, policy autoheal-1.1: fields carried over on the operator's earlier evidence
                (propagation), a pack hot-loaded, an ALERT; what nobody has evidence for is WITHHELD and asked on the page —
                never answered from the sheet, never guessed. A mandatory attribute unresolved: nothing is promoted, the
                operator is asked first. Two detections: unknown signature (positional, CSV, key=value, LEEF: the router's
                arity sketch) -> the new family is ADDED; routed-then-refused (JSON, XML: no sketch exists, the drafted spec
                rejects unknown keys) -> the family is REPLACED. 1.0 healed unknown signatures only.
"""
import argparse
import base64
import glob
import hashlib
import http.server
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "demo" / "ui"
POLICY_VERSION = "autoheal-1.1"
LOCK = threading.RLock()
ENVELOPES = {"raw": "no envelope", "none": "no envelope", "rfc3164": "syslog RFC 3164", "rfc5424": "syslog RFC 5424", "cef": "CEF header", "leef": "LEEF header"}
SURFACES = {"tokens": "positional text", "kv": "key=value", "csv": "CSV", "json": "JSON", "xml": "XML"}
ATTRIBUTES = ["time", "action_id", "src_endpoint.ip", "src_endpoint.port", "src_endpoint.zone", "dst_endpoint.ip", "dst_endpoint.port", "dst_endpoint.zone",
              "connection_info.protocol_name", "connection_info.protocol_num", "connection_info.direction", "traffic.bytes_out", "traffic.bytes_in", "traffic.packets_out", "traffic.packets_in"]
# op-014's prepared answer sheet for THEIR sensor, by column order (the six shapes carry the same columns in the same order)
SHEET = [("time", "flowtap stamps the line when the flow is logged: it is the event time"), ("action_id", "the verdict code: 1 allowed, 2 denied — the same codes OCSF uses"),
         ("connection_info.protocol_name", "tcp or udp"), ("src_endpoint.ip", "flowtap writes the initiator first"), ("src_endpoint.port", "the initiator's port follows its address"),
         ("dst_endpoint.ip", "the second address is the responder"), ("dst_endpoint.port", "the responder's port follows its address"),
         ("traffic.bytes_out", "first counter: bytes from the initiator"), ("traffic.bytes_in", "second counter: bytes to the initiator")]
SHEET_V2 = {2: ("connection_info.protocol_num", "firmware 2.0 writes the IANA protocol number"), 9: ("src_endpoint.zone", "the new column is the initiator's zone")}


class Tail:
    def __init__(self, path):
        self.path, self.off = path, 0

    def lines(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.off); data = f.read()
        except OSError:
            return
        pos = 0
        while True:
            e = data.find(b"\n", pos)
            if e < 0:
                break
            yield self.off + pos, data[pos:e]
            pos = e + 1
        self.off += pos


class System:
    def __init__(self, a):
        self.dir = Path(a.state); self.ev = self.dir / "ev"; self.run = self.dir / "run-1"
        self.a = a
        self.policy = {"auto_onboard": True, "prepared_answers": True, "operator": "op-014", "heal_policy": POLICY_VERSION}
        self.inventory = json.loads((ROOT / "demo" / "apps" / "inventory.json").read_text())
        self.events, self.order = {}, []          # event_id -> record; arrival order
        self.tails = {}
        self.egress = {}                          # sink name -> {"state", "since", "detail"}
        self.pack_records = []
        self.jobs, self.alerts = [], []
        self.active = {}                          # family key -> {"pack": dir, "job": id, "l1", "l2"}
        self.ignore = {}                          # trigger key -> event id: quarantines at or before it are history
        self.runtime = None
        self.reloads = 0
        self.tick_lock = threading.Lock()
        self.destinations = json.loads(Path(a.destinations).read_text())
        self.health = {}                          # destination name -> (up, detail, checked_at)
        self.siem_action = None                   # outage / recover in progress
        self.traces = {}                          # event id -> the round trip's result
        self.held = set()                         # trigger keys the operator rolled back: no automatic healing until a restart

    # ------------------------------------------------------------------ runtime
    def start_runtime(self):
        self.run.mkdir(parents=True, exist_ok=True)
        (self.dir / "packs.txt").write_text("")
        a = self.a
        cmd = [a.rt, "run", "--pack", a.golden, "--packs-file", str(self.dir / "packs.txt"), "--source-id", "live-ingress-01", "--listen", f"tcp:{a.in_tcp}", "--listen", f"http:{a.in_http}",
               "--idle-timeout", "3600s", "--evidence", str(self.ev), "--out", str(self.run / "out.jsonl"), "--quarantine", str(self.run / "q.jsonl"),
               "--spool", str(self.dir / "spool"), "--spool-cap", a.spool_cap, "--forward-stall-after", "2s", "--forward-drain", "5s"]
        for d in self.destinations:   # N destinations, any kind: the list decides, not the code
            cmd += ["--forward", d["url"]]
        self.runtime = subprocess.Popen(cmd, stdout=open(self.run / "egress-stdout.ndjson", "wb"), stderr=open(self.run / "runtime.err", "wb"), cwd=str(ROOT))

    def err_text(self):
        try:
            return (self.run / "runtime.err").read_text(errors="replace")
        except OSError:
            return ""

    def reload(self):
        before = self.err_text().count("\nreloaded:") + self.err_text().startswith("reloaded:")
        refused = self.err_text().count("reload REFUSED")
        dirs = [v["pack"] for v in self.active.values()]
        tmp = self.dir / "packs.txt.tmp"; tmp.write_text("".join(d + "\n" for d in dirs)); os.replace(tmp, self.dir / "packs.txt")
        self.runtime.send_signal(signal.SIGHUP)
        for _ in range(100):
            t = self.err_text()
            if t.count("reload REFUSED") > refused:
                raise RuntimeError("the runtime refused the pack: " + t.rsplit("reload REFUSED", 1)[1][:300])
            if t.count("\nreloaded:") + t.startswith("reloaded:") > before:
                self.reloads += 1
                return
            time.sleep(0.1)
        raise RuntimeError("the runtime did not confirm the reload")

    # ------------------------------------------------------------------ monitor
    def raw(self, rec):
        try:
            with open(self.ev / (rec["segment_id"] + ".raw"), "rb") as f:
                f.seek(rec["offset"]); return f.read(rec["length"])
        except OSError:
            return None

    def tick(self):
        for p in sorted(glob.glob(str(self.ev / "seg_*.idx.jsonl"))):
            for _, l in self.tails.setdefault(p, Tail(p)).lines():
                try:
                    r = json.loads(l)
                except ValueError:
                    continue
                e = {"rec": r, "ok": None}
                if r.get("framing", {}).get("method") == "gap_record":
                    e["record"] = True
                    try:
                        g = json.loads(self.raw(r) or b"{}")
                    except ValueError:
                        g = {}
                    e["kind"] = g.get("kind")
                    if g.get("kind") in ("egress_stalled", "egress_resumed"):
                        self.egress[g.get("peer")] = {"state": "stalled" if g["kind"] == "egress_stalled" else "delivering", "since": g.get("detected_at"), "detail": g.get("detail")}
                    if g.get("kind") in ("pack_activated", "pack_deactivated"):
                        self.pack_records.append({"kind": g["kind"], "pack": g.get("peer"), "at": g.get("detected_at"), "detail": g.get("detail")})
                with LOCK:
                    self.events[r["event_id"]] = e; self.order.append(r["event_id"])
        out = str(self.run / "out.jsonl")
        for off, l in self.tails.setdefault(out, Tail(out)).lines():
            try:
                lin = json.loads(l)["_lineage"]
            except (ValueError, KeyError):
                continue
            e = self.events.get(lin["event_id"])
            if e is not None:
                e.update(ok=True, pack=lin.get("parser_id"), family=lin.get("family_id"), sig=lin.get("routing_signature", ""), out=(off, len(l)))
        q = str(self.run / "q.jsonl")
        for _, l in self.tails.setdefault(q, Tail(q)).lines():
            try:
                r = json.loads(l)
            except ValueError:
                continue
            e = self.events.get(r.get("event_id"))
            if e is not None:
                e.update(ok=False, stage=r.get("stage"), reason=r.get("reason"), sig=r.get("routing_signature", ""))

    def host_of(self, e):
        return (e["rec"].get("peer") or "").rsplit(":", 1)[0]

    def triggers(self):
        """Quarantined events of the recent window, grouped by what would have to be learned to read them."""
        with LOCK:
            recent = [self.events[i] for i in self.order[-60:]]
        groups = {}
        for e in recent:
            if e.get("ok") is not False or e.get("record"):
                continue
            kind = "unknown_signature" if e["stage"] == "routing" else "parse_drop" if e["stage"] in ("parse", "tiling", "normalize") else None
            if kind is None:
                continue
            key = kind + " " + e["sig"]
            if e["rec"]["event_id"] <= self.ignore.get(key, "") or key in self.held:
                continue
            groups.setdefault(key, []).append(e)
        for key, evs in groups.items():
            if len(evs) >= 10 and not any(j["key"] == key and (j["state"] not in ("done", "failed") or (j["state"] == "failed" and time.time() - j["started"] < 60)) for j in self.jobs):
                kind, sig = key.split(" ", 1)
                parts = sig.split("|")
                job = {"id": f"job-{len(self.jobs) + 1}", "key": key, "trigger": kind, "signature": sig, "l1": parts[0], "l2": parts[1] if len(parts) > 1 else "?", "host": self.host_of(evs[-1]),
                       "state": "starting", "steps": [], "fields": [], "answers": {}, "started": time.time(), "go": threading.Event(), "promote": threading.Event()}
                self.jobs.append(job)
                threading.Thread(target=self.run_job, args=(job,), daemon=True).start()

    def probe(self):
        """UP / DOWN per destination, from its own health URL (one probe per second, not per page refresh)."""
        import urllib.request
        for d in self.destinations:
            try:
                with urllib.request.urlopen(d["health"], timeout=1.5) as r:
                    self.health[d["name"]] = (r.status < 500, f"HTTP {r.status}", time.time())
            except Exception as ex:
                self.health[d["name"]] = (False, type(ex).__name__, time.time())
        siem = next((d for d in self.destinations if d.get("kind") == "siem" and d.get("metrics")), None)
        if siem and self.health.get(siem["name"], (False,))[0] and time.time() - getattr(self, "_metrics_at", 0) >= 5:
            self._metrics_at = time.time()   # the quarantine panel in the SIEM's dashboard: the console's counts, posted as documents
            c = self.state_counts()
            try:
                body = json.dumps({"time": int(time.time() * 1000), **c}).encode()
                urllib.request.urlopen(urllib.request.Request(siem["metrics"], data=body, method="POST", headers={"Content-Type": "application/json"}), timeout=2).read()
            except Exception:
                pass

    def state_counts(self):
        with LOCK:
            evs = [self.events[i] for i in self.order if not self.events[i].get("record")]
        return {"frames": len(evs), "usable": sum(1 for e in evs if e.get("ok") is True), "quarantined": sum(1 for e in evs if e.get("ok") is False)}

    def siem_control(self, action):
        if action not in ("outage", "recover") or self.siem_action:
            raise ValueError("outage | recover, one at a time")
        def run():
            self.siem_action = action
            try:
                r = subprocess.run(["bash", str(ROOT / "demo" / "siem" / "siem.sh"), action], capture_output=True, text=True, timeout=240)
                print(f"siem {action}: {(r.stdout + r.stderr).strip()[-200:]}", flush=True)
            finally:
                self.siem_action = None
        threading.Thread(target=run, daemon=True).start()

    def lake_view(self, event_id=None):
        """The read-only lake page: fixed DuckDB queries over the Parquet the lake writer wrote (DuckDB's own UI fetches its
        assets from ui.duckdb.org at request time — measured: HTTP 500 with no network — so the demo cannot use it)."""
        import duckdb
        lake = Path(self.a.lake)
        con = duckdb.connect()
        out = {"sources": [], "latest": [], "lookup": None, "writer": None}
        try:
            import urllib.request
            out["writer"] = json.loads(urllib.request.urlopen(self.a.lake_status, timeout=1).read())
        except Exception:
            pass
        for src in sorted((lake / "ext").glob("*")) if (lake / "ext").exists() else []:
            fs = sorted(str(f) for f in src.rglob("*.parquet"))
            if not fs:
                continue
            days = con.execute(f"SELECT eventDay, count(*), count(DISTINCT filename) FROM read_parquet({fs!r}, hive_partitioning=true, filename=true) GROUP BY 1 ORDER BY 1").fetchall()
            schemas = {json.dumps(con.execute(f"DESCRIBE SELECT * FROM read_parquet('{f}')").fetchall()) for f in fs}
            size = sum(Path(f).stat().st_size for f in fs)
            out["sources"].append({"source": src.name, "path": str(src.relative_to(lake)) + "/region=…/accountId=…/eventDay=…/", "files": len(fs), "bytes": size, "distinct_schemas": len(schemas),
                                   "columns": len(json.loads(next(iter(schemas)))), "days": [{"day": str(d), "rows": r, "files": n} for d, r, n in days]})
            if src.name == "ulpf_network_activity":
                out["latest"] = [dict(zip(("event_id", "raw_hash", "segment_id", "offset", "time", "src", "dst", "action_id", "family_id", "file"), r)) for r in con.execute(
                    f"SELECT event_id, raw_hash, segment_id, \"offset\", time, src_endpoint.ip, dst_endpoint.ip, action_id, family_id, filename FROM read_parquet({fs!r}, filename=true) ORDER BY time DESC LIMIT 25").fetchall()]
                for r in out["latest"]:
                    r["file"] = str(Path(r["file"]).relative_to(lake))
            if event_id:
                hit = con.execute(f"SELECT event_id, raw_hash, segment_id, \"offset\", length, source_id, parser_id, family_id, filename FROM read_parquet({fs!r}, filename=true) WHERE event_id = ?", [event_id]).fetchone()
                if hit:
                    out["lookup"] = dict(zip(("event_id", "raw_hash", "segment_id", "offset", "length", "source_id", "parser_id", "family_id", "file"), hit))
                    out["lookup"]["file"] = str(Path(out["lookup"]["file"]).relative_to(lake))
        return out

    def findings(self):
        siem = next((d for d in self.destinations if d.get("kind") == "siem"), None)
        if not siem or not self.health.get(siem["name"], (False,))[0] or not siem.get("findings"):
            return []
        sys.path.insert(0, str(ROOT / "demo" / "apps"))
        import trace
        try:
            return trace.findings(siem["findings"])
        except Exception:
            return []

    def prove(self, event_id):
        sys.path.insert(0, str(ROOT / "demo" / "apps"))
        import trace
        siem = next((d for d in self.destinations if d.get("kind") == "siem"), {})
        work = self.dir / "trace"; work.mkdir(exist_ok=True)
        t = trace.trace(event_id, str(self.ev), self.a.lake, siem.get("findings", "http://127.0.0.1:9200"), str(work))
        self.traces[event_id] = t
        return t

    def loop(self):
        last_probe = 0
        while True:
            if time.time() - last_probe >= 1:
                last_probe = time.time()
                threading.Thread(target=self.probe, daemon=True).start()
            try:
                with self.tick_lock:
                    self.tick()
                self.triggers()
            except Exception as ex:   # the console must outlive a bad line
                print("monitor:", ex, file=sys.stderr, flush=True)
            time.sleep(0.6)

    # ------------------------------------------------------------------ jobs
    def step(self, job, text, state=None):
        with LOCK:
            job["steps"].append({"at": time.strftime("%H:%M:%S"), "text": text})
            if state:
                job["state"] = state
        print(f"[{job['id']}] {text}", flush=True)

    def learn(self, *args):
        r = subprocess.run([self.a.python, "-m", "ulpf_learn", *args], cwd=str(ROOT / "learning"), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"ulpf_learn {args[0]} failed: " + (r.stdout + r.stderr)[-500:])
        return r.stdout

    def family_key(self, job, arity):
        return f"{job['l1']}|{job['l2']}" if job["l2"] in ("json", "xml") else f"{job['l1']}|{job['l2']}|{arity}"

    def publish_fields(self, job, session):
        s = json.loads((session / "session.json").read_text())
        certs = {c["context"]["slot_index"]: c for c in s["certificates"].values() if c["status"] != "resolved"}
        prop = {h["slot_index"] for h in s.get("propagated", [])}
        fields = []
        for sl in s["plan"]["slots"]:
            p = sl["parts"][0]; c = certs.get(sl["index"])
            cats = [m["provenance"].get("category") for m in p["mappings"]]
            fields.append({"field": p["field"], "slot": sl["index"], "cls": p["cls"], "samples": sl["samples"][:3], "mapped": [m["attribute"] for m in p["mappings"]], "provenance": cats,
                           "propagated": sl["index"] in prop, "evidenced": bool(cats) and all(x not in ("model_proposal", "fixture_proposal") for x in cats),
                           "ambiguity": c and c["evidence"]["discriminator"].get("ambiguity_class"), "candidates": [r["attribute"] for r in c["ranked_candidates"]] if c else p["candidates"]})
        with LOCK:
            job["fields"], job["blockers"] = fields, s["verdict"]["blockers"]
            job["event_class_uid"], job["provider"] = s["proposal"]["event_class_uid"], s["proposal"]["provider"]
        return s

    def assert_field(self, job, session, field, attribute, note, how):
        self.learn("respond", "--session", str(session), "--discriminator", "operator_assertion", "--field", field, "--attribute", attribute,
                   "--input", f"operator {self.policy['operator']} asserts {field} is {attribute}: {note} [{how}]")
        self.step(job, f"operator {self.policy['operator']} asserts {field} → {attribute}  ({how})")

    def run_job(self, job):
        try:
            self._run_job(job)
        except Exception as ex:
            self.step(job, f"FAILED: {ex}", "failed")
            with LOCK:
                self.ignore[job["key"]] = self.order[-1] if self.order else ""

    def _run_job(self, job):
        work = self.dir / "jobs" / job["id"]; work.mkdir(parents=True, exist_ok=True)
        inv = self.inventory.get(job["host"], {"source_id": "unknown-" + job["host"].replace(".", "-"), "name": "unknown application", "vendor": "unknown", "product": "unknown"})
        src = inv["source_id"]
        same = [k for k, v in self.active.items() if (v["l1"], v["l2"]) == (job["l1"], job["l2"]) and v["source_id"] == src]
        job["kind"] = "heal" if same else "onboard"
        job["source_id"], job["app"] = src, inv["name"]
        fmt = (ENVELOPES.get(job["l1"], job["l1"]) + " → " if job["l1"] not in ("raw", "") else "") + SURFACES.get(job["l2"], job["l2"])
        job["format"] = fmt
        with LOCK:
            mine = [e for e in (self.events[i] for i in self.order) if e.get("ok") is False and job["key"] == ("unknown_signature " if e["stage"] == "routing" else "parse_drop ") + e.get("sig", "")
                    and e["rec"]["event_id"] > self.ignore.get(job["key"], "")]
            known = {(e["rec"].get("ingest_channel"), self.host_of(e)) for e in self.events.values() if e.get("ok") and (e.get("pack") or "").startswith(src)}
        seen = {(e["rec"].get("ingest_channel"), self.host_of(e)) for e in mine}
        bound = bool(seen) and seen <= known
        if job["kind"] == "heal":
            self.step(job, f"DRIFT on {inv['name']}: {fmt} lines no longer {'match any family' if job['trigger'] == 'unknown_signature' else 'parse under their family'} — {len(mine)} quarantined, bytes kept", "sampling")
            alert = {"id": f"alert-{len(self.alerts) + 1}", "alert": "drift_auto_heal", "policy_version": POLICY_VERSION, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "app": inv["name"], "host": job["host"],
                     "source_id": src, "format": fmt, "trigger": {"kind": job["trigger"], "signature": job["signature"], "quarantined_events": len(mine)},
                     "source_binding": {"bound": bound, "drifted_from": sorted(map(list, seen)), "source_known_from": sorted(map(list, known)), "limit": "binding is by ingest channel and peer host; the transports in use authenticate nobody"},
                     "outcome": "healing…", "job": job["id"]}
            with LOCK:
                self.alerts.append(alert); job["alert"] = alert
            if not bound:
                alert["outcome"] = "refused: the drifted traffic is not bound to the onboarded source (another channel or host) — a human decides"
                self.step(job, alert["outcome"], "waiting_approval")
                job["go"].wait()
        else:
            self.step(job, f"NEW FORMAT from {inv['name']}: {fmt} — every line quarantined, bytes kept, nothing parsed, nothing guessed", "sampling")
            if self.policy["auto_onboard"]:
                job["decision"] = {"decision": "onboard", "tier": 1, "by": "policy auto_onboard (set by " + self.policy["operator"] + ")", "at": time.strftime("%H:%M:%S"), "quarantined_when_decided": len(mine)}
                self.step(job, "onboarding started BY POLICY (auto-onboard is on; set by " + self.policy["operator"] + ")")
            else:
                self.step(job, "waiting for the operator: Onboard this application's format? (auto-onboard is off)", "waiting_approval")
                job["go"].wait()
                job["decision"] = {"decision": "onboard", "tier": 1, "by": self.policy["operator"] + " (button)", "at": time.strftime("%H:%M:%S"), "quarantined_when_decided": len(mine)}
                self.step(job, f"operator {self.policy['operator']} said: onboard this")
        (work / "decision.json").write_text(json.dumps(job.get("decision") or job.get("alert", {}).get("source_binding"), indent=1))
        # samples out of the evidence store, raw_hash checked
        lines = []
        for e in mine[-24:]:
            raw = self.raw(e["rec"])
            if raw is None or "sha256:" + hashlib.sha256(raw).hexdigest() != e["rec"]["raw_hash"]:
                raise RuntimeError(f"evidence bytes of {e['rec']['event_id']} do not match their raw_hash — refusing to use them")
            lines.append(raw.rstrip(b"\r\n"))
        (work / "samples.log").write_bytes(b"".join(l + b"\n" for l in lines))
        self.step(job, f"{len(lines)} samples taken out of the evidence log (raw_hash checked)", "model")
        a = self.a
        prov = (["--provider", "model", "--model-id", a.model_id, "--server", a.server, "--backend", a.backend, "--mode", "whole"] if a.provider == "model"
                else ["--provider", "fixture", "--fixture", str(ROOT / "demo" / "live" / "flowtap-proposals.json")])
        self.step(job, ("the local model labels the fields" if a.provider == "model" else "FALLBACK: team-authored proposals stand in for the model") + " — proposals only, never evidence")
        session = work / "session"
        t0 = time.time()
        self.learn("onboard", "--samples", str(work / "samples.log"), "--source-id", src, "--operator", self.policy["operator"] if job["kind"] == "onboard" else "auto-heal", "--session", str(session),
                   "--vendor", inv["vendor"], "--product", inv["product"], "--transport-hint", "syslog-tcp", "--propagation-store", str(self.dir / "propagation.json"), *prov)
        s = self.publish_fields(job, session)
        arity = s["structure"]["arity"]
        drafted = s.get("drafted")
        self.step(job, f"structure {'drafted from the lines own keys' if drafted else 'induced'}: {arity} fields; proposals in {time.time() - t0:.1f}s; {len(s['certificates'])} ambiguity certificate(s); "
                       f"{len(s.get('propagated', []))} field(s) carried over from earlier answers")
        version = "1.0"
        if job["kind"] == "onboard":
            if self.policy["prepared_answers"]:
                self.step(job, "answers: the operator's PREPARED SHEET (policy prepared_answers is on)", "answering")
                for f in list(job["fields"]):
                    ans = SHEET_V2.get(f["slot"]) if arity == 10 and f["slot"] in SHEET_V2 else SHEET[f["slot"]] if f["slot"] < len(SHEET) else None
                    if ans and not f["propagated"]:
                        self.assert_field(job, session, f["field"], ans[0], ans[1], "prepared sheet")
                self.publish_fields(job, session)
            else:
                self.step(job, "waiting for the operator: say what each field is, then press Promote", "answering")
                self.wait_answers(job, session)
        else:
            alert = job["alert"]
            alert["propagated"] = [f["field"] for f in job["fields"] if f["propagated"]]
            alert["model_proposed"] = {f["field"]: f["candidates"] or f["mapped"] for f in job["fields"] if not f["propagated"]}
            if job["blockers"]:
                alert["outcome"] = "blocked: a mandatory attribute did not resolve — nothing is promoted until the operator answers"
                alert["blockers"] = job["blockers"]
                self.step(job, alert["outcome"], "answering")
                self.wait_answers(job, session)
        self.promote_and_load(job, session, work, arity, version, replace=None)
        if job["kind"] == "heal":
            withheld = [f for f in job["fields"] if not f["evidenced"]]
            alert = job["alert"]
            alert["auto_promoted"] = [{"field": f["field"], "attribute": f["mapped"][0], "provenance": f["provenance"][0]} for f in job["fields"] if f["evidenced"] and f["mapped"]]
            alert["withheld"] = [{"field": f["field"], "samples": f["samples"], "why": ("ambiguous between " + ", ".join(f["candidates"])) if f["ambiguity"] else "a proposal is not evidence" if f["mapped"] or f["candidates"] else "nobody has said what this field is"} for f in withheld]
            alert["pack"] = job["pack"]
            alert["outcome"] = ("healed: every field resolved on sufficient evidence" if not withheld else
                                f"healed in part: {len(alert['auto_promoted'])} field(s) carried over on earlier evidence, {len(withheld)} withheld — the operator is asked")
            self.step(job, "ALERT: " + alert["outcome"], "asking" if withheld else "done")
            if withheld:
                self.wait_answers(job, session, only=[f["field"] for f in withheld])
                self.promote_and_load(job, session, work, arity, "1.1", replace=job["family_key"])
                alert["pack"] = job["pack"]
                alert["answered"] = dict(job["answers"]); alert["outcome"] += f" → answered by {self.policy['operator']}, pack {job['pack']['pack_version']} loaded"
        self.step(job, "done: events of this format are normalized from here on", "done")

    def wait_answers(self, job, session, only=None):
        """The page posts answers into job['answers'] and then sets job['promote']; each answer is applied through `respond`."""
        done = set()
        while True:
            job["promote"].wait(0.3)
            for f, attr in list(job["answers"].items()):
                if f not in done and (only is None or f in only):
                    self.assert_field(job, session, f, attr, "chosen on the System page", "asked on the page")
                    done.add(f)
                    self.publish_fields(job, session)
            if job["promote"].is_set():
                job["promote"].clear()
                if job.get("blockers"):
                    self.step(job, "cannot promote yet: " + "; ".join(job["blockers"])[:200])
                    continue
                return

    def promote_and_load(self, job, session, work, arity, version, replace):
        fam = json.loads((session / "session.json").read_text())["plan"].get("family_id") or f"positional-{arity}"
        out = work / f"pack-{version}"
        self.step(job, "promoting: acceptance policy, signed pack" + (" (what rests on a proposal alone is withheld, carried unmapped)" if job["kind"] == "heal" else ""), "promoting")
        self.learn("promote", "--session", str(session), "--out", str(out), "--pack-id", f"{job['source_id']}-{fam}", "--withhold-unevidenced", "--pack-version", version)
        r = subprocess.run([self.a.rt, "verify-pack", "--pack", str(out)], capture_output=True, text=True, cwd=str(ROOT))
        if r.returncode != 0:
            raise RuntimeError("verify-pack: " + (r.stdout + r.stderr)[-300:])
        key = self.family_key(job, arity)
        doc = json.loads((out / "pack.json").read_text())
        with LOCK:
            prev = [v["pack"] for v in self.active.values()]
            if self.active.get(key, {}).get("job") != job["id"]:
                job["replaced"] = self.active.get(key)   # what a rollback restores: the family this pack replaced, or nothing (it was added)
            self.active[key] = {"pack": str(out), "job": job["id"], "l1": job["l1"], "l2": job["l2"], "source_id": job["source_id"], "pack_id": doc["pack_id"], "pack_version": doc["pack_version"], "family": fam}
            job["family_key"] = key
            job["pack"] = {"pack_id": doc["pack_id"], "pack_version": doc["pack_version"], "sha256": "sha256:" + hashlib.sha256((out / "pack.json").read_bytes()).hexdigest(),
                           "signed_by": doc["signing"]["authority_id"], "previous_packs": prev}
        self.reload()
        with self.tick_lock:
            self.tick()   # everything that arrived before the reload is history for this trigger
        with LOCK:
            self.ignore[job["key"]] = self.order[-1] if self.order else ""
        self.publish_fields(job, session)
        self.step(job, f"pack {doc['pack_id']} v{doc['pack_version']} verified by the Go engine and HOT-LOADED — no restart; the activation is an evidence-log record")

    def rollback(self, alert_id):
        """One click back: this job's pack leaves the runtime, the family it replaced (if any) returns; the change is an
        evidence-log record like the activation was. Automatic healing of that format is HELD until a restart — the operator
        overruled the policy, the policy does not answer back."""
        al = next((x for x in self.alerts if x["id"] == alert_id), None)
        job = next((j for j in self.jobs if al and j["id"] == al["job"]), None)
        if not job or "family_key" not in job:
            raise ValueError("nothing to roll back")
        with LOCK:
            cur = self.active.get(job["family_key"])
            if not cur or cur["job"] != job["id"]:
                raise ValueError("already superseded by a later pack")
            if job.get("replaced"):
                self.active[job["family_key"]] = job["replaced"]
            else:
                del self.active[job["family_key"]]
            self.held.add(job["key"])
        self.reload()
        al["outcome"] += " → ROLLED BACK by " + self.policy["operator"] + "; automatic healing of this format is held"
        al["rolled_back"] = True

    # ------------------------------------------------------------------ views
    def state(self):
        with LOCK:
            apps = {}
            now_ms = time.time() * 1000
            for i in self.order:
                e = self.events[i]
                if e.get("record"):
                    continue
                h = self.host_of(e)
                a = apps.setdefault(h, {"host": h, "events": 0, "usable": 0, "quarantined": 0})
                a["events"] += 1; a["usable"] += e.get("ok") is True; a["quarantined"] += e.get("ok") is False
                a["channel"], a["peer"], a["last_ms"] = e["rec"].get("ingest_channel"), e["rec"].get("peer"), e["rec"].get("ingest_time") or 0
            for h, a in apps.items():
                inv = self.inventory.get(h, {})
                a["name"], a["source_id"] = inv.get("name", "unknown application"), inv.get("source_id")
                a["connector"] = {"tcp": "Syslog over TCP", "http": "HTTP POST"}.get((a.get("channel") or "").split(":")[0], a.get("channel"))
                a["idle_s"] = round((now_ms - a["last_ms"]) / 1000, 1)
                a["connected"] = a["idle_s"] < 3
                a["alert"] = any(j.get("host") == h and j["state"] not in ("done", "failed") for j in self.jobs)
            recent = [self.events[i] for i in self.order[-40:] if not self.events[i].get("record") and self.events[i].get("ok") is not None]
            curs = {}
            for f in (self.dir / "spool").glob("cursor-*.json"):
                try:
                    c = json.loads(f.read_text()); curs[c["sink"]] = c
                except (OSError, ValueError, KeyError):
                    pass
            usable = sum(a["usable"] for a in apps.values())
            egress = []
            for d in self.destinations:
                sink = ("bulk+" + d["url"][len("bulk+"):]) if d["url"].startswith("bulk+") else d["url"]
                cur = curs.get(sink, {})
                up, why, _ = self.health.get(d["name"], (False, "not probed yet", 0))
                st = self.egress.get(sink, {})
                egress.append({"name": d["name"], "kind": d.get("kind"), "url": d["url"], "ui": d.get("ui"), "up": up, "why": why, "delivery": st.get("state") or ("delivering" if cur.get("delivered_events") else "waiting"),
                               "delivered": cur.get("delivered_events", 0), "ahead_by": max(0, usable - cur.get("delivered_events", 0)), "skipped": cur.get("skipped_events", 0),
                               "rejected": cur.get("rejected_events", 0), "last_event_id": cur.get("last_event_id")})
            jobs = [{k: v for k, v in j.items() if k not in ("go", "promote")} for j in self.jobs]
            return {"policy": self.policy, "runtime": {"up": self.runtime is not None and self.runtime.poll() is None, "ingress": [{"label": "Syslog over TCP", "addr": self.a.in_tcp}, {"label": "HTTP POST", "addr": self.a.in_http}],
                                                       "packs": [{"pack_id": v["pack_id"], "pack_version": v["pack_version"], "family": v["family"]} for v in self.active.values()], "reloads": self.reloads,
                                                       "provider": self.a.provider, "pack_records": self.pack_records[-6:]},
                    "apps": list(apps.values()), "egress": egress, "siem_action": self.siem_action, "jobs": jobs, "alerts": self.alerts, "attributes": ATTRIBUTES,
                    "counts": {"frames": sum(a["events"] for a in apps.values()), "usable": sum(a["usable"] for a in apps.values()), "quarantined": sum(a["quarantined"] for a in apps.values())},
                    "parse_success": round(sum(1 for e in recent if e["ok"]) / len(recent), 3) if recent else None}

    def fmt_of(self, sig):
        p = (sig or "").split("|")
        return " → ".join(x for x in (ENVELOPES.get(p[0], p[0]) if p and p[0] not in ("", "raw") else "", SURFACES.get(p[1], p[1]) if len(p) > 1 else "") if x) or "?"

    def logs(self, host, limit=120):
        with LOCK:
            ids = [i for i in reversed(self.order) if not self.events[i].get("record") and self.host_of(self.events[i]) == host][:limit]
            rows = []
            for i in ids:
                e = self.events[i]; raw = self.raw(e["rec"]) or b""
                rows.append({"event_id": i, "at": time.strftime("%H:%M:%S", time.localtime((e["rec"].get("ingest_time") or 0) / 1000)), "connector": (e["rec"].get("ingest_channel") or "").split(":")[0],
                             "bytes": e["rec"]["length"], "format": self.fmt_of(e.get("sig")) if e.get("ok") is not None else "…", "ok": e.get("ok"),
                             "outcome": e.get("family") if e.get("ok") else ("quarantined: " + e.get("stage", "")) if e.get("ok") is False else "in flight", "preview": raw[:130].decode("utf-8", "replace")})
            return rows

    def describe(self, eid):
        with LOCK:
            e = self.events.get(eid)
        if e is None:
            return None
        rec, raw = e["rec"], self.raw(e["rec"])
        ev = None
        if e.get("out"):
            with open(self.run / "out.jsonl", "rb") as f:
                f.seek(e["out"][0]); ev = json.loads(f.read(e["out"][1]))
        lin = (ev or {}).get("_lineage", {})
        p = (e.get("sig") or "").split("|")
        env = lin.get("envelope") or {}
        return {"event_id": eid,
                "raw": {"text": raw.decode("utf-8", "replace") if raw is not None else None, "base64": base64.b64encode(raw or b"").decode(), "bytes": rec["length"], "raw_hash": rec["raw_hash"],
                        "hash_verified_now": raw is not None and "sha256:" + hashlib.sha256(raw).hexdigest() == rec["raw_hash"], "segment": rec["segment_id"], "offset": rec["offset"],
                        "ingest_time_ms": rec.get("ingest_time"), "ingest_channel": rec.get("ingest_channel"), "peer": rec.get("peer"), "framing": rec.get("framing")},
                "format": {"envelope": ENVELOPES.get(p[0], p[0]) if p and p[0] else "no envelope", "envelope_header": env or None, "surface": SURFACES.get(p[1], p[1]) if len(p) > 1 else None,
                           "arity": p[3] if len(p) > 3 else None, "token_classes": p[4].split(",") if len(p) > 4 and p[4] else None, "routing_signature": e.get("sig")},
                "parsed": ({"status": "normalized", "pack": lin.get("parser_id"), "pack_version": lin.get("parser_version"), "family": lin.get("family_id"), "event": {k: v for k, v in ev.items() if k != "_lineage"}, "lineage": lin}
                           if ev else {"status": "quarantined", "stage": e.get("stage"), "reason": e.get("reason")} if e.get("ok") is False else {"status": "in flight"})}


def handler(sysm):
    class H(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body=b"", ctype="application/json"):
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

        def do_GET(self):
            p, _, qs = self.path.partition("?")
            q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
            if p == "/api/state":
                return self._send(200, json.dumps(sysm.state(), default=str).encode())
            if p == "/api/logs":
                return self._send(200, json.dumps(sysm.logs(q.get("host", ""))).encode())
            if p == "/api/log":
                d = sysm.describe(q.get("id", ""))
                return self._send(200 if d else 404, json.dumps(d).encode())
            if p == "/api/lake":
                try:
                    return self._send(200, json.dumps(sysm.lake_view(q.get("event_id")), default=str).encode())
                except Exception as ex:
                    return self._send(200, json.dumps({"error": f"{type(ex).__name__}: {ex}", "sources": [], "latest": []}).encode())
            if p == "/api/findings":
                return self._send(200, json.dumps(sysm.findings()).encode())
            if p == "/api/trace":
                return self._send(200, json.dumps(sysm.traces.get(q.get("id", ""))).encode())
            f = {"/": "system.html", "/lake": "lake.html", "/theme.css": "theme.css"}.get(p)
            if not f:
                return self._send(404, b"not found", "text/plain")
            self._send(200, (UI / f).read_bytes(), "text/css" if f.endswith(".css") else "text/html; charset=utf-8")

        def do_POST(self):
            try:
                d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)) or b"{}")
                job = next((j for j in sysm.jobs if j["id"] == d.get("job")), None)
                if self.path == "/api/policy":
                    for k in ("auto_onboard", "prepared_answers"):
                        if isinstance(d.get(k), bool):
                            sysm.policy[k] = d[k]
                elif self.path == "/api/approve" and job:
                    job["go"].set()
                elif self.path == "/api/answer" and job and d.get("attribute") in ATTRIBUTES and any(f["field"] == d.get("field") for f in job["fields"]):
                    job["answers"][d["field"]] = d["attribute"]
                elif self.path == "/api/promote" and job:
                    job["promote"].set()
                elif self.path == "/api/rollback":
                    sysm.rollback(d.get("alert"))
                elif self.path == "/api/siem":
                    sysm.siem_control(d.get("action"))
                elif self.path == "/api/prove" and str(d.get("event_id", "")).startswith("ev_"):
                    threading.Thread(target=sysm.prove, args=(d["event_id"],), daemon=True).start()
                else:
                    raise ValueError("unknown request")
                self._send(204)
            except (ValueError, RuntimeError) as ex:
                self._send(400, str(ex).encode(), "text/plain")

        def log_message(self, *a):
            pass
    return H


def main() -> int:
    ap = argparse.ArgumentParser(description="ULPF demo: the system console")
    ap.add_argument("--state", required=True); ap.add_argument("--listen", default="127.0.0.1:8765")
    ap.add_argument("--rt", default=str(ROOT / "runtime" / "bin" / "ulpf-runtime")); ap.add_argument("--golden", default=str(ROOT / "contracts" / "golden" / "squid-native"))
    ap.add_argument("--in-tcp", default="127.0.0.1:6515"); ap.add_argument("--in-http", default="127.0.0.1:8516"); ap.add_argument("--destinations", default=str(ROOT / "demo" / "apps" / "destinations.json"))
    ap.add_argument("--spool-cap", default="256MiB"); ap.add_argument("--lake", required=True); ap.add_argument("--lake-status", default="http://127.0.0.1:8792/status")
    ap.add_argument("--python", default="python"); ap.add_argument("--provider", choices=["model", "fixture"], default="fixture")
    ap.add_argument("--model-id", default=""); ap.add_argument("--server", default="http://127.0.0.1:8081"); ap.add_argument("--backend", default="unknown")
    a = ap.parse_args()
    s = System(a)
    s.start_runtime()
    threading.Thread(target=s.loop, daemon=True).start()
    host, port = a.listen.rsplit(":", 1)
    srv = http.server.ThreadingHTTPServer((host, int(port)), handler(s))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    print(f"system: http://{a.listen}/  (state: {a.state}; provider: {a.provider})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if s.runtime and s.runtime.poll() is None:
            s.runtime.terminate()
            try:
                s.runtime.wait(8)
            except subprocess.TimeoutExpired:
                s.runtime.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
