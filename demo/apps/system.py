#!/usr/bin/env python3
"""SYSTEM — ULPF's operator console for the demo (http://127.0.0.1:8765/): it runs N runtime PROCESSES on the same
ingress addresses (SO_REUSEPORT: the kernel keeps each sender's connection on one process), watches what they write, and
drives onboarding and drift healing through the same CLIs as everything else. Standard library only, offline.
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
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "demo" / "ui"
POLICY_VERSION = "autoheal-1.1"
LOCK = threading.RLock()
ENVELOPES = {"raw": "no envelope", "none": "no envelope", "rfc3164": "syslog RFC 3164", "rfc5424": "syslog RFC 5424", "cef": "CEF header", "leef": "LEEF header"}
SURFACES = {"tokens": "positional text", "kv": "key=value", "csv": "CSV", "json": "JSON", "xml": "XML"}
ATTRIBUTES = ["time", "action_id", "src_endpoint.ip", "src_endpoint.port", "src_endpoint.zone", "dst_endpoint.ip", "dst_endpoint.port", "dst_endpoint.zone",
              "connection_info.protocol_name", "connection_info.protocol_num", "connection_info.direction", "traffic.bytes_out", "traffic.bytes_in", "traffic.packets_out", "traffic.packets_in",
              # a device's own events (2026-09-30, the FortiGate's system events: OCSF Authentication and kin); the learning
              # plane checks every answer against the pinned table of the class being onboarded
              "user.name", "status_id", "status", "status_detail", "message", "activity_id", "logon_type", "auth_protocol", "service.name", "metadata.event_code",
              # an IDS's alerts (2026-09-30, Suricata: OCSF Detection Finding)
              "finding_info.title", "finding_info.uid", "finding_info.desc", "severity_id", "severity", "action", "confidence_id"]
# op-014's prepared answer sheet for THEIR sensor, by column order (the six shapes carry the same columns in the same order)
SHEET = [("time", "flowtap stamps the line when the flow is logged: it is the event time"), ("action_id", "the verdict code: 1 allowed, 2 denied — the same codes OCSF uses"),
         ("connection_info.protocol_name", "tcp or udp"), ("src_endpoint.ip", "flowtap writes the initiator first"), ("src_endpoint.port", "the initiator's port follows its address"),
         ("dst_endpoint.ip", "the second address is the responder"), ("dst_endpoint.port", "the responder's port follows its address"),
         ("traffic.bytes_out", "first counter: bytes from the initiator"), ("traffic.bytes_in", "second counter: bytes to the initiator")]
SHEET_V2 = {2: ("connection_info.protocol_num", "firmware 2.0 writes the IANA protocol number"), 9: ("src_endpoint.zone", "the new column is the initiator's zone")}
# A prepared sheet is BOUND to the source it was prepared for (2026-09-30): it answers that source's fields and no
# other's. Before, the sheet was applied by column position to whatever was being onboarded — on the real FortiGate it
# asserted "position 1 is time" on a CEF line; only the acceptance policy kept that pack out.
# Suricata's EVE alert fields BY NAME (2026-10-02, the user's request: no hand labelling on every onboarding): op-014's
# answers written down in advance from Suricata's EVE documentation, bound to this one sensor. The fields it does not name
# are left unmapped (carried under their own names).
SURICATA_SHEET = {"timestamp": ("time", "EVE: the time the event was logged", None),
                  "src_ip": ("src_endpoint.ip", "EVE: the packet's source address", None), "src_port": ("src_endpoint.port", "EVE: the source port", None),
                  "dest_ip": ("dst_endpoint.ip", "EVE: the packet's destination address", None), "dest_port": ("dst_endpoint.port", "EVE: the destination port", None),
                  "proto": ("connection_info.protocol_name", "EVE: the transport protocol", None),
                  "action": ("action_id", "EVE alert.action: what the sensor did — allowed 1, blocked 2 (OCSF's codes)", {"allowed": 1, "blocked": 2}),
                  "signature": ("message", "EVE alert.signature: the rule's message", None)}
PREPARED_SHEETS = {"flowtap-01": {"author": "op-014", "for": "the flowtap sensor's columns", "by_slot": SHEET, "v2": SHEET_V2},
                   "suricata-lab-01": {"author": "op-014", "for": "Suricata's EVE alert fields, by name", "by_name": SURICATA_SHEET}}
# Adding a runtime process (container deployment): at most one per CPU Docker reports, and not below this much free memory
# (a process's three containers measured ~170 MiB together: runtime ~20, lake writer ~130, committer ~10 — docs/laptop-branch.md §7)
MIN_FREE_BYTES = 512 << 20
# a Docker bridge gateway: what a sender's address becomes through a published port (measured 2026-10-01: 172.17.0.1)
DOCKER_GATEWAY = re.compile(r"^172\.(1[7-9]|2\d|3[01])\.0\.1$")


class Tail:
    """Follows a file by offset. With `fallback` (the evidence archive): an index file deleted locally after shipping,
    before the console had read all of it, is finished from its archived copy — byte-identical, so the offset holds."""
    def __init__(self, path, fallback=None):
        self.path, self.off, self.fallback, self.done = path, 0, fallback, False

    def lines(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.off); data = f.read()
        except OSError:
            alt = self.fallback(self.path) if self.fallback and not self.done else None
            if not alt:
                return
            try:
                with open(alt, "rb") as f:
                    f.seek(self.off); data = f.read()
            except OSError:
                return
            self.done = True   # a shipped segment is sealed: its archived index is complete
        pos = 0
        while True:
            e = data.find(b"\n", pos)
            if e < 0:
                break
            yield self.off + pos, data[pos:e]
            pos = e + 1
        self.off += pos


class Scaler:
    """The container deployment (deploy/, 2026-10-01): the console ASKS deploy/scaler.py — the only container with the
    Docker socket — to start, stop and signal the containers of a runtime process. The scaler owns the template (image,
    mounts, user, capability, network); the console chooses the unit number and its program's arguments."""
    def __init__(self, url):
        self.url = url.rstrip("/")
        self._info, self._at = None, 0.0

    def call(self, method, path, body=None, timeout=60, text=False):
        req = urllib.request.Request(self.url + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
        except urllib.error.HTTPError as ex:
            raise RuntimeError(f"scaler {path}: {ex.read()[:300].decode(errors='replace')}") from None
        return data.decode("utf-8", "replace") if text else json.loads(data)

    def info(self, max_age=1.0):
        if self._info is None or time.time() - self._at > max_age:
            self._info, self._at = self.call("GET", "/info", timeout=10), time.time()
        return self._info

    def state_of(self, unit, part):
        try:
            return next((u["state"] for u in self.info()["units"] if u["unit"] == unit and u["part"] == part), "absent")
        except Exception:   # noqa: BLE001 — the scaler unreachable is a state the page shows
            return "unknown"

    def start(self, unit, part, args):
        self._info = None
        return self.call("POST", "/start", {"unit": unit, "part": part, "args": [str(x) for x in args]})

    def stop(self, unit, part, timeout=20):
        self._info = None
        return self.call("POST", "/stop", {"unit": unit, "part": part, "timeout": timeout}, timeout=timeout + 60)

    def signal(self, unit, part, sig="HUP"):
        return self.call("POST", "/signal", {"unit": unit, "part": part, "signal": sig})

    def logs(self, unit, part):
        return self.call("GET", f"/logs?unit={unit}&part={part}", timeout=20, text=True)


class Proc:
    """One ULPF runtime process of N (scale-out). Its own evidence directory (its own store_id), outputs, spool, commit
    tree and lake writer; shared: the ingress addresses (SO_REUSEPORT), the packs, the evidence archive, the SIEM, the lake
    root. Process 1 keeps the single-process names (ev, run-1, spool, commit).
    Two ways to run it: a child process of this console (start-demo.sh: the number is fixed at start), or — the container
    deployment — a UNIT of containers (runtime, committer, lake writer) through the scaler, added and removed while running.
    `state`: starting | running | draining | retired (a retired process's evidence stays readable: Prove it still works)."""
    def __init__(self, i, base, a, ctl=None):
        sfx = "" if i == 1 else f"-{i}"
        self.i = i
        self.ev, self.run, self.spool = base / ("ev" + sfx), base / f"run-{i}", base / ("spool" + sfx)
        self.commit = (a.commit_dir + sfx) if a.commit_dir else None
        self.lake_port = a.lake_port + i - 1
        self.packs = base / ("packs.txt" if i == 1 else f"packs-{i}.txt")
        self.runtime = None
        self.ctl = ctl
        self.state = "starting"
        self.label = i          # the number the page shows: a new process takes the lowest free one (2026-10-02, the user's request)
        self.final_log = None   # a removed runtime container's last log (its log goes with the container)

    def err_text(self):
        if self.ctl:
            if self.final_log is not None:
                return self.final_log
            try:
                return self.ctl.logs(self.i, "runtime")
            except Exception:   # noqa: BLE001 — not started yet, or the scaler is unreachable
                return ""
        try:
            return (self.run / "runtime.err").read_text(errors="replace")
        except OSError:
            return ""

    def alive(self):
        if self.ctl:
            return self.state != "retired" and self.ctl.state_of(self.i, "runtime") == "running"
        return self.runtime is not None and self.runtime.poll() is None

    def hup(self):
        if self.ctl:
            self.ctl.signal(self.i, "runtime", "HUP")
        else:
            self.runtime.send_signal(signal.SIGHUP)

    def ident(self):
        if self.ctl:
            if self.state == "retired":
                return "container removed"
            try:
                return "container " + next(u["name"] for u in self.ctl.info()["units"] if u["unit"] == self.i and u["part"] == "runtime")
            except Exception:   # noqa: BLE001
                return "container —"
        return f"pid {self.runtime.pid}" if self.runtime else "—"

    def store_id(self):
        try:
            return json.loads((self.ev / "store.json").read_text())["store_id"]
        except (OSError, ValueError, KeyError):
            return None


def dest_for(d, proc):
    """A destination as one process sees it: {lake_port} is that process's lake writer."""
    return {k: (v.replace("{lake_port}", str(proc.lake_port)) if isinstance(v, str) else v) for k, v in d.items()}


def sink_name(url):
    """What the runtime names a sink (its cursor file): the URL without the batch parameter."""
    base, _, q = url.partition("?")
    keep = [kv for kv in q.split("&") if kv and not kv.startswith("batch=")]
    return base + ("?" + "&".join(keep) if keep else "")


class System:
    def __init__(self, a):
        self.dir = Path(a.state)
        self.a = a
        self.scaler = Scaler(a.scaler) if a.scaler else None   # the container deployment: processes can be added and removed
        self.procs = [Proc(i, self.dir, a, self.scaler) for i in range(1, a.processes + 1)]
        self.scale_busy, self.scale_history = None, []
        self.proc_lock = threading.Lock()   # a reload and the start of an added process never interleave
        self.lake_on = a.mode != "devices"   # devices mode: the lake's writers start on "Connect the lake"
        self.ev, self.run = self.procs[0].ev, self.procs[0].run   # process 1 (the single-process names)
        self.started = time.time()
        self.mode = a.mode   # generator (the fallback, and the gate) | devices (the final demo: the real FortiGate and Suricata)
        # devices mode: auto-onboard starts OFF — an unknown source's onboarding waits for the presenter's "Onboard" click on stage
        self.policy = {"auto_onboard": a.mode != "devices", "prepared_answers": True, "operator": "op-014", "heal_policy": POLICY_VERSION,
                       "vendor_relay": bool(a.vendor_capture and Path(a.vendor_capture).exists()) and a.mode != "devices"}
        self.devices = None
        if a.mode == "devices":
            sys.path.insert(0, str(ROOT / "demo" / "apps"))
            from devices import Devices
            self.devices = Devices(Path(a.state) / "devices.log")
            threading.Thread(target=self.devices_watch, daemon=True).start()
        self.lake_writers = {}   # devices mode: process i -> the lake writer this console started ("Connect the lake")
        self.relay_sent = 0
        self.inventory = json.loads((ROOT / "demo" / "apps" / "inventory.json").read_text())
        self.events, self.order = {}, []          # event_id -> record; arrival order
        self.tails = {}
        self.egress = {}                          # sink name -> {"state", "since", "detail"}
        self.pack_records = []
        self.jobs, self.alerts = [], []
        self.active = {}                          # family key -> {"pack": dir, "job": id, "l1", "l2"}
        self.ignore = {}                          # trigger key -> event id: quarantines at or before it are history
        self.reloads = 0
        self.tick_lock = threading.Lock()
        # $VARIABLES in the list are the deployment's (deploy/destinations.json: the SIEM's port is a setting)
        self.destinations = [{k: os.path.expandvars(v) if isinstance(v, str) else v for k, v in d.items()} for d in json.loads(Path(a.destinations).read_text())]
        self.health = {}                          # destination name -> (up, detail, checked_at)
        self.siem_action = None                   # outage / recover in progress
        self.traces = {}                          # event id -> the round trip's result
        self.held = set()                         # trigger keys the operator rolled back: no automatic healing until a restart
        self.tlog_refusals = []                   # packs a process refused (pack_refused records in its evidence log)
        self.bound = {}                           # (ingest channel, peer host) -> {pack_id: events it parsed}: the SOURCE BINDING
        self.pack_vendor = {}                     # pack_id -> declared vendor (lower case), for the packs loaded at start
        self.pack_dir = {}                        # pack_id -> its directory (the packs loaded at start)
        self.pack_family_keys = {}                # pack_id -> the keys its families are told apart by (key-locator anchors)
        for d in [a.golden] + [str(Path(a.vendor_packs) / v) for v in ("cisco-asa", "panos", "fortigate") if a.vendor_packs]:
            try:
                doc = json.loads((Path(d) / "pack.json").read_text())
                self.pack_vendor[doc["pack_id"]] = (doc.get("source") or {}).get("vendor", "").lower()
                self.pack_dir[doc["pack_id"]] = d
                keyof = {x["anchor_id"]: x["locator"].get("key") for x in doc.get("anchors", []) if x.get("locator", {}).get("kind") == "key"}
                self.pack_family_keys[doc["pack_id"]] = sorted({keyof[v["anchor_id"]] for f in doc.get("families", [])
                                                                for v in f.get("routing_signature", {}).get("l3_anchor_values", []) if keyof.get(v["anchor_id"])})
            except (OSError, ValueError, KeyError):
                pass

    # ------------------------------------------------------------------ runtime
    def start_runtime(self):
        if self.scaler:
            self.scaler.call("POST", "/reset")   # no unit container of an earlier run survives
        for p in self.procs:
            p.packs.write_text("")
        self.write_bindings()
        for p in self.procs:
            self.start_proc(p)
            p.state = "running"

    def live(self):
        """The processes that run (not being removed, not retired): they reload, get lake writers, are probed."""
        return [p for p in self.procs if p.state in ("starting", "running")]

    def start_proc(self, p):
        p.run.mkdir(parents=True, exist_ok=True)
        a = self.a
        vendor = [x for v in ("cisco-asa", "panos", "fortigate") if a.vendor_packs and (Path(a.vendor_packs) / v / "pack.json").exists() for x in ("--pack", str(Path(a.vendor_packs) / v))]
        self.vendors_loaded = len(vendor) // 2
        cmd = [a.rt, "run", "--pack", a.golden, *vendor, "--packs-file", str(p.packs), "--bindings", str(self.dir / "bindings.json"), "--source-id", "live-ingress-01", "--listen", f"tcp:{a.in_tcp}", "--listen", f"http:{a.in_http}",
               "--idle-timeout", "3600s", "--evidence", str(p.ev), "--out", str(p.run / "out.jsonl"), "--quarantine", str(p.run / "q.jsonl"),
               "--spool", str(p.spool), "--spool-cap", a.spool_cap, "--forward-stall-after", "2s", "--forward-drain", "5s"]
        if len(self.procs) > 1 or self.scaler:
            cmd += ["--reuse-port"]   # N processes on the same addresses; the kernel keeps each connection on one (and a process can be added)
        # the evidence archive: the local evidence directory is a short buffer; the committer (started beside this console)
        # ships, the runtime deletes a shipped segment when every condition holds
        cmd += (["--evidence-archive", a.archive, "--commit-dir", p.commit, "--evidence-grace", a.evidence_grace, "--evidence-buffer-cap", a.evidence_buffer_cap]
                if a.archive else ["--dev-no-evidence-archive"])
        for d in self.destinations:   # N destinations, any kind: the list decides, not the code
            cmd += ["--forward", dest_for(d, p)["url"]]
        if self.scaler:
            # a UNIT of containers: the runtime (root + CAP_LINUX_IMMUTABLE only, host network), its committer (nonroot, no
            # network, no capability — the P5 boundary, now one container each) and its lake writer
            if p.commit:
                Path(p.commit).mkdir(parents=True, exist_ok=True)
                os.chown(p.commit, 65532, 65532)   # the committer runs as the distroless nonroot user
            self.scaler.start(p.i, "runtime", cmd[1:])
            if a.archive:
                self.scaler.start(p.i, "committer", ["commit", "--evidence", str(p.ev), "--commit", p.commit, "--key", "/keys/ulpf-committer-dev.json",
                                                     "--every", os.environ.get("ULPF_COMMIT_EVERY", "5s"), "--archive", a.archive])
            if self.lake_on:
                self.start_lake(p)
            return
        p.runtime = subprocess.Popen(cmd, stdout=open(p.run / "egress-stdout.ndjson", "wb"), stderr=open(p.run / "runtime.err", "wb"), cwd=str(ROOT))

    def start_lake(self, p):
        self.scaler.start(p.i, "lake", ["--lake", self.a.lake, "--listen", f"127.0.0.1:{p.lake_port}", "--writer-id", str(p.i), "--rotate-bytes", "8MiB",
                                         "--rotate-seconds", os.environ.get("ULPF_LAKE_ROTATE_SECONDS", "10")])

    def err_text(self):
        return "".join(p.err_text() for p in self.procs)

    def write_bindings(self):
        """The operator's source binding, for the RUNTIME (2026-09-30, the user's decision): each inventory host -> the
        LOADED packs that belong to its source (the packs this console onboarded for it, and the vendor packs of the vendor
        the inventory declares). A line from a bound host routes only among these; a host with none stays unbound
        (structure-only routing — a new source is onboarded exactly as before). Trusts the sender's address."""
        loaded = set(self.pack_vendor) | {v["pack_id"] for v in self.active.values()}
        out = {}
        for host, inv in self.inventory.items():
            if isinstance(inv, dict) and not host.startswith("_"):
                ids = sorted(pid for pid in loaded if self.belongs(pid, inv))
                if ids:
                    out[host] = ids
        tmp = self.dir / "bindings.json.tmp"
        tmp.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
        os.replace(tmp, self.dir / "bindings.json")
        self.runtime_bindings = out

    def reload(self):
        """Every process reloads the same packs (SIGHUP); each must confirm, or the refusal is reported."""
        with self.proc_lock:
            return self._reload()

    def _reload(self):
        procs = self.live()
        before = {p.i: p.err_text().count("\nreloaded:") + p.err_text().startswith("reloaded:") for p in procs}
        refused = {p.i: p.err_text().count("reload REFUSED") for p in procs}
        dirs = [v["pack"] for v in self.active.values()]
        for p in self.procs:   # a retired process's packs file too: it is what it would load if it ran again
            tmp = p.packs.with_suffix(".tmp"); tmp.write_text("".join(d + "\n" for d in dirs)); os.replace(tmp, p.packs)
        self.write_bindings()   # the runtime re-reads it on the same SIGHUP, after the packs
        for p in procs:
            p.hup()
        waiting = {p.i for p in procs}
        for _ in range(150):
            for p in procs:
                if p.i not in waiting:
                    continue
                t = p.err_text()
                if t.count("reload REFUSED") > refused[p.i]:
                    raise RuntimeError(f"process {p.i} refused the pack: " + t.rsplit("reload REFUSED", 1)[1][:300])
                if t.count("\nreloaded:") + t.startswith("reloaded:") > before[p.i]:
                    waiting.discard(p.i)
            if not waiting:
                self.reloads += 1
                return
            time.sleep(0.1)
        raise RuntimeError(f"process(es) {sorted(waiting)} did not confirm the reload")

    def proc_of(self, rec):
        return self.procs[(rec.get("_proc") or 1) - 1]

    # ------------------------------------------------------------------ adding and removing a runtime process
    def scaling_view(self, apps):
        v = {"available": bool(self.scaler), "busy": self.scale_busy, "history": self.scale_history[-6:], "live": len(self.live())}
        if not self.scaler:
            v["why"] = "fixed at start here (start-demo.sh): adding and removing processes is the container deployment's (deploy/ulpf.sh up)"
            return v
        try:
            info = self.scaler.info(5)
        except Exception as ex:   # noqa: BLE001
            v.update(available=False, why=f"the scaler does not answer: {ex}")
            return v
        v.update(limit=int(info.get("ncpu") or 1), mem_available=info.get("memavailable"), engine=f"Docker {info.get('engine')} on {info.get('os')}")
        gw = sorted(h for h in apps if DOCKER_GATEWAY.match(h))
        if gw:
            v["address_warning"] = (f"senders arrive from {', '.join(gw)}, a Docker gateway: the sender's real address is being rewritten (a published port, or "
                                    "Docker Desktop), so the inventory and the source binding cannot tell devices apart. Run on Linux with Docker Engine.")
        return v

    def scale(self, action):
        if not self.scaler:
            raise ValueError("the processes are fixed at start here (start-demo.sh); adding and removing them needs the container deployment (deploy/ulpf.sh up)")
        if action not in ("add", "remove"):
            raise ValueError("add | remove")
        with LOCK:
            if self.scale_busy:
                raise ValueError(f"one change at a time: {self.scale_busy}")
            live = self.live()
            if action == "add":
                info = self.scaler.info(0)
                cap = int(info.get("ncpu") or 1)
                if len(live) >= cap:
                    raise ValueError(f"{len(live)} processes already: the limit is one per CPU, and Docker reports {cap}")
                if (info.get("memavailable") or MIN_FREE_BYTES) < MIN_FREE_BYTES:
                    raise ValueError(f"only {info['memavailable'] >> 20} MiB of memory available: adding a process needs {MIN_FREE_BYTES >> 20} MiB")
            elif len(live) <= 1:
                raise ValueError("one process is the minimum: removing the last one would stop ingestion")
            self.scale_busy = f"{action}: starting"
        threading.Thread(target=self._scale, args=(action,), daemon=True).start()

    def _scale(self, action):
        t0 = time.time()
        rec = {"at": time.strftime("%H:%M:%S"), "action": action}
        try:
            rec.update(self.add_proc() if action == "add" else self.remove_proc())
            rec["ok"] = True
        except Exception as ex:   # noqa: BLE001 — shown on the page
            rec.update(ok=False, outcome=str(ex)[:400])
        rec["seconds"] = round(time.time() - t0, 1)
        print(f"scale {action}: {rec}", flush=True)
        with LOCK:
            self.scale_history.append(rec)
            self.scale_busy = None

    def add_proc(self):
        """One more runtime process: a new unit (runtime, committer, lake writer) with its OWN evidence store, loaded with every
        pack active now, on the same ingress ports. The kernel spreads NEW connections over the processes; a connection
        already open stays where it is."""
        with self.proc_lock:
            with self.tick_lock:
                i = len(self.procs) + 1
                p = Proc(i, self.dir, self.a, self.scaler)
                used = {x.label for x in self.live()}
                p.label = next(n for n in range(1, len(self.procs) + 2) if n not in used)
                p.packs.write_text("".join(v["pack"] + "\n" for v in self.active.values()))
                self.procs.append(p)
            self.scale_busy = f"add: starting process {p.label}"
            self.start_proc(p)
            for _ in range(120):
                if "listening for" in p.err_text():
                    break
                if self.scaler.state_of(i, "runtime") == "exited":
                    p.state = "retired"
                    raise RuntimeError(f"process {p.label}'s runtime exited: {p.err_text()[-300:]}")
                time.sleep(0.5)
            else:
                raise RuntimeError(f"process {p.label}'s runtime did not start listening in 60 s")
            if self.lake_on:   # running = all of it answers: its lake writer too (a remove right after an add found it not up yet)
                for _ in range(60):
                    try:
                        urllib.request.urlopen(f"http://127.0.0.1:{p.lake_port}/status", timeout=1).read()
                        break
                    except Exception:   # noqa: BLE001
                        time.sleep(0.5)
            p.state = "running"
        return {"process": i, "label": p.label, "outcome": f"process {p.label} running: {p.ident()}, its own evidence store {p.store_id() or '(created on its first event)'}, "
                                         f"{len(self.active) + 1 + self.vendors_loaded} packs loaded"}

    def proc_ahead(self, p):
        """What process p parsed that a destination does not have yet (the most behind destination)."""
        with LOCK:
            usable = sum(1 for i in self.order if self.events[i].get("ok") is True and (self.events[i]["rec"].get("_proc") or 1) == p.i)
        curs = {}
        for f in p.spool.glob("cursor-*.json"):
            try:
                c = json.loads(f.read_text()); curs[c["sink"]] = c.get("delivered_events", 0)
            except (OSError, ValueError, KeyError):
                pass
        return max([0] + [usable - curs.get(sink_name(dest_for(d, p)["url"]), 0) for d in self.destinations])

    def proc_pending(self, p):
        """Process p's sealed local segments the committer has not shipped to the archive yet."""
        sid = p.store_id()
        if not (sid and self.a.archive):
            return 0
        shipped = {Path(x).stem for x in glob.glob(str(Path(self.a.archive) / sid / "receipts" / "seg_*.json"))}
        return sum(1 for x in glob.glob(str(p.ev / "seg_*.seal.json")) if Path(x).name[:-len(".seal.json")] not in shipped)

    def remove_proc(self):
        """One process less, without losing what it holds: (1) wait until every destination has what it parsed, (2) stop its
        runtime — it drains its spool for a last moment and SEALS its open segment, (3) wait until its committer has shipped
        every sealed segment to the archive, (4) stop the committer and the lake writer. The process stays on the page as
        RETIRED: its evidence store is kept, Prove it still works on its events. Its open connections close; the senders
        reconnect, and the kernel puts them on another process."""
        p = max(self.live(), key=lambda x: x.label)   # the highest-numbered process on the page
        down = [d["name"] for d in self.destinations if not self.health.get(d["name"], (False,))[0]]
        if down:
            raise RuntimeError(f"{', '.join(down)} is down: process {p.label} would be removed with events still in its spool — reconnect it first")
        with self.proc_lock:
            p.state = "draining"   # no reload goes to it from now on
        self.scale_busy = f"remove: process {p.label} — waiting until every destination has what it parsed"
        end = time.time() + 45
        while time.time() < end and self.proc_ahead(p) > 0:
            time.sleep(1)
        self.scale_busy = f"remove: stopping process {p.label}'s runtime (it drains and seals its open segment)"
        r = self.scaler.stop(p.i, "runtime", 30)
        p.final_log = r.get("log_tail") or ""
        self.scale_busy = f"remove: process {p.label} — waiting until its committer has shipped every sealed segment"
        end = time.time() + 120
        while time.time() < end and self.proc_pending(p) > 0:
            time.sleep(2)
        # what is left behind, by the RUNTIME's own final accounting (its exit summary: events emitted, and per destination
        # delivered events and undelivered spool bytes) — the console's own count can lag the last cursor write
        summary = None
        for line in reversed(p.final_log.splitlines()):
            if line.startswith("{") and '"egress"' in line:
                try:
                    summary = json.loads(line)
                    break
                except ValueError:
                    pass
        pending = self.proc_pending(p)
        if summary is not None:
            ahead = max(0, summary.get("emitted", 0) - min((e.get("delivered_events", 0) for e in summary["egress"]), default=summary.get("emitted", 0)))
            ahead = ahead if ahead or not sum(e.get("undelivered_bytes", 0) for e in summary["egress"]) else 1
        else:
            ahead = self.proc_ahead(p)
        self.scaler.stop(p.i, "committer", 20)
        if self.scaler.state_of(p.i, "lake") != "absent":
            self.scaler.stop(p.i, "lake", 30)
        p.state = "retired"
        p.retired_at = time.strftime("%H:%M:%S")
        return {"process": p.i, "label": p.label, "accounting": "the runtime's exit summary" if summary is not None else "the console's count", "emitted": (summary or {}).get("emitted"),
                "outcome": f"process {p.label} retired (runtime exit {r.get('exit_code')}): {ahead} parsed event(s) not delivered"
                                           f"{' — kept in its spool' if ahead else ''}, {pending} segment(s) not shipped{' — kept locally' if pending else ''}; "
                                           "its evidence stays readable"}

    # ------------------------------------------------------------------ monitor
    def raw(self, rec):
        """The raw bytes of an evidence record: the local buffer, else the archived copy (one lookup path, trace.py)."""
        sys.path.insert(0, str(ROOT / "demo" / "apps"))
        import trace
        try:
            return trace.read_raw(str(self.proc_of(rec).ev), self.a.archive, rec)[0]
        except OSError:
            return None

    def archived_index(self, path):
        """The archived copy of a local index file that is gone (None when there is no archive or no copy)."""
        if not self.a.archive:
            return None
        sys.path.insert(0, str(ROOT / "demo" / "apps"))
        import trace
        seg = os.path.basename(path)[:-len(".idx.jsonl")]
        ev = os.path.dirname(path)
        p, where = trace.seg_file(ev, self.a.archive, seg, ".idx.jsonl")
        return p if where == "archive" else None

    def archive_status(self):
        """What the System page shows about the evidence archive: ULPF holds only a short local buffer."""
        a = self.a
        if not a.archive:
            return {"configured": False}
        def size(ps):
            n = 0
            for p in ps:
                try:
                    n += os.path.getsize(p)
                except OSError:
                    pass
            return n
        per = []
        for pr in self.procs:
            sid = pr.store_id()
            local = sorted(x[:-4] for x in glob.glob(str(pr.ev / "seg_*.raw")))
            base = Path(a.archive) / sid if sid else None
            shipped = {Path(x).stem for x in glob.glob(str(base / "receipts" / "seg_*.json"))} if base else set()
            per.append({"process": pr.i, "store_id": sid, "local_segments": len(local), "local_bytes": size([x + s for x in local for s in (".raw", ".idx.jsonl", ".seal.json")]),
                        "shipped_segments": len(shipped), "pending_segments": len([x for x in local if Path(x).name not in shipped]),
                        "deleted_segments": len(glob.glob(str(pr.ev / "catalog" / "seg_*.ids"))),
                        "archived_bytes": size([x for x in glob.glob(str(base / "segments" / "seg_*")) if not x.endswith(".part")]) if base else 0,
                        "checkpoints": len(glob.glob(os.path.join(pr.commit, "checkpoints", "ckpt_*.json"))) if pr.commit else 0,
                        "state": pr.state,
                        "committer": (pr.state == "retired" or self.scaler.state_of(pr.i, "committer") == "running") if self.scaler else
                                     bool(subprocess.run(["pgrep", "-f", f"ulpf-committer commit --evidence {pr.ev} "], capture_output=True).stdout.strip())})
        tot = {k: sum(x[k] for x in per) for k in ("local_segments", "local_bytes", "shipped_segments", "pending_segments", "deleted_segments", "archived_bytes", "checkpoints")}
        cap = parse_bytes(a.evidence_buffer_cap)
        return {"configured": True, "archive": a.archive, "store_id": per[0]["store_id"], "grace": a.evidence_grace, "cap": cap * len(self.live()), "cap_per_process": cap, **tot,
                "buffer_event": getattr(self, "buffer_event", None), "committer": all(x["committer"] for x in per), "processes": per}

    def tick(self):
        for pr in self.procs:
            self.tick_proc(pr)

    def tick_proc(self, pr):
        # the local index files, and any partly read one deleted since (finished from the archive)
        mine = str(pr.ev) + os.sep
        for p in sorted(set(glob.glob(str(pr.ev / "seg_*.idx.jsonl"))) | {k for k, t in self.tails.items() if k.startswith(mine) and k.endswith(".idx.jsonl") and not t.done and not os.path.exists(k)}):
            for _, l in self.tails.setdefault(p, Tail(p, self.archived_index)).lines():
                try:
                    r = json.loads(l)
                except ValueError:
                    continue
                r["_proc"] = pr.i   # which process (evidence store) holds it
                e = {"rec": r, "ok": None}
                if r.get("framing", {}).get("method") == "gap_record":
                    e["record"] = True
                    try:
                        g = json.loads(self.raw(r) or b"{}")
                    except ValueError:
                        g = {}
                    e["kind"] = g.get("kind")
                    if (g.get("kind") or "").startswith("evidence_buffer_"):
                        self.buffer_event = {"kind": g["kind"], "at": g.get("detected_at"), "detail": g.get("detail")}
                    if g.get("kind") in ("egress_stalled", "egress_resumed"):
                        self.egress[g.get("peer")] = {"state": "stalled" if g["kind"] == "egress_stalled" else "delivering", "since": g.get("detected_at"), "detail": g.get("detail")}
                    if g.get("kind") == "pack_refused":
                        self.tlog_refusals.append({"process": pr.i, "pack": g.get("peer"), "at": g.get("detected_at"), "detail": g.get("detail"), "event_id": r["event_id"], "segment": r["segment_id"]})
                    if g.get("kind") in ("pack_activated", "pack_deactivated"):
                        self.pack_records.append({"kind": g["kind"], "pack": g.get("peer"), "at": g.get("detected_at"), "detail": g.get("detail")})
                with LOCK:
                    self.events[r["event_id"]] = e; self.order.append(r["event_id"])
        # an outcome line can be read before its evidence record: the index files were listed first, and a batch committed
        # and interpreted since then (group commit) writes its index lines and its outcomes between the two reads. Such a
        # line is kept and matched on a later tick, never dropped (dropping it left the event without an outcome: miscounted)
        out = str(pr.run / "out.jsonl")
        um = getattr(self, "unmatched", {})
        waiting = um.get(pr.i, []); um[pr.i] = []; self.unmatched = um
        fresh = [("out", off, l) for off, l in self.tails.setdefault(out, Tail(out)).lines()]
        q = str(pr.run / "q.jsonl")
        fresh += [("q", 0, l) for _, l in self.tails.setdefault(q, Tail(q)).lines()]
        for kind, off, l in waiting[-20000:] + fresh:
            try:
                r = json.loads(l)
                eid = r["_lineage"]["event_id"] if kind == "out" else r.get("event_id")
            except (ValueError, KeyError, TypeError):
                continue
            e = self.events.get(eid)
            if e is None:
                self.unmatched[pr.i].append((kind, off, l))
                continue
            if kind == "out":
                lin = r["_lineage"]
                e.update(ok=True, pack=lin.get("parser_id"), family=lin.get("family_id"), sig=lin.get("routing_signature", ""), out=(off, len(l)))
                b = self.bound.setdefault((e["rec"].get("ingest_channel"), self.host_of(e)), {})
                b[e["pack"]] = b.get(e["pack"], 0) + 1
            else:
                e.update(ok=False, stage=r.get("stage"), reason=r.get("reason"), sig=r.get("routing_signature", ""))

    def host_of(self, e):
        return (e["rec"].get("peer") or "").rsplit(":", 1)[0]

    def trigger_key(self, e):
        """What would have to be learned to read a quarantined event, PER SOURCE (peer host): `routing` and `routing_drift`
        both mean no family routes the line (routing_drift only adds the router's surface note about an anchor)."""
        st = e.get("stage")
        kind = "unknown_signature" if st in ("routing", "routing_drift") else "parse_drop" if st in ("parse", "tiling", "normalize") else None
        return None if kind is None else f"{kind} {e.get('sig', '')} @{self.host_of(e)}"

    WINDOW = 60   # events per SOURCE (2026-09-30: it was the last 60 of ALL sources — the relay's 8/s starved the FortiGate's 1/s)

    def triggers(self):
        """Quarantined events of each source's recent window, grouped by what would have to be learned to read them."""
        with LOCK:
            per, n = {}, 0
            for i in reversed(self.order):
                e = self.events[i]
                n += 1
                if n > 50000:
                    break
                if e.get("record") or e.get("ok") is None:
                    continue
                h = self.host_of(e)
                w = per.setdefault(h, [])
                if len(w) < self.WINDOW:
                    w.append(e)
        groups = {}
        for h, recent in per.items():
            for e in recent:
                if e.get("ok") is not False or not self.learnable(e):
                    continue   # the vendor relay is not learnable: its unknown lines stay quarantined
                key = self.trigger_key(e)
                if key is None or e["rec"]["event_id"] <= self.ignore.get(key, "") or key in self.held:
                    continue
                groups.setdefault(key, []).append(e)
        for key, evs in groups.items():
            sig0 = (evs[-1].get("sig") or "").split("|")[:2]
            # one learning job at a time per SOURCE and FORMAT (2026-10-02): a CSV drift's lines differ in column count, so their
            # signatures differ, and a second heal of the same format queued behind the first on the one model
            same_format = any(j["state"] not in ("done", "failed") and j.get("host") == self.host_of(evs[-1]) and j.get("l1") == sig0[0]
                              and j.get("l2") == (sig0[1] if len(sig0) > 1 else "?") for j in self.jobs)
            if len(evs) >= 10 and not same_format and not any(j["key"] == key and (j["state"] not in ("done", "failed") or (j["state"] == "failed" and time.time() - j["started"] < 60)) for j in self.jobs):
                kind = key.split(" ", 1)[0]
                sig = evs[-1].get("sig", "")
                parts = sig.split("|")
                job = {"id": f"job-{len(self.jobs) + 1}", "key": key, "trigger": kind, "signature": sig, "l1": parts[0], "l2": parts[1] if len(parts) > 1 else "?", "host": self.host_of(evs[-1]),
                       "router_note": next((x.get("reason") for x in reversed(evs) if x.get("stage") == "routing_drift"), None),
                       "router_reason": evs[-1].get("reason"),
                       "state": "starting", "steps": [], "fields": [], "answers": {}, "started": time.time(), "go": threading.Event(), "promote": threading.Event()}
                self.jobs.append(job)
                threading.Thread(target=self.run_job, args=(job,), daemon=True).start()

    def relay(self):
        """The four-vendor relay (unified visibility): the recorded mixed capture — ASA, PAN-OS, FortiGate and Squid behind a syslog
        relay, as scripts/p6-build-packs.sh builds it from the corpus — replayed in a loop from 127.0.0.2, so it is a second
        application in the list, next to the generator, with the packs that were onboarded for it. Declared in inventory.json as
        not learnable: its unknown lines are quarantined and counted, never onboarded or healed by this console."""
        import socket
        lines = [l for l in Path(self.a.vendor_capture).read_bytes().splitlines() if l.strip()]
        host, port = self.a.in_tcp.rsplit(":", 1)
        host = "127.0.0.1" if host == "0.0.0.0" else host   # bound on every local address (real devices): the relay stays on loopback
        sock, i = None, 0
        while True:
            if not self.policy["vendor_relay"]:
                if sock:
                    sock.close(); sock = None
                time.sleep(0.5); continue
            try:
                if sock is None:
                    sock = socket.socket(); sock.bind(("127.0.0.2", 0)); sock.connect((host, int(port)))
                l = lines[i % len(lines)]; i += 1
                sock.sendall(str(len(l)).encode() + b" " + l)
                self.relay_sent += 1
            except OSError:
                if sock:
                    sock.close()
                sock = None; time.sleep(1)
            time.sleep(1.0 / self.a.relay_rate)

    def belongs(self, pack_id, inv):
        """A pack reads this inventory source: one this console onboarded for it (named after its source_id), or a vendor
        pack of the vendor the operator declared for it."""
        if not pack_id:
            return False
        if pack_id.startswith(inv.get("source_id") or "\0"):
            return True
        v = self.pack_vendor.get(pack_id)
        return bool(v) and v == (inv.get("vendor") or "").lower()

    def bound_to(self, e):
        """The inventory name of the source this event's (channel, peer) is bound to, or None."""
        inv = self.inventory.get(self.host_of(e), {})
        packs = self.bound.get((e["rec"].get("ingest_channel"), self.host_of(e)), {})
        return inv.get("name") if inv and any(self.belongs(p, inv) for p in packs) else None

    def learnable(self, e):
        return self.inventory.get(self.host_of(e), {}).get("learn", True)

    def probe(self):
        """UP / DOWN per destination, from its own health URL (one probe per second, not per page refresh)."""
        import urllib.request
        for d in self.destinations:
            ups, why = [], "HTTP 200"
            for pr in (self.live() if "{lake_port}" in d.get("health", "") else self.procs[:1]):
                try:
                    with urllib.request.urlopen(dest_for(d, pr)["health"], timeout=1.5) as r:
                        ups.append(r.status < 500); why = f"HTTP {r.status}"
                except Exception as ex:
                    ups.append(False); why = type(ex).__name__ + (f" (process {pr.i})" if len(self.live()) > 1 else "")
            self.health[d["name"]] = (all(ups), why, time.time())
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

    # ------------------------------------------------------------------ the real devices (final demo)
    def devices_watch(self):
        """Every 20 s: the lab's status for the page, and the WATCHDOG — a FortiGate whose syslog is ON but which has sent
        nothing for 60 s is reconnected automatically (re-committing its syslog setting restarts FortiOS's backed-off
        reliable-syslog connection); at most once every 2 minutes, and said so on the page."""
        last_fix = 0.0
        while True:
            try:
                st = self.devices.refresh()
                if (st.get("fgt_syslog_on") and not self.devices.busy and time.time() - last_fix > 120 and time.time() - self.started > 60
                        and not self.sending(self.devices.FGT, 60)):
                    last_fix = time.time()
                    self.devices.act("fgt-connect", self.devices.format)
                    with self.devices.lock:
                        self.devices.history.append({"at": time.strftime("%H:%M:%S"), "action": "watchdog: FortiGate silent for 60 s with syslog ON — reconnected automatically", "rc": 0, "output": "", "seconds": None})
            except Exception as ex:   # noqa: BLE001 — the lab being unreachable is shown on the page, not fatal
                print("devices:", ex, file=sys.stderr, flush=True)
            time.sleep(20)

    def sending(self, host, within_s=30):
        """The device's lines are arriving (a real device sends at its own pace: the FortiGate ~1/s, Suricata in bursts)."""
        with LOCK:
            for i in reversed(self.order[-3000:]):
                e = self.events[i]
                if not e.get("record") and self.host_of(e) == host:
                    return time.time() * 1000 - (e["rec"].get("ingest_time") or 0) < within_s * 1000
        return False

    def device_action(self, action, arg=None):
        """A device-side action from the System page — run in the Containerlab distro (demo/devices/lab.sh), never a terminal."""
        if not self.devices:
            raise ValueError("not in devices mode (bash demo/start-demo.sh devices)")
        allowed = {"fgt-connect", "fgt-disconnect", "fgt-format", "fgt-logins", "ids-connect", "ids-disconnect", "attack"}
        if action not in allowed or (action == "fgt-format" and arg not in ("default", "json", "csv", "cef")):
            raise ValueError("unknown device action")
        if self.devices.busy:
            raise ValueError(f"a device action is running: {self.devices.busy}")

        def run():
            try:
                if action in ("fgt-connect", "ids-connect"):
                    host = self.devices.FGT if action == "fgt-connect" else self.devices.IDS
                    r = self.devices.ensure_connected(host, lambda h: self.sending(h, 20))
                    with self.devices.lock:
                        self.devices.history.append({"at": time.strftime("%H:%M:%S"), "action": action + " (checked)", "rc": 0 if r["connected"] else 1,
                                                     "output": ("sending to ULPF" if r["connected"] else "NOT sending after two attempts") + f" — attempts: {r['attempts']}", "seconds": None})
                else:
                    self.devices.act(action, *([str(arg)] if arg is not None else []))
            except Exception as ex:   # noqa: BLE001 — shown on the page with the action
                with self.devices.lock:
                    self.devices.history.append({"at": time.strftime("%H:%M:%S"), "action": action, "rc": 1, "output": str(ex)[-300:], "seconds": None})
        threading.Thread(target=run, daemon=True).start()

    def lake_control(self, action):
        """Devices mode: the lake's writers are started from the page ("Connect the lake") and stopped the same way — one per
        runtime process, exactly as start-demo.sh starts them in the generator demo."""
        if self.scaler:
            if action not in ("connect", "disconnect"):
                raise ValueError("connect | disconnect")
            self.lake_on = action == "connect"
            for pr in self.live():
                if self.lake_on and self.scaler.state_of(pr.i, "lake") != "running":
                    self.start_lake(pr)
                elif not self.lake_on:
                    self.scaler.stop(pr.i, "lake", 20)   # the writer flushes what it staged before it exits
            return
        if action == "connect":
            for pr in self.procs:
                if pr.i in self.lake_writers and self.lake_writers[pr.i].poll() is None:
                    continue
                self.lake_writers[pr.i] = subprocess.Popen(
                    [self.a.python, str(ROOT / "adapters" / "lake" / "lakewriter.py"), "--lake", self.a.lake, "--listen", f"127.0.0.1:{pr.lake_port}", "--writer-id", str(pr.i),
                     "--rotate-bytes", "8MiB", "--rotate-seconds", os.environ.get("ULPF_LAKE_ROTATE_SECONDS", "10")],
                    stdout=open(self.dir / f"lakewriter-{pr.i}.log", "ab"), stderr=subprocess.STDOUT, cwd=str(ROOT), start_new_session=True)
        elif action == "disconnect":
            for w in self.lake_writers.values():
                if w.poll() is None:
                    w.terminate()
            for w in self.lake_writers.values():
                try:
                    w.wait(20)   # the writer flushes what it staged before it exits
                except subprocess.TimeoutExpired:
                    w.kill()
        else:
            raise ValueError("connect | disconnect")

    def siem_control(self, action):
        if action not in ("outage", "recover") or self.siem_action:
            raise ValueError("outage | recover, one at a time")
        def run():
            self.siem_action = action
            try:
                if self.scaler:   # the SIEM container is the scaler's to stop and start (the outage step)
                    print(f"siem {action}: {self.scaler.call('POST', '/siem', {'action': action})}", flush=True)
                    if action == "recover":
                        siem = next((d for d in self.destinations if d.get("kind") == "siem"), {})
                        for _ in range(180):
                            try:
                                urllib.request.urlopen(siem.get("health", ""), timeout=2).read()
                                break
                            except Exception:   # noqa: BLE001
                                time.sleep(1)
                    return
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
            ws = [json.loads(urllib.request.urlopen(f"http://127.0.0.1:{pr.lake_port}/status", timeout=1).read()) for pr in self.live()]
            out["writer"] = ws[0] if len(ws) == 1 else {**ws[0], "writers": len(ws), **{k: sum(w.get(k) or 0 for w in ws) for k in ("rows_written", "files_written", "staged_rows", "received_rows", "duplicate_rows_ignored")}}
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
            # the latest rows of EVERY class (2026-10-02: it was network activity only), each with the format its raw log
            # arrived in — read off the console's record of the event (its routing signature), not guessed from the row
            cols = {c[0] for c in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{fs[-1]}')").fetchall()}
            net = "src_endpoint" in cols and "dst_endpoint" in cols
            q = (f"SELECT event_id, time, family_id, {'src_endpoint.ip, dst_endpoint.ip' if net else 'NULL, NULL'}, {'action_id' if 'action_id' in cols else 'NULL'}, filename "
                 f"FROM read_parquet({fs!r}, filename=true, union_by_name=true) ORDER BY time DESC LIMIT 25")
            for eid, t, fam, sip, dip, act, fn in con.execute(q).fetchall():
                with LOCK:
                    e = self.events.get(eid)
                out["latest"].append({"event_id": eid, "time": t, "family_id": fam, "src": sip, "dst": dip, "action_id": act, "class": src.name.replace("ulpf_", "").replace("_", " "),
                                      "format": self.fmt_of(e.get("sig")) if e else None,
                                      "source": self.inventory.get(self.host_of(e), {}).get("name") if e else None, "file": str(Path(fn).relative_to(lake))})
            if event_id:
                hit = con.execute(f"SELECT event_id, raw_hash, segment_id, \"offset\", length, source_id, parser_id, family_id, filename FROM read_parquet({fs!r}, filename=true) WHERE event_id = ?", [event_id]).fetchone()
                if hit:
                    out["lookup"] = dict(zip(("event_id", "raw_hash", "segment_id", "offset", "length", "source_id", "parser_id", "family_id", "file"), hit))
                    out["lookup"]["file"] = str(Path(out["lookup"]["file"]).relative_to(lake))
        out["latest"] = sorted(out["latest"], key=lambda r: r["time"] or 0, reverse=True)[:25]
        out["checked_at"] = time.strftime("%H:%M:%S")
        out["rotate_seconds"] = int(os.environ.get("ULPF_LAKE_ROTATE_SECONDS", "10"))
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
        with LOCK:
            e = self.events.get(event_id)
        pr = self.proc_of(e["rec"]) if e else next((x for x in self.procs if trace.find_record(str(x.ev), self.a.archive, event_id)[0]), self.procs[0])
        t = trace.trace(event_id, str(pr.ev), self.a.lake, siem.get("findings", "http://127.0.0.1:9200"), str(work), self.a.archive, pr.commit if self.a.archive else None)
        t["process"] = pr.i
        self.traces[event_id] = t
        return t

    def tlog_view(self):
        """The parser history: every pack ULPF may load — when it was logged and how it was produced."""
        r = subprocess.run([str(ROOT / "runtime" / "bin" / "ulpf-tlog"), "list", "--json"], capture_output=True, text=True, env={**os.environ, "ULPF_ROOT": str(ROOT)})
        try:
            d = json.loads(r.stdout)
        except ValueError:
            d = {"entries": [], "checkpoint": {}, "error": (r.stderr or r.stdout)[-300:]}
        active = {v["pack_id"] + " " + v["pack_version"] for v in self.active.values()}
        for e in d.get("entries") or []:
            e["active"] = (e.get("PackID", "") + " " + e.get("PackVersion", "")) in active
        d["entries"] = list(reversed(d.get("entries") or []))[:60]
        d["refusals"] = self.tlog_refusals[-10:]
        d["witness"] = os.environ.get("ULPF_TLOG_WITNESS")
        return d

    def push_unlogged(self, proc_i):
        """The demo moment: a pack that is validly SIGNED but NOT in the parser transparency log is pushed to ONE process
        (its packs file + SIGHUP). The runtime refuses it — the running packs stay — and the refusal is a `pack_refused`
        record in that process's evidence log."""
        import shutil
        pr = next((x for x in self.live() if x.i == int(proc_i)), None) or self.live()[0]
        src = Path(next(iter(self.active.values()))["pack"]) if self.active else Path(self.a.golden)
        n = len(list((self.dir / "rogue").glob("pack-*"))) + 1 if (self.dir / "rogue").exists() else 1
        dst = self.dir / "rogue" / f"pack-{n}"
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("pack.json.tlog-proof"))
        doc = json.loads((dst / "pack.json").read_text())
        doc["pack_version"] = f"{doc['pack_version'].split('.')[0]}.{900 + n}"   # a valid version never logged: signed, contract-valid, NOT in the log
        (dst / "pack.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        r = subprocess.run([self.a.python, "-c", f"import sys; sys.path.insert(0, 'learning'); from pathlib import Path; from ulpf_learn.signing import sign_pack; sign_pack(Path({str(dst)!r}), log=False)"],
                           cwd=str(ROOT), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("could not sign the unlogged pack: " + r.stderr[-300:])
        refused = pr.err_text().count("reload REFUSED")
        before = len(self.tlog_refusals)
        dirs = [v["pack"] for v in self.active.values()] + [str(dst)]
        tmp = pr.packs.with_suffix(".tmp"); tmp.write_text("".join(d + "\n" for d in dirs)); os.replace(tmp, pr.packs)
        pr.hup()
        for _ in range(100):
            if pr.err_text().count("reload REFUSED") > refused:
                break
            time.sleep(0.1)
        dirs = [v["pack"] for v in self.active.values()]
        tmp = pr.packs.with_suffix(".tmp"); tmp.write_text("".join(d + "\n" for d in dirs)); os.replace(tmp, pr.packs)   # the push is over; the file lists the logged packs again
        t = pr.err_text()
        ok = t.count("reload REFUSED") > refused
        return {"process": pr.i, "pack": f"{doc['pack_id']} v{doc['pack_version']}", "refused": ok,
                "reason": t.rsplit("reload REFUSED", 1)[1].strip()[:400] if ok else "the runtime did not answer", "recorded_before": before}

    def certificate(self, event_id):
        sys.path.insert(0, str(ROOT / "demo" / "apps"))
        import certificate
        import trace
        t = self.traces.get(event_id) or self.prove(event_id)
        pr = self.procs[(t.get("process") or 1) - 1]
        rec, where = trace.find_record(str(pr.ev), self.a.archive, event_id)
        rec = rec or {}
        host = (rec.get("peer") or "").rsplit(":", 1)[0]
        device = self.inventory.get(host, {})
        try:
            doc = json.loads((self.dir / "trace" / f"expected-{event_id}.json").read_text())
        except (OSError, ValueError):
            doc = {}
        raw_where = next((x.get("evidence_source") for x in t.get("steps", []) if x.get("evidence_source")), where)
        note = (f"shipped byte-exact to the evidence archive ({self.a.archive}); the local copy was deleted after shipping, the bytes above were read from the archive and re-hashed"
                if raw_where == "archive" else f"is held in the local evidence buffer and shipped byte-exact to the evidence archive ({self.a.archive}) after it is committed") if self.a.archive else "is held in the local evidence directory (no archive configured)"
        return certificate.render(event_id, t, rec, device, doc, note, pr.i)

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
        """One active pack per (source, format, family): two devices sending JSON, or one device's traffic and event
        families in JSON, are different families and never replace each other."""
        base = f"{job['l1']}|{job['l2']}" if job["l2"] in ("json", "xml") else f"{job['l1']}|{job['l2']}|{arity}"
        return f"{job.get('source_id', '')}|{base}" + (f"|{job['family']}" if job.get("family") else "")

    def family_keys_for(self, inv, packs):
        """The keys whose values name a family of this source: declared by its bound packs' anchors (FortiGate: type), or
        by the operator in the inventory (`family_keys`)."""
        return sorted(set(inv.get("family_keys") or []) | {k for p in packs for k in self.pack_family_keys.get(p, [])})

    def seed_answers(self, job, inv, packs, work):
        """Cross-format carry-over by name (the user's decision, 2026-09-30): the answers the source's BOUND vendor packs
        already give for its self-describing families are recorded for this source under the name key. The value class of
        each key is observed on lines that pack parsed from THIS peer, taken out of the evidence store (raw_hash checked)."""
        n = 0
        for pid in packs:
            if pid not in self.pack_dir:
                continue   # a pack this console onboarded recorded its own answers when it was promoted
            with LOCK:
                parsed = [e for e in (self.events[i] for i in self.order) if e.get("ok") and e.get("pack") == pid and self.host_of(e) == job["host"]][-48:]
            lines = []
            for e in parsed:
                raw = self.raw(e["rec"])
                if raw is not None and "sha256:" + hashlib.sha256(raw).hexdigest() == e["rec"]["raw_hash"]:
                    lines.append(raw.rstrip(b"\r\n"))
            if not lines:
                continue
            f = work / f"seed-{pid}.log"
            f.write_bytes(b"".join(l + b"\n" for l in lines))
            out = self.learn("seed-propagation", "--store", str(self.dir / "propagation.json"), "--source-id", job["source_id"], "--samples", str(f), self.pack_dir[pid])
            k = int(out.split()[1]) if out.startswith("seeded ") else 0
            n += k
            self.step(job, f"earlier answers for {inv['name']}: {k} field answer(s) of its bound pack {pid} (vendor documentation), value classes observed on "
                           f"{len(lines)} of its lines that pack parsed — recorded under the cross-format name key (self-describing formats only)")
        return n

    def publish_fields(self, job, session):
        s = json.loads((session / "session.json").read_text())
        certs = {c["context"]["slot_index"]: c for c in s["certificates"].values() if c["status"] != "resolved"}
        prop = {h["slot_index"] for h in s.get("propagated", [])}
        by_name = {h["slot_index"] for h in s.get("propagated", []) if h.get("by") == "name"}
        fields = []
        for sl in s["plan"]["slots"]:
            p = sl["parts"][0]; c = certs.get(sl["index"])
            cats = [m["provenance"].get("category") for m in p["mappings"]]
            fields.append({"field": p["field"], "slot": sl["index"], "cls": p["cls"], "samples": sl["samples"][:3], "mapped": [m["attribute"] for m in p["mappings"]], "provenance": cats,
                           "propagated": sl["index"] in prop, "by_name": sl["index"] in by_name, "unmapped_name": p.get("unmapped_name"),
                           # a carried answer may be "carried unmapped under its name" — the evidence named it so; that is an answer too
                           "evidenced": (bool(cats) and all(x not in ("model_proposal", "fixture_proposal") for x in cats)) or (sl["index"] in prop and bool(p.get("unmapped_name"))),
                           "ambiguity": c and c["evidence"]["discriminator"].get("ambiguity_class"), "candidates": [r["attribute"] for r in c["ranked_candidates"]] if c else p["candidates"]})
        # every ambiguity certificate of the session, resolved or not: what was ambiguous, between which candidates, what
        # evidence the library asked for, and who resolved it — the page shows them beside the fields
        cert_list = []
        for cid, c in s["certificates"].items():
            sl = next((x for x in s["plan"]["slots"] if x["index"] == c["context"]["slot_index"]), None)
            cert_list.append({"id": cid, "field": sl["parts"][0]["field"] if sl else c["context"]["slot_index"], "status": c["status"],
                              "ambiguity": c["evidence"]["discriminator"].get("ambiguity_class"), "candidates": [r["attribute"] for r in c.get("ranked_candidates", [])][:4],
                              "request": ((c.get("request") or {}).get("selected") or {}).get("discriminator_id"),
                              "resolved_by": next((r.get("discriminator_id") for r in s.get("resolutions", []) if cid in (r.get("certificate_ids") or [])), None)})
        with LOCK:
            job["certificates"] = cert_list
            job["fields"], job["blockers"] = fields, s["verdict"]["blockers"]
            job["event_class_uid"], job["provider"] = s["proposal"]["event_class_uid"], s["proposal"]["provider"]
        return s

    def assert_field(self, job, session, field, attribute, note, how, lookup=None):
        """With `lookup` the operator also states the value map onto an enum attribute (status="success" -> status_id 1)."""
        self.learn("respond", "--session", str(session), "--discriminator", "operator_assertion", "--field", field, "--attribute", attribute,
                   "--input", f"operator {self.policy['operator']} asserts {field} is {attribute}: {note} [{how}]", *(["--lookup", json.dumps(lookup)] if lookup else []))
        self.step(job, f"operator {self.policy['operator']} asserts {field} → {attribute}" + (" with " + ", ".join(f"{k}={v}" for k, v in lookup.items()) if lookup else "") + f"  ({how})")

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
        job["source_id"], job["app"] = src, inv["name"]
        fmt = (ENVELOPES.get(job["l1"], job["l1"]) + " → " if job["l1"] not in ("raw", "") else "") + SURFACES.get(job["l2"], job["l2"])
        job["format"] = fmt
        with LOCK:
            mine = [e for e in (self.events[i] for i in self.order) if e.get("ok") is False and self.trigger_key(e) == job["key"] and e["rec"]["event_id"] > self.ignore.get(job["key"], "")]
            # the SOURCE BINDING: the (channel, peer) pairs whose lines this source's packs have parsed — the packs this
            # console onboarded for it, and the vendor packs of the vendor the operator's inventory declares for it
            known = {cp for cp, packs in self.bound.items() if any(self.belongs(p, inv) for p in packs)}
            by = sorted({p for cp, packs in self.bound.items() if cp in known for p in packs if self.belongs(p, inv)})
        seen = {(e["rec"].get("ingest_channel"), self.host_of(e)) for e in mine}
        bound = bool(seen) and seen <= known
        # heal: a changed format of a family this console onboarded for the source (autoheal-1.1); drift: the lines of a
        # BOUND source changed format — that source's drift, whatever another vendor's anchor noticed; onboard: a new source
        discovery = "family discovery input" in (job.get("router_reason") or "")   # an anchor value in its domain that no family owns: a new FAMILY
        job["kind"] = "heal" if same else ("discovery" if discovery else "drift") if bound else "onboard"
        job["binding"] = {"bound": bound, "by_packs": by, "drifted_from": sorted(map(list, seen)), "source_known_from": sorted(map(list, known)),
                          "router_note": job.get("router_note"), "limit": "binding is by ingest channel and peer host; the transports in use authenticate nobody"}
        if job["kind"] == "discovery":
            self.step(job, f"NEW EVENT FAMILY from {inv['name']} (bound: its lines on this channel and peer were parsed by {', '.join(by)}): {fmt} lines "
                           f"that no onboarded family owns — {job.get('router_reason')} — {len(mine)} quarantined, bytes kept", "sampling")
            alert = {"id": f"alert-{len(self.alerts) + 1}", "alert": "new_family_known_source", "policy_version": POLICY_VERSION, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "app": inv["name"], "host": job["host"], "source_id": src, "format": fmt, "trigger": {"kind": job["trigger"], "signature": job["signature"], "quarantined_events": len(mine)},
                     "source_binding": job["binding"], "outcome": "onboarding a new event family of a known source…", "job": job["id"]}
            with LOCK:
                self.alerts.append(alert); job["alert"] = alert
        if job["kind"] == "drift":
            note = (f" The router's note — {job['router_note']} — is a surface observation about another pack's anchor, not an attribution: this peer is bound to {inv['name']}."
                    if job.get("router_note") else "")
            self.step(job, f"DRIFT on {inv['name']} (bound: its lines on this channel and peer were parsed by {', '.join(by)}): the format changed to {fmt} — "
                           f"{len(mine)} quarantined, bytes kept.{note}", "sampling")
            alert = {"id": f"alert-{len(self.alerts) + 1}", "alert": "drift_new_format", "policy_version": POLICY_VERSION, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "app": inv["name"],
                     "host": job["host"], "source_id": src, "format": fmt, "trigger": {"kind": job["trigger"], "signature": job["signature"], "quarantined_events": len(mine)},
                     "source_binding": job["binding"], "outcome": "onboarding the new format of a known source…", "job": job["id"]}
            with LOCK:
                self.alerts.append(alert); job["alert"] = alert
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
            if job["kind"] == "onboard":
                self.step(job, f"NEW FORMAT from {inv['name']}: {fmt} — every line quarantined, bytes kept, nothing parsed, nothing guessed", "sampling")
            if job["kind"] == "drift":
                # a changed format of a KNOWN, BOUND source is a heal, governed by the heal policy — never held behind the
                # auto-onboard switch, which is about unknown sources and new event families (2026-09-30, the final demo:
                # with auto-onboard off for Suricata's on-stage "Onboard", the FortiGate's JSON drift waited for a click)
                job["decision"] = {"decision": "heal", "tier": 1, "by": f"heal policy {POLICY_VERSION}: drift of a bound source", "at": time.strftime("%H:%M:%S"), "quarantined_when_decided": len(mine)}
                self.step(job, f"healing started BY POLICY ({POLICY_VERSION}: the format of a bound source changed; what is not evidenced will be asked)")
            elif self.policy["auto_onboard"]:
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
        keys = self.family_keys_for(inv, by)
        if job["kind"] != "onboard":
            self.seed_answers(job, inv, by, work)
        a = self.a
        prov = (["--provider", "model", "--model-id", a.model_id, "--server", a.server, "--backend", a.backend, "--mode", "whole"] if a.provider == "model"
                else ["--provider", "fixture", "--fixture", str(ROOT / "demo" / "live" / "flowtap-proposals.json")])
        self.step(job, ("the local model labels the fields" if a.provider == "model" else "FALLBACK: team-authored proposals stand in for the model") + " — proposals only, never evidence")
        session = work / "session"
        t0 = time.time()
        self.learn("onboard", "--samples", str(work / "samples.log"), "--source-id", src, "--operator", self.policy["operator"] if job["kind"] != "heal" else "auto-heal", "--session", str(session),
                   "--vendor", inv["vendor"], "--product", inv["product"], "--transport-hint", "syslog-tcp", "--propagation-store", str(self.dir / "propagation.json"),
                   *(["--family-keys", ",".join(keys)] if keys else []), *prov)
        s = self.publish_fields(job, session)
        job["family"] = s.get("family") or ""
        split = [e for e in s["timeline"] if e["step"] == "family_split"]
        if split:
            self.step(job, f"one family per onboarding: kept {split[0]['kept']} ({s['sample_count']} samples); "
                           + ", ".join(f"{k or 'no family key'}: {v}" for k, v in split[0]["left"].items()) + " stay quarantined for their own job")
        arity = s["structure"]["arity"]
        drafted = s.get("drafted")
        self.step(job, f"structure {'drafted from the lines own keys' if drafted else 'induced'}: {arity} fields; proposals in {time.time() - t0:.1f}s; {len(s['certificates'])} ambiguity certificate(s); "
                       f"{len(s.get('propagated', []))} field(s) carried over from earlier answers")
        version = "1.0"
        # a drifted or new family of a BOUND source whose answers carried over by name (self-describing format, the user's
        # decision of 2026-09-30) heals as a known family heals (autoheal-1.1): what rests on evidence is promoted now,
        # what nobody has answered is withheld (carried unmapped) and asked — the format's events flow meanwhile
        named = [f for f in job["fields"] if f.get("by_name")]
        job["auto_heal"] = job["kind"] in ("drift", "discovery") and bool(named) and not job["blockers"]
        if job["auto_heal"]:
            by = sorted({h["from_family"] for h in s.get("propagated", []) if h.get("by") == "name"})
            job["alert"]["alert"] = "drift_auto_heal"
            job["alert"]["carried_by_name_from"] = by
            self.step(job, f"{len(named)} of {len(job['fields'])} field(s) carried over BY NAME from earlier answers for {inv['name']} ({', '.join(by)}) — a self-describing "
                           f"format, same source, same family ({job['family'] or 'none declared'}), same value class: nothing guessed", "promoting")
        elif job["kind"] in ("onboard", "drift", "discovery"):
            sheet = PREPARED_SHEETS.get(src) if self.policy["prepared_answers"] else None
            if sheet:
                self.step(job, f"answers: {sheet['author']}'s PREPARED SHEET for {src} ({sheet['for']}; policy prepared_answers is on)", "answering")
                for f in list(job["fields"]):
                    if "by_name" in sheet:
                        ans = sheet["by_name"].get(f["field"])
                        if ans and not f["propagated"]:
                            self.assert_field(job, session, f["field"], ans[0], ans[1], "prepared sheet", lookup=ans[2])
                        continue
                    ans = sheet["v2"].get(f["slot"]) if arity == 10 and f["slot"] in sheet["v2"] else sheet["by_slot"][f["slot"]] if f["slot"] < len(sheet["by_slot"]) else None
                    if ans and not f["propagated"]:
                        self.assert_field(job, session, f["field"], ans[0], ans[1], "prepared sheet")
                self.publish_fields(job, session)
            else:
                if self.policy["prepared_answers"]:
                    self.step(job, f"no prepared sheet for {src}: a sheet is bound to the source it was written for "
                                   f"({', '.join(sorted(PREPARED_SHEETS))}) and is never applied to another device's fields")
                open_ = [f for f in job["fields"] if not f["propagated"]]
                if job["kind"] in ("drift", "discovery"):
                    job["alert"]["outcome"] = (f"asked the operator: the new format's {len(open_)} field(s) have no evidence yet"
                                               + (f" ({len(job['fields']) - len(open_)} carried over)" if len(open_) < len(job["fields"]) else "")
                                               + " — earlier answers carry over by name only for a self-describing format (JSON, key=value) of the same source and family with the same value class; "
                                               "anything else keeps the structure key (same source, same L1–L3)")
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
        if job["kind"] == "heal" or job.get("auto_heal"):
            withheld = [f for f in job["fields"] if not f["evidenced"]]
            alert = job["alert"]
            alert["auto_promoted"] = [{"field": f["field"], "attribute": f["mapped"][0], "provenance": f["provenance"][0]} for f in job["fields"] if f["evidenced"] and f["mapped"]]
            alert["withheld"] = [{"field": f["field"], "samples": f["samples"], "why": ("ambiguous between " + ", ".join(f["candidates"])) if f["ambiguity"] else "a proposal is not evidence" if f["mapped"] or f["candidates"] else "nobody has said what this field is"} for f in withheld]
            alert["pack"] = job["pack"]
            how = " (by name, from " + ", ".join(alert.get("carried_by_name_from", [])) + ")" if job.get("auto_heal") else ""
            alert["outcome"] = (f"healed automatically: every field resolved on sufficient evidence{how}, nobody asked" if not withheld else
                                f"healed automatically in part: {len(job['fields']) - len(withheld)} field(s) carried over on earlier evidence{how}, "
                                f"{len(withheld)} withheld (carried unmapped) — the operator is asked for those: " + ", ".join(f["field"] for f in withheld))
            self.step(job, "ALERT: " + alert["outcome"], "asking" if withheld else "done")
            if withheld:
                self.wait_answers(job, session, only=[f["field"] for f in withheld])
                self.promote_and_load(job, session, work, arity, "1.1", replace=job["family_key"])
                alert["pack"] = job["pack"]
                alert["answered"] = dict(job["answers"]); alert["outcome"] += f" → answered by {self.policy['operator']}, pack {job['pack']['pack_version']} loaded"
        if job["kind"] in ("drift", "discovery"):
            job["alert"]["pack"] = job.get("pack")
            if not job.get("auto_heal"):
                job["alert"]["outcome"] += f" → answered by {self.policy['operator']}, pack {job['pack']['pack_version']} loaded" if job.get("pack") else ""
        self.step(job, "done: events of this format are normalized from here on", "done")

    def wait_answers(self, job, session, only=None):
        """The page posts answers into job['answers'] and then sets job['promote']; each answer is applied through `respond`."""
        done = {}   # field -> (attribute, value map) applied; a change is applied again (a re-assertion replaces the mapping)
        while True:
            job["promote"].wait(0.3)
            for f, attr in list(job["answers"].items()):
                lk = job.get("lookups", {}).get(f)
                if done.get(f) != (attr, json.dumps(lk, sort_keys=True)) and (only is None or f in only):
                    via = job.get("answer_via", {}).get(f)
                    self.assert_field(job, session, f, attr, "the model's proposal, accepted on the System page" if via == "proposal" else "chosen on the System page",
                                      "accepted the model's proposal" if via == "proposal" else "asked on the page", lookup=lk)
                    done[f] = (attr, json.dumps(lk, sort_keys=True))
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
        self.step(job, "promoting: acceptance policy, signed pack" + (" (what rests on a proposal alone is withheld, carried unmapped)" if job["kind"] == "heal" or job.get("auto_heal") else ""), "promoting")
        auto = job["kind"] == "heal" or job.get("auto_heal")
        fam_tag = ("-" + re.sub(r"[^A-Za-z0-9]+", "-", job["family"].split("=", 1)[-1]).strip("-")) if job.get("family") else ""
        self.learn("promote", "--session", str(session), "--out", str(out), "--pack-id", f"{job['source_id']}-{fam}{fam_tag}", "--withhold-unevidenced", "--pack-version", version,
                   "--produced-by", "auto-healed" if auto else "onboarded")   # logged in the parser transparency log BEFORE it is activated
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
                a = apps.setdefault(h, {"host": h, "events": 0, "usable": 0, "quarantined": 0, "processes": set(), "peers": set()})
                a["events"] += 1; a["usable"] += e.get("ok") is True; a["quarantined"] += e.get("ok") is False
                a["processes"].add(e["rec"].get("_proc") or 1); a["peers"].add(e["rec"].get("peer"))
                a["channel"], a["peer"], a["last_ms"] = e["rec"].get("ingest_channel"), e["rec"].get("peer"), e["rec"].get("ingest_time") or 0
            for h, a in apps.items():
                inv = self.inventory.get(h, {})
                a["name"], a["source_id"] = inv.get("name", "unknown application"), inv.get("source_id")
                a["real_device"] = inv.get("real_device")   # declared by the operator (inventory.json): a physical/virtual appliance, not a generator
                a["connector"] = {"tcp": "Syslog over TCP", "http": "HTTP POST"}.get((a.get("channel") or "").split(":")[0], a.get("channel"))
                a["idle_s"] = round((now_ms - a["last_ms"]) / 1000, 1)
                a["connected"] = a["idle_s"] < (30 if a["real_device"] else 3)   # a real device sends at its own pace (Suricata: in bursts)
                a["bound_packs"] = (getattr(self, "runtime_bindings", {}) or {}).get(h, [])
                a["alert"] = any(j.get("host") == h and j["state"] not in ("done", "failed") for j in self.jobs)
                a["processes"], a["connections"] = sorted(a["processes"]), len(a.pop("peers"))
                a["process_labels"] = sorted({self.procs[i - 1].label for i in a["processes"] if i <= len(self.procs) and self.procs[i - 1].state != "retired"})
            recent = [e for e in (self.events[i] for i in self.order[-200:]) if not e.get("record") and e.get("ok") is not None and self.learnable(e)][-40:]   # the applications being onboarded
            curs = {}   # (process, sink) -> cursor
            for pr in self.procs:
                for f in pr.spool.glob("cursor-*.json"):
                    try:
                        c = json.loads(f.read_text()); curs[(pr.i, c["sink"])] = c
                    except (OSError, ValueError, KeyError):
                        pass
            usable = sum(a["usable"] for a in apps.values())
            egress = []
            for d in self.destinations:
                cs = [curs.get((pr.i, sink_name(dest_for(d, pr)["url"])), {}) for pr in self.procs]
                cur = {k: sum(c.get(k, 0) for c in cs) for k in ("delivered_events", "skipped_events", "rejected_events")}
                cur["last_event_id"] = max((c.get("last_event_id") or "" for c in cs), default=None)
                sink = sink_name(dest_for(d, self.procs[0])["url"])
                up, why, _ = self.health.get(d["name"], (False, "not probed yet", 0))
                st = self.egress.get(sink, {})
                egress.append({"name": d["name"], "kind": d.get("kind"), "url": d["url"], "ui": d.get("ui"), "up": up, "why": why, "delivery": st.get("state") or ("delivering" if cur.get("delivered_events") else "waiting"),
                               "delivered": cur.get("delivered_events", 0), "ahead_by": max(0, usable - cur.get("delivered_events", 0)), "skipped": cur.get("skipped_events", 0),
                               "rejected": cur.get("rejected_events", 0), "last_event_id": cur.get("last_event_id")})
            jobs = [{k: v for k, v in j.items() if k not in ("go", "promote")} for j in self.jobs]
            procs = []
            for pr in self.procs:
                procs.append({"process": pr.i, "label": pr.label, "pid": pr.ident(), "up": pr.alive(), "state": pr.state, "retired_at": getattr(pr, "retired_at", None), "store_id": pr.store_id(),
                              "evidence": str(pr.ev), "lake_port": pr.lake_port, "events": sum(1 for i in self.order if (self.events[i]["rec"].get("_proc") or 1) == pr.i and not self.events[i].get("record")),
                              "applications": sorted(h for h, a in apps.items() if pr.i in a["processes"])})
            return {"policy": self.policy, "processes": procs, "mode": self.mode,
                    "devices": self.devices.view() if self.devices else None,
                    "lake_writers": (sum(1 for pr in self.live() if self.scaler.state_of(pr.i, "lake") == "running") if self.scaler else
                                     sum(1 for w in self.lake_writers.values() if w.poll() is None)) if self.mode == "devices" else None,
                    "scaling": self.scaling_view(apps),
                    "runtime": {"up": all(x["up"] for x in procs if x["state"] in ("starting", "running")), "processes": sum(1 for x in procs if x["state"] in ("starting", "running")), "ingress": [{"label": "Syslog over TCP" + (" — also real devices, on the Containerlab bridge 172.20.20.1" if self.a.in_tcp.startswith("0.0.0.0:") else ""), "addr": self.a.in_tcp},
                                {"label": "HTTP POST", "addr": self.a.in_http}],
                                                       "packs": [{"pack_id": v["pack_id"], "pack_version": v["pack_version"], "family": v["family"]} for v in self.active.values()], "reloads": self.reloads,
                                                       "provider": self.a.provider, "pack_records": self.pack_records[-6:], "vendor_packs": getattr(self, "vendors_loaded", 0),
                                                       "relay_sent": self.relay_sent, "relay_available": bool(self.a.vendor_capture and Path(self.a.vendor_capture).exists())},
                    "archive": self.archive_status(),
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
                rows.append({"event_id": i, "at": time.strftime("%H:%M:%S", time.localtime((e["rec"].get("ingest_time") or 0) / 1000)), "ms": e["rec"].get("ingest_time"), "connector": (e["rec"].get("ingest_channel") or "").split(":")[0],
                             "bytes": e["rec"]["length"], "format": self.fmt_of(e.get("sig")) if e.get("ok") is not None else "…", "ok": e.get("ok"),
                             "outcome": e.get("family") if e.get("ok") else self.quarantine_label(e) if e.get("ok") is False else "in flight", "preview": raw[:130].decode("utf-8", "replace")})
            return rows

    def quarantine_label(self, e):
        """Attribution by SOURCE BINDING, never by another vendor's anchor: a bound source's unroutable line is that source's drift."""
        b = self.bound_to(e) if e.get("stage") in ("routing", "routing_drift") else None
        return f"quarantined: format drift of {b} (bound source)" if b else "quarantined: " + (e.get("stage") or "")

    def describe(self, eid):
        with LOCK:
            e = self.events.get(eid)
        if e is None:
            return None
        rec, raw = e["rec"], self.raw(e["rec"])
        ev = None
        if e.get("out"):
            with open(self.proc_of(rec).run / "out.jsonl", "rb") as f:
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
                           if ev else {"status": "quarantined", "stage": e.get("stage"), "reason": e.get("reason"), "attributed_to": self.bound_to(e),
                                "attribution": "by source binding (ingest channel + peer host); the router's reason is its surface observation" if self.bound_to(e) else None}
                           if e.get("ok") is False else {"status": "in flight"})}


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
            if p == "/api/tlog":
                return self._send(200, json.dumps(sysm.tlog_view(), default=str).encode())
            if p == "/certificate":
                try:
                    return self._send(200, sysm.certificate(q.get("id", "")).encode(), "text/html; charset=utf-8")
                except Exception as ex:
                    return self._send(500, f"certificate: {type(ex).__name__}: {ex}".encode(), "text/plain")
            if p == "/api/bundle":
                t = sysm.traces.get(q.get("id", "")) or {}
                b = next((x.get("bundle") for x in t.get("steps", []) if x.get("bundle")), None)
                if not b or not Path(b).exists():
                    return self._send(404, b"no derivation bundle yet: run Prove it", "text/plain")
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", f"attachment; filename=\"{Path(b).name}\""); self.end_headers()
                return self.wfile.write(Path(b).read_bytes())
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
                    for k in ("auto_onboard", "prepared_answers", "vendor_relay"):
                        if isinstance(d.get(k), bool):
                            sysm.policy[k] = d[k]
                elif self.path == "/api/approve" and job:
                    job["go"].set()
                elif self.path == "/api/answer" and job and (d.get("attribute") in ATTRIBUTES or d.get("attribute") == "unmapped") and any(f["field"] == d.get("field") for f in job["fields"]):
                    if d.get("lookup"):   # "success=1, failed=2": the operator's value map onto an enum attribute
                        lk = d["lookup"] if isinstance(d["lookup"], dict) else dict(x.split("=", 1) for x in str(d["lookup"]).replace(";", ",").split(",") if "=" in x)
                        job.setdefault("lookups", {})[d["field"]] = {str(k).strip(): int(str(v).strip()) for k, v in lk.items()}
                    job["answers"][d["field"]] = d["attribute"]
                    job.setdefault("answer_via", {})[d["field"]] = "proposal" if d.get("via") == "proposal" else "operator"
                elif self.path == "/api/promote" and job:
                    job["promote"].set()
                elif self.path == "/api/rollback":
                    sysm.rollback(d.get("alert"))
                elif self.path == "/api/siem":
                    sysm.siem_control(d.get("action"))
                elif self.path == "/api/device":
                    sysm.device_action(d.get("action"), d.get("arg"))
                elif self.path == "/api/lake-control":
                    sysm.lake_control(d.get("action"))
                elif self.path == "/api/scale":
                    sysm.scale(d.get("action"))
                elif self.path == "/api/push-unlogged":
                    res = sysm.push_unlogged(d.get("process", 1))
                    return self._send(200, json.dumps(res).encode())
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


def parse_bytes(v):
    for suf, mul in (("KiB", 1 << 10), ("MiB", 1 << 20), ("GiB", 1 << 30), ("KB", 10**3), ("MB", 10**6), ("GB", 10**9)):
        if v.endswith(suf):
            return int(float(v[:-len(suf)]) * mul)
    return int(v)


def main() -> int:
    ap = argparse.ArgumentParser(description="ULPF demo: the system console")
    ap.add_argument("--state", required=True); ap.add_argument("--listen", default="127.0.0.1:8765")
    ap.add_argument("--rt", default=str(ROOT / "runtime" / "bin" / "ulpf-runtime")); ap.add_argument("--golden", default=str(ROOT / "contracts" / "golden" / "squid-native"))
    ap.add_argument("--mode", choices=["generator", "devices"], default="generator", help="devices: the final demo with the real FortiGate and Suricata (start-demo.sh devices)")
    ap.add_argument("--in-tcp", default="127.0.0.1:6515"); ap.add_argument("--in-http", default="127.0.0.1:8516"); ap.add_argument("--destinations", default=str(ROOT / "demo" / "apps" / "destinations.json"))
    ap.add_argument("--vendor-packs", help="source packs of the four-vendor relay (demo/reset.sh builds them: $STATE/p6/source-packs)")
    ap.add_argument("--vendor-capture", help="the recorded four-vendor mixed capture ($STATE/p6/mixed.log)"); ap.add_argument("--relay-rate", type=float, default=8)
    ap.add_argument("--spool-cap", default="256MiB"); ap.add_argument("--lake", required=True)
    ap.add_argument("--lake-port", type=int, default=8792, help="process i's lake writer listens on this port + i - 1 ({lake_port} in destinations.json)")
    ap.add_argument("--processes", type=int, default=1, help="scale-out: N runtime processes on the same ingress addresses (SO_REUSEPORT)")
    ap.add_argument("--python", default="python"); ap.add_argument("--provider", choices=["model", "fixture"], default="fixture")
    ap.add_argument("--model-id", default=""); ap.add_argument("--server", default="http://127.0.0.1:8081"); ap.add_argument("--backend", default="unknown")
    ap.add_argument("--archive", help="the evidence archive (start-demo.sh: $APP/evidence-archive); without it the runtime runs with --dev-no-evidence-archive")
    ap.add_argument("--commit-dir", help="the always-running committer's commit tree (start-demo.sh: $APP/commit)")
    ap.add_argument("--evidence-grace", default="60s"); ap.add_argument("--evidence-buffer-cap", default="64MiB")
    ap.add_argument("--scaler", help="the container deployment (deploy/): each runtime process is a unit of containers, started, stopped and "
                                     "signalled through this scaler — and processes can be added and removed while running")
    a = ap.parse_args()
    s = System(a)
    s.start_runtime()
    threading.Thread(target=s.loop, daemon=True).start()
    if a.vendor_capture and Path(a.vendor_capture).exists():
        threading.Thread(target=s.relay, daemon=True).start()
    host, port = a.listen.rsplit(":", 1)
    srv = http.server.ThreadingHTTPServer((host, int(port)), handler(s))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    print(f"system: http://{a.listen}/  (state: {a.state}; provider: {a.provider})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if s.scaler:   # the container deployment: each runtime drains and seals; then its committer and lake writer stop
            for pr in s.live():
                for part, t in (("runtime", 30), ("committer", 15), ("lake", 30)):
                    try:
                        s.scaler.stop(pr.i, part, t)
                    except Exception as ex:   # noqa: BLE001
                        print(f"stop {part} {pr.i}: {ex}", file=sys.stderr, flush=True)
        for pr in s.procs:
            if pr.runtime and pr.runtime.poll() is None:
                pr.runtime.terminate()
        for pr in s.procs:
            if pr.runtime:
                try:
                    pr.runtime.wait(8)
                except subprocess.TimeoutExpired:
                    pr.runtime.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
