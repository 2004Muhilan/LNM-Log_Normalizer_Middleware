#!/usr/bin/env python3
"""ULPF SCALER — the only container that holds the Docker socket (2026-10-01, the user's decision: least privilege).

The console asks; the scaler acts, on a FIXED template. A runtime PROCESS is a unit of containers, one per part:

    runtime     ulpf-runtime, host network (the sender's address must reach it intact: measured 2026-10-01 — through a
                published port a lab sender at 172.20.20.50 arrived as 172.17.0.1), root with CAP_LINUX_IMMUTABLE and
                nothing else (the evidence store's kernel flag), SO_REUSEPORT on the shared ingress ports
    committer   ulpf-committer, nonroot, NO network, no capability — it signs checkpoints and ships sealed segments
    lake        the process's lake writer (the app image), host network, loopback only

The caller chooses the unit number and the ARGUMENTS of the part's fixed program; the image, the program, the mounts, the
user, the capability and the network are the scaler's. It touches only containers it labelled (ulpf.scaler=<project>),
plus the one SIEM container it is configured with (the outage step). Standard library only.

    GET  /info                         Docker's CPU count and memory, MemAvailable, every unit container and its state
    POST /start   {unit, part, args}   create and start (an exited container of the same name is replaced)
    POST /stop    {unit, part, timeout} SIGTERM, wait, remove; returns the exit code
    POST /signal  {unit, part, signal} e.g. HUP to a runtime (the hot reload)
    GET  /logs?unit=&part=             the container's stderr+stdout, as text
    POST /siem    {action: outage|recover}
    POST /reset                        remove every unit container (a fresh start)
"""
import http.client
import http.server
import json
import os
import socket
import sys
import urllib.parse

SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
PROJECT = os.environ.get("ULPF_PROJECT", "ulpf")
LISTEN = os.environ.get("ULPF_SCALER_LISTEN", "127.0.0.1:8797")
V = {k: os.environ[k] for k in ("ULPF_VOL_STATE", "ULPF_VOL_PACKS", "ULPF_VOL_KEYS", "ULPF_VOL_TRUST", "ULPF_VOL_TLOG",
                                "ULPF_IMAGE_RUNTIME", "ULPF_IMAGE_COMMITTER", "ULPF_IMAGE_APP")}
SIEM = os.environ.get("ULPF_SIEM_CONTAINER", "")


def vol(name, target, ro=False):
    return {"Type": "volume", "Source": name, "Target": target, "ReadOnly": ro}


TEMPLATES = {
    "runtime": {"image": V["ULPF_IMAGE_RUNTIME"], "first": "run", "prefix": [], "user": "0", "cap_add": ["LINUX_IMMUTABLE"], "network": "host",
                "mounts": [vol(V["ULPF_VOL_STATE"], "/state"), vol(V["ULPF_VOL_PACKS"], "/ulpf/packs", True),
                           vol(V["ULPF_VOL_TRUST"], "/keys/trust", True), vol(V["ULPF_VOL_TLOG"], "/tlog", True)]},
    "committer": {"image": V["ULPF_IMAGE_COMMITTER"], "first": "commit", "prefix": [], "user": "", "cap_add": [], "network": "none",
                  "mounts": [vol(V["ULPF_VOL_STATE"], "/state"), vol(V["ULPF_VOL_KEYS"], "/keys", True), vol(V["ULPF_VOL_TRUST"], "/trust", True)]},
    "lake": {"image": V["ULPF_IMAGE_APP"], "first": "--lake", "prefix": ["python", "adapters/lake/lakewriter.py"], "user": "", "cap_add": [], "network": "host",
             "mounts": [vol(V["ULPF_VOL_STATE"], "/state")]},
}


class UnixConn(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost", timeout=120)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(120)
        self.sock.connect(SOCK)


def docker(method, path, body=None, raw=False):
    c = UnixConn()
    try:
        c.request(method, "/v1.43" + path, body=json.dumps(body) if body is not None else None, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
    finally:
        c.close()
    if r.status >= 400:
        raise RuntimeError(f"docker {method} {path}: HTTP {r.status} {data[:300].decode(errors='replace')}")
    return data if raw else (json.loads(data) if data else None)


def cname(unit, part):
    return f"{PROJECT}-{part}-{int(unit)}"


def check(unit, part):
    if part not in TEMPLATES or not isinstance(unit, int) or not 1 <= unit <= 4096:
        raise ValueError("unit: an integer 1..4096; part: runtime | committer | lake")


def units():
    flt = urllib.parse.quote(json.dumps({"label": [f"ulpf.scaler={PROJECT}"]}))
    out = []
    for c in docker("GET", f"/containers/json?all=1&filters={flt}"):
        out.append({"name": c["Names"][0].lstrip("/"), "unit": int(c["Labels"].get("ulpf.unit", 0)), "part": c["Labels"].get("ulpf.part"),
                    "state": c["State"], "status": c["Status"], "id": c["Id"][:12]})
    return sorted(out, key=lambda x: (x["unit"], x["part"] or ""))


def meminfo():
    try:
        with open("/proc/meminfo") as f:
            return {l.split(":")[0]: int(l.split()[1]) * 1024 for l in f if l.split(":")[0] in ("MemTotal", "MemAvailable")}
    except OSError:
        return {}


def start(unit, part, args):
    check(unit, part)
    t = TEMPLATES[part]
    if not isinstance(args, list) or not args or args[0] != t["first"] or not all(isinstance(a, str) and "\n" not in a and "\0" not in a for a in args):
        raise ValueError(f"{part}: args must be a list of strings starting with {t['first']!r}")
    name = cname(unit, part)
    try:
        docker("DELETE", f"/containers/{name}?force=1")
    except RuntimeError as ex:
        if "404" not in str(ex):
            raise
    spec = {"Image": t["image"], "Cmd": t["prefix"] + args, "Labels": {"ulpf.scaler": PROJECT, "ulpf.unit": str(unit), "ulpf.part": part},
            "HostConfig": {"NetworkMode": t["network"], "Mounts": t["mounts"], "CapAdd": t["cap_add"] or None, "RestartPolicy": {"Name": "no"},
                           "LogConfig": {"Type": "json-file", "Config": {"max-size": "20m", "max-file": "2"}}}}
    if t["image"] == V["ULPF_IMAGE_APP"]:
        spec["WorkingDir"] = "/ulpf"
    if t["user"]:
        spec["User"] = t["user"]
    docker("POST", f"/containers/create?name={name}", spec)
    docker("POST", f"/containers/{name}/start")
    return {"name": name, "started": True}


def stop(unit, part, timeout=20):
    check(unit, part)
    name = cname(unit, part)
    try:
        docker("POST", f"/containers/{name}/stop?t={int(timeout)}")
    except RuntimeError as ex:
        if "404" in str(ex):
            return {"name": name, "exit_code": None, "absent": True}
        if "304" not in str(ex):
            raise
    code = docker("POST", f"/containers/{name}/wait").get("StatusCode")
    logs = text_logs(name)
    docker("DELETE", f"/containers/{name}?force=1")
    return {"name": name, "exit_code": code, "log_tail": logs[-40000:]}   # the runtime's exit summary is one long JSON line


def text_logs(name):
    data = docker("GET", f"/containers/{name}/logs?stdout=1&stderr=1", raw=True)
    out, i = [], 0
    while i + 8 <= len(data):   # the multiplexed stream of a container without a TTY: [stream, 0, 0, 0, size(4)] payload
        n = int.from_bytes(data[i + 4:i + 8], "big")
        out.append(data[i + 8:i + 8 + n]); i += 8 + n
    return b"".join(out).decode("utf-8", "replace")


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, obj, ctype="application/json"):
        body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        p, _, qs = self.path.partition("?")
        q = dict(urllib.parse.parse_qsl(qs))
        try:
            if p == "/info":
                i = docker("GET", "/info")
                return self._send(200, {"ncpu": i.get("NCPU"), "mem_total": i.get("MemTotal"), **{k.lower(): v for k, v in meminfo().items()},
                                        "engine": i.get("ServerVersion"), "os": i.get("OperatingSystem"), "units": units()})
            if p == "/logs":
                check(int(q.get("unit", 0)), q.get("part"))
                return self._send(200, text_logs(cname(int(q["unit"]), q["part"])), "text/plain; charset=utf-8")
            return self._send(404, {"error": "not found"})
        except (ValueError, RuntimeError) as ex:
            return self._send(404 if "404" in str(ex) else 400, {"error": str(ex)})

    def do_POST(self):
        try:
            d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536)) or b"{}")
            if self.path == "/start":
                return self._send(200, start(d.get("unit"), d.get("part"), d.get("args")))
            if self.path == "/stop":
                return self._send(200, stop(d.get("unit"), d.get("part"), d.get("timeout", 20)))
            if self.path == "/signal":
                check(d.get("unit"), d.get("part"))
                if d.get("signal") not in ("HUP", "TERM"):
                    raise ValueError("signal: HUP | TERM")
                docker("POST", f"/containers/{cname(d['unit'], d['part'])}/kill?signal={d['signal']}")
                return self._send(200, {"signalled": True})
            if self.path == "/siem":
                if not SIEM or d.get("action") not in ("outage", "recover"):
                    raise ValueError("siem: outage | recover (and a configured SIEM container)")
                docker("POST", f"/containers/{SIEM}/{'stop?t=5' if d['action'] == 'outage' else 'start'}")
                return self._send(200, {"siem": d["action"]})
            if self.path == "/reset":
                gone = []
                for u in units():
                    docker("DELETE", f"/containers/{u['name']}?force=1"); gone.append(u["name"])
                return self._send(200, {"removed": gone})
            return self._send(404, {"error": "not found"})
        except (ValueError, RuntimeError, TypeError) as ex:
            msg = str(ex)
            # 304: already stopped / already started — not an error for the SIEM switch
            if "HTTP 304" in msg:
                return self._send(200, {"unchanged": True})
            return self._send(400, {"error": msg})

    def log_message(self, *a):
        pass


def main():
    host, port = LISTEN.rsplit(":", 1)
    srv = http.server.ThreadingHTTPServer((host, int(port)), H)
    print(f"scaler: http://{LISTEN}/ (project {PROJECT}; socket {SOCK})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
