#!/usr/bin/env python3
"""GENERATOR — the demo's log-producing application, with its own page (http://127.0.0.1:8780/). Standard library only,
offline, entirely OUTSIDE the pipeline: all it knows about ULPF is two addresses, one per ingress connector.

    generator.py --tcp 127.0.0.1:6515 --http 127.0.0.1:8516 [--listen 127.0.0.1:8780] [--rate 6]

Everything is a button on the page (POST /api/set):
  connector   none | tcp (syslog over TCP, RFC 6587 octet counting) | http (HTTP POST, newline-delimited lines)
  shape       positional | csv | kv | json | xml | leef        — the file format of the lines (demo/live/flowgen.py)
  running     generation on / off
  drift       "firmware 2.0": the protocol becomes its IANA number and a zone field is appended, in whatever shape is on

Lines are queued and sent in order; while no connector is chosen (or ULPF is not listening) the queue grows, bounded,
and is delivered on reconnect. TCP has no application acknowledgement: a receiver crash can lose lines in flight.
"""
import argparse
import collections
import http.client
import http.server
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "live"))
from flowgen import SHAPES, Flowtap  # noqa: E402

UI = Path(__file__).resolve().parents[1] / "ui"
LOCK = threading.Lock()
S = {"app": "flowtap generator", "connector": "none", "shape": "positional", "running": False, "drift": False, "rate": 6.0, "generated": 0, "sent": 0, "backlog": 0,
     "connected": False, "dropped_queue_full": 0, "burst": 0, "recent": [], "shapes": SHAPES, "connectors": {}, "by_shape": {}}
MAX_QUEUE = 5000


def worker(targets):
    gen, backlog, sock, sock_kind = Flowtap(26156), collections.deque(), None, None
    recent = collections.deque(maxlen=14)
    next_t = time.time()

    def close():
        nonlocal sock, sock_kind
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        sock, sock_kind = None, None

    while True:
        with LOCK:
            conn, shape, running, drift, rate = S["connector"], S["shape"], S["running"], S["drift"], S["rate"]
        now = time.time()
        if not running:
            next_t = now
        with LOCK:
            burst, S["burst"] = S["burst"], 0
        for _ in range(burst):   # the attack burst: denied flows from one source, all at once
            line = gen.line(2 if drift else 1, now, shape, burst=True)
            backlog.append(line); recent.append({"shape": shape + " burst", "line": line})
            with LOCK:
                S["generated"] += 1
        while running and now >= next_t:
            line = gen.line(2 if drift else 1, next_t, shape)
            if len(backlog) >= MAX_QUEUE:
                backlog.popleft()
                with LOCK:
                    S["dropped_queue_full"] += 1
            backlog.append(line); recent.append({"shape": shape + (" v2" if drift else ""), "line": line})
            with LOCK:
                S["generated"] += 1
                k = shape + (" v2" if drift else ""); S["by_shape"][k] = S["by_shape"].get(k, 0) + 1
            next_t += 1.0 / rate
        if sock is not None and sock_kind != conn:
            close()
        if sock is None and conn in targets:
            host, port = targets[conn].rsplit(":", 1)
            try:
                if conn == "http":
                    sock = http.client.HTTPConnection(host, int(port), timeout=2.0); sock.connect()
                else:
                    sock = socket.create_connection((host, int(port)), timeout=1.0)
                sock_kind = conn
            except OSError:
                sock = None
        sent = 0
        while sock is not None and backlog:
            try:
                if sock_kind == "http":
                    batch = list(backlog)[:200]
                    sock.request("POST", "/", body=("\n".join(batch) + "\n").encode(), headers={"Content-Type": "text/plain"})
                    r = sock.getresponse(); r.read()
                    if r.status // 100 != 2:
                        raise OSError(f"HTTP {r.status}")
                    for _ in batch:
                        backlog.popleft()
                    sent += len(batch)
                else:
                    l = backlog[0].encode()
                    sock.sendall(str(len(l)).encode() + b" " + l)
                    backlog.popleft(); sent += 1
            except (OSError, http.client.HTTPException):
                close()
        with LOCK:
            S["sent"] += sent; S["backlog"] = len(backlog); S["connected"] = sock is not None; S["recent"] = list(recent)[::-1]
        time.sleep(0.05)


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/api/state":
            with LOCK:
                return self._send(200, json.dumps(S).encode())
        f = {"/": "generator.html", "/theme.css": "theme.css"}.get(p)
        if not f:
            return self._send(404, b"not found", "text/plain")
        self._send(200, (UI / f).read_bytes(), "text/css" if f.endswith(".css") else "text/html; charset=utf-8")

    def do_POST(self):
        try:
            d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 2048)) or b"{}")
            with LOCK:
                if d.get("connector") in ("none", "tcp", "http"):
                    S["connector"] = d["connector"]
                if d.get("shape") in SHAPES:
                    S["shape"] = d["shape"]
                if d.get("burst") is True:
                    S["burst"] += 12
                for k in ("running", "drift"):
                    if isinstance(d.get(k), bool):
                        S[k] = d[k]
            self._send(204, b"")
        except ValueError as e:
            self._send(400, str(e).encode(), "text/plain")

    def log_message(self, *a):
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="the demo's generator application and its page")
    ap.add_argument("--tcp", default="127.0.0.1:6515"); ap.add_argument("--http", default="127.0.0.1:8516"); ap.add_argument("--listen", default="127.0.0.1:8780"); ap.add_argument("--rate", type=float, default=6.0)
    a = ap.parse_args()
    S["rate"] = a.rate
    S["connectors"] = {"tcp": {"label": "Syslog over TCP", "to": a.tcp}, "http": {"label": "HTTP POST", "to": a.http}}
    threading.Thread(target=worker, args=({"tcp": a.tcp, "http": a.http},), daemon=True).start()
    host, port = a.listen.rsplit(":", 1)
    print(f"generator: http://{a.listen}/", flush=True)
    try:
        http.server.ThreadingHTTPServer((host, int(port)), H).serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
