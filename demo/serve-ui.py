#!/usr/bin/env python3
"""The demo UI server: standard library only, fully offline. Serves demo/ui/ at / and the demo state
directory at /state/ with no caching, so the browser sees what the scripts just wrote. Read-only, with ONE exception:
POST /live/assert appends the operator's choice on screen 5 ({"field": "pos_4", "attribute": "src_endpoint.ip"} or
{"promote": true}) as a line to <state>/live/assertions.jsonl. The server executes nothing: the live sequence
(demo/live/assertions.py) reads that queue and calls the same `ulpf_learn respond` CLI it would call for a scripted answer.

    python3 demo/serve-ui.py --state ~/ulpf-demo --port 8765
"""
import argparse
import json
import re
import http.server
import os
import posixpath
import sys
from pathlib import Path

UI = Path(__file__).resolve().parent / "ui"


class Handler(http.server.SimpleHTTPRequestHandler):
    state = Path.home() / "ulpf-demo"

    def translate_path(self, path):
        path = path.split("?", 1)[0].split("#", 1)[0]
        path = posixpath.normpath(path)
        if path.startswith("/state/") or path == "/state":
            rel = path[len("/state/"):] if path.startswith("/state/") else ""
            return str(self.state / rel)
        if path in ("/", ""):
            return str(UI / "index.html")
        return str(UI / path.lstrip("/"))

    def do_POST(self):
        if self.path != "/live/assert":
            self.send_error(404); return
        try:
            d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)))
            if d.get("onboard") is True:   # the Tier 1 decision: a human says "onboard this source"
                dq = self.state / "live" / "decisions.jsonl"
                if not dq.exists():
                    raise ValueError("the live sequence is not waiting for a decision")
                with open(dq, "a") as f:
                    f.write(json.dumps({"onboard": True, "by": "ui"}) + "\n")
                self.send_response(204); self.end_headers(); return
            if d.get("promote") is True:
                rec = {"promote": True, "by": "ui"}
            elif re.fullmatch(r"pos_[0-9]{1,2}", str(d.get("field", ""))) and re.fullmatch(r"[a-z_]+(\.[a-z_]+){0,2}", str(d.get("attribute", ""))):
                rec = {"field": d["field"], "attribute": d["attribute"], "by": "ui"}
            else:
                raise ValueError("expected {field: pos_N, attribute: ocsf.path} or {promote: true}")
            q = self.state / "live" / "assertions.jsonl"
            if not q.exists():
                raise ValueError("the live sequence is not waiting for the operator")
            with open(q, "a") as f:
                f.write(json.dumps(rec) + "\n")
            self.send_response(204); self.end_headers()
        except (ValueError, OSError) as e:
            self.send_response(400); self.end_headers(); self.wfile.write(str(e).encode())

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def log_message(self, fmt, *args):  # quiet: the terminal is the fallback display
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=str(Path.home() / "ulpf-demo"))
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--bind", default="127.0.0.1")
    a = ap.parse_args()
    Handler.state = Path(a.state)
    os.chdir(str(UI))
    srv = http.server.ThreadingHTTPServer((a.bind, a.port), Handler)
    print(f"ulpf demo ui: http://localhost:{a.port}/  (state: {a.state})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
