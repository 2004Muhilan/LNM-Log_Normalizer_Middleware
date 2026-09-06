#!/usr/bin/env python3
"""The demo UI server: standard library only, fully offline. Serves demo/ui/ at / and the demo state
directory at /state/ with no caching, so the browser sees what the scripts just wrote. Read-only.

    python3 demo/serve-ui.py --state ~/ulpf-demo --port 8765
"""
import argparse
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
