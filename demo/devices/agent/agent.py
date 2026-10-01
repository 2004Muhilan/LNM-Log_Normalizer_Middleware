#!/usr/bin/env python3
"""LAB AGENT — the device-side actions of the final demo (demo/devices/lab.sh) behind HTTP, for the container deployment
(2026-10-01). It is LAB EQUIPMENT, not part of ULPF: it drives the FortiGate (SSH, with the lab's key) and the Suricata
forwarder (the lab's Docker engine). The console in the container deployment calls it instead of `wsl.exe -d Containerlab`,
which a container cannot run. Bound to loopback; it runs one action at a time, only the ones lab.sh knows.

    POST /run {"args": ["fgt-connect", "default"]}  ->  {"rc": 0, "out": "..."}
"""
import http.server
import json
import os
import subprocess
import sys
import threading

LAB = os.environ.get("ULPF_LAB_SH", "/lab/lab.sh")
ACTIONS = {"status", "fgt-connect", "fgt-disconnect", "fgt-format", "fgt-logins", "ids-connect", "ids-disconnect", "attack"}
ONE = threading.Lock()


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            d = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)) or b"{}")
            args = d.get("args") or []
            if self.path != "/run" or not args or args[0] not in ACTIONS or not all(isinstance(a, str) and a.replace("-", "").isalnum() for a in args):
                raise ValueError("POST /run {args: [action, ...]} with a lab.sh action")
            with ONE:
                r = subprocess.run(["bash", LAB, *args], capture_output=True, text=True, timeout=int(d.get("timeout") or 180))
            body, code = {"rc": r.returncode, "out": r.stdout + r.stderr}, 200
        except subprocess.TimeoutExpired:
            body, code = {"rc": 124, "out": "timed out"}, 200
        except (ValueError, TypeError) as ex:
            body, code = {"error": str(ex)}, 400
        b = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    listen = os.environ.get("ULPF_LAB_AGENT_LISTEN", "127.0.0.1:8799")
    host, port = listen.rsplit(":", 1)
    print(f"lab agent: http://{listen}/run ({LAB})", flush=True)
    http.server.ThreadingHTTPServer((host, int(port)), H).serve_forever()
    sys.exit(0)
