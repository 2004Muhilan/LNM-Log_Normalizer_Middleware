#!/usr/bin/env python3
"""ULPF demo replay server — Python 3 standard library only, no network access at any point.

    python3 serve.py            # then open http://localhost:8765/

Replays one recorded run of the six-step demo (capture/) through the unchanged demo UI (ui/). The UI
reads files under /state/ exactly as it does live; this server decides which files are visible
according to a replay clock: a step's artifacts appear when its replay window ends, step 5's event
stream is revealed line by line over its window, and status.json reports each step's REAL measured
duration while the replay itself is compressed (step 2: ~145 s live, replayed in 18 s).

Controls (from the UI, via replay.js): 1–6 jump to a step, n/→ next, p/← previous, space pause/resume,
t terminal output, s cycle screens. The same controls exist as HTTP endpoints under /replay/.

Optional real mode (real/): if the Linux binaries are present, `bash real/run-real.sh [capture-file]`
runs steps 5 and 6 for real on this machine and writes into state-real/; `python3 serve.py --real`
serves that instead of the recording (steps 1–4 are still the recording — they need the learning plane).
"""
import argparse
import http.server
import json
import os
import posixpath
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
UI = HERE / "ui"
CAPTURE = HERE / "capture"

# replay window per step, seconds (the real durations come from the recording's status.json)
WINDOWS = {"1": 2.0, "2": 18.0, "3": 2.5, "4": 2.5, "5": 9.0, "6": 3.0}
# files of step 5 revealed progressively (line-oriented) over its window
PROGRESSIVE = {"step5/out.jsonl", "step5/q.jsonl", "step5/ml.jsonl"}
LATE = {"step5/stats.json", "step5/summary.txt", "step5/gaps.txt"}   # only at the end of step 5
GAP_AT = 0.72                                                          # gaps.json appears at 72 % of step 5


class Replay:
    """The replay clock: which step is playing, how far into its window, paused or not."""

    def __init__(self, recorded_status):
        self.rec = recorded_status
        self.lock = threading.Lock()
        self.step = 0          # 0 = before step 1
        self.started = None    # wall time the current step's window began
        self.elapsed = 0.0     # accumulated when paused
        self.paused = False
        self.finished = set()  # steps whose window has completed (artifacts visible)

    def _progress(self):
        if self.step == 0:
            return 1.0
        if self.step in self.finished:
            return 1.0
        e = self.elapsed + (0.0 if self.paused or self.started is None else time.time() - self.started)
        w = WINDOWS.get(str(self.step), 2.0)
        if e >= w:
            self.finished.add(self.step)
            return 1.0
        return e / w

    def goto(self, n):
        with self.lock:
            n = max(0, min(6, n))
            self.step = n
            self.finished = {k for k in range(1, n)}   # everything before n is complete
            self.started, self.elapsed, self.paused = time.time(), 0.0, False

    def next(self):
        with self.lock:
            cur = self.step
        self.goto(cur + 1 if cur < 6 else 6)

    def prev(self):
        with self.lock:
            cur = self.step
        self.goto(cur - 1 if cur > 0 else 0)

    def pause(self):
        with self.lock:
            if self.step == 0 or self.step in self.finished:
                return
            if self.paused:
                self.started, self.paused = time.time(), False
            else:
                self.elapsed += time.time() - self.started
                self.paused = True

    def visible(self, rel):
        """Whether a state file is visible now, and (for progressive files) what fraction of it."""
        with self.lock:
            p = self._progress()
            step = self.step
            done = set(self.finished)
        top = rel.split("/", 1)[0]
        if not top.startswith("step"):
            return True, 1.0            # packs, p6, preflight.json: always
        n = int(top[4:]) if top[4:].isdigit() else 0
        if n in done:
            return True, 1.0
        if n != step:
            return False, 0.0
        if rel in PROGRESSIVE:
            return True, p
        if rel == "step5/progress.json":
            return True, p
        if rel == "step5/gaps.json":
            return (p >= GAP_AT), 1.0
        return False, 0.0                # the step's result files appear when its window ends

    def status(self):
        """status.json as the UI expects it: real seconds for completed steps, 'running' for the current one."""
        with self.lock:
            p = self._progress()
            step, done, paused = self.step, set(self.finished), self.paused
        steps = {}
        for k, s in self.rec.get("steps", {}).items():
            n = int(k)
            entry = {"title": s.get("title", ""), "note": s.get("note", ""), "seconds": s.get("seconds")}
            if n in done:
                entry["state"] = "done"
            elif n == step:
                entry["state"] = "running"
            else:
                entry["state"] = ""
                entry.pop("seconds")
            steps[k] = entry
        return {"run_id": self.rec.get("run_id"), "replay": True, "steps": steps, "current": str(step) if step else None,
                "updated": time.time(), "replay_progress": round(p, 3), "replay_paused": paused,
                "replay_window_s": WINDOWS.get(str(step)), "real_seconds": (self.rec.get("steps", {}).get(str(step)) or {}).get("seconds")}


class Handler(http.server.SimpleHTTPRequestHandler):
    replay = None
    state_dir = CAPTURE / "state"
    real = False

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _bytes(self, b, ctype="application/octet-stream", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def do_GET(self):
        path = posixpath.normpath(self.path.split("?", 1)[0])
        r = self.replay
        if path.startswith("/replay/"):
            cmd = path[len("/replay/"):]
            if cmd == "status":
                return self._json(r.status())
            if cmd == "next":
                r.next()
            elif cmd == "prev":
                r.prev()
            elif cmd == "pause":
                r.pause()
            elif cmd.startswith("goto/"):
                r.goto(int(cmd[5:]))
            elif cmd.startswith("terminal/"):
                f = CAPTURE / "terminal" / f"step{cmd[9:]}.txt"
                return self._bytes(f.read_bytes() if f.exists() else b"(no terminal capture)", "text/plain; charset=utf-8")
            return self._json(r.status())
        if path == "/state/status.json":
            return self._json(r.status())
        if path.startswith("/state/"):
            rel = path[len("/state/"):]
            ok, frac = r.visible(rel)
            f = self.state_dir / rel
            if not ok or not f.is_file():
                return self._bytes(b"not yet", "text/plain", 404)
            data = f.read_bytes()
            if rel in PROGRESSIVE and frac < 1.0:
                lines = data.split(b"\n")
                keep = int(len(lines) * frac)
                data = b"\n".join(lines[:keep]) + (b"\n" if keep else b"")
            if rel == "step5/progress.json" and frac < 1.0:
                try:
                    pj = json.loads(data)
                    pj["sent_a"] = int(pj.get("sent_a", 0) * frac)
                    pj["done"] = False
                    data = json.dumps(pj).encode()
                except Exception:
                    pass
            ctype = "application/json" if rel.endswith(".json") else "text/plain; charset=utf-8"
            return self._bytes(data, ctype)
        if path in ("/", ""):
            return self._bytes((UI / "index.html").read_bytes(), "text/html; charset=utf-8")
        f = UI / path.lstrip("/")
        if f.is_file():
            ctype = {"js": "application/javascript", "css": "text/css", "html": "text/html"}.get(f.suffix[1:], "application/octet-stream")
            return self._bytes(f.read_bytes(), ctype)
        return self._bytes(b"not found", "text/plain", 404)


def main():
    ap = argparse.ArgumentParser(description="ULPF demo replay (stdlib only, offline)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--real", action="store_true", help="serve state-real/ (written by real/run-real.sh) for steps 5 and 6")
    a = ap.parse_args()
    rec = json.loads((CAPTURE / "status.json").read_text())
    Handler.replay = Replay(rec)
    if a.real:
        Handler.state_dir = HERE / "state-real"
        if not Handler.state_dir.exists():
            raise SystemExit("state-real/ not found: run bash real/run-real.sh first")
        try:
            rs = json.loads((Handler.state_dir / "status.json").read_text())
            for k in ("5", "6"):
                if k in rs.get("steps", {}):
                    rec["steps"][k] = rs["steps"][k]
        except Exception:
            pass
    srv = http.server.ThreadingHTTPServer((a.bind, a.port), Handler)
    print(f"ULPF demo replay: http://localhost:{a.port}/   (recording {rec.get('run_id')}; keys 1-6 n p space t s)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
