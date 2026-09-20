#!/usr/bin/env python3
"""sink — the demo's CONSUMER / storage app: receives what ULPF's egress connector delivers (HTTP POST, NDJSON, one
normalized OCSF event per line), writes it to SQLite, and SHOWS it: http://127.0.0.1:8790/ is a page with the row
count and the latest rows, newest first — an outage reads as the rows stopping, the catch-up as them resuming. Standard library only, fully offline, entirely OUTSIDE the pipeline.

    sink.py --listen 127.0.0.1:8790 --db events.sqlite --status consumer.json

Delivery from ULPF is at-least-once, so `event_id` is the primary key and a repeated event is ignored and counted.
A 2xx is returned only after the batch is committed — that answer is ULPF's acknowledgement. Killing this process is
the demo's egress outage: ULPF keeps ingesting, records the outage in its evidence log, and delivers from its cursor
when the process is back (the database file survives the restart).
"""
import argparse
import http.server
import json
import os
import sqlite3
import sys
import threading
import time

LOCK = threading.Lock()
STATE = {"app": "sink", "rows": 0, "batches": 0, "received": 0, "duplicates_ignored": 0, "by_family": {}, "latest": [], "per_second": [], "started": time.time()}

PAGE = """<!doctype html><meta charset=utf-8><title>Database — the consumer's events</title>
<style>body{margin:0;padding:28px 36px;background:#fff;color:#000;font:22px/1.35 system-ui,-apple-system,"Segoe UI",sans-serif}h1{font-size:1.5rem;margin:0 0 18px}
.lab{color:#666;font-size:.95rem}.big{font-size:5rem;font-weight:800;line-height:1}table{border-collapse:collapse;width:100%;margin-top:22px;font:1.05rem ui-monospace,Consolas,monospace}
td,th{padding:7px 14px 7px 0;border-bottom:1px solid #ddd;text-align:left}th{color:#666;font:400 .9rem system-ui,sans-serif}.red{color:#c00000}</style>
<h1>Database — a consumer app outside ULPF, fed by the HTTP POST connector</h1>
<div class=lab>rows</div><div class=big id=rows>…</div>
<table><thead><tr><th>stored at</th><th>event time (ms)</th><th>source</th><th>destination</th><th>action</th><th>bytes out / in</th></tr></thead><tbody id=t></tbody></table>
<script>async function tick(){try{const d=await (await fetch('/stats')).json();rows.textContent=d.rows;rows.className='big';
t.innerHTML=d.latest.map(r=>`<tr><td>${r.stored_at}</td><td>${r.time}</td><td>${r.src}</td><td>${r.dst}</td><td>${r.action_id}</td><td>${r.bytes}</td></tr>`).join('');
}catch(e){rows.className='big red';rows.textContent='DOWN'}}tick();setInterval(tick,500)</script>"""


def dig(d, path):
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def refresh(db_path, status_path):
    con = sqlite3.connect(db_path)
    STATE["rows"] = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    STATE["by_family"] = dict(con.execute("SELECT family, COUNT(*) FROM events GROUP BY family").fetchall())
    now = int(time.time())
    per = dict(con.execute("SELECT CAST(stored_at AS INTEGER), COUNT(*) FROM events WHERE stored_at >= ? GROUP BY 1", (now - 120,)).fetchall())
    STATE["per_second"] = [[s, per.get(s, 0)] for s in range(now - 119, now + 1)]
    STATE["latest"] = [{"stored_at": time.strftime("%H:%M:%S", time.localtime(r[0])), "event_id": r[1], "family": r[2], "time": r[3], "src": r[4], "dst": r[5], "action_id": r[6], "bytes": r[7]}
                       for r in con.execute("SELECT stored_at, event_id, family, time, src, dst, action_id, bytes FROM events ORDER BY stored_at DESC, event_id DESC LIMIT 14")]
    con.close()
    tmp = status_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({**STATE, "at": time.time(), "pid": os.getpid()}, f)
    os.replace(tmp, status_path)


def make_handler(db_path, status_path):
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            rows, now = [], time.time()
            try:
                for l in body.splitlines():
                    if l.strip():
                        e = json.loads(l); lin = e["_lineage"]
                        rows.append((lin["event_id"], now, lin.get("family_id"), json.dumps(e.get("time")), f"{dig(e, 'src_endpoint.ip')}:{dig(e, 'src_endpoint.port')}", f"{dig(e, 'dst_endpoint.ip')}:{dig(e, 'dst_endpoint.port')}",
                                     json.dumps(e.get("action_id")), f"{dig(e, 'traffic.bytes_out')} / {dig(e, 'traffic.bytes_in')}", lin.get("raw_hash"), l.decode("utf-8")))
            except (ValueError, KeyError) as ex:
                self.send_response(400); self.end_headers(); self.wfile.write(str(ex).encode())
                return
            with LOCK:
                con = sqlite3.connect(db_path)
                before = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                con.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
                con.commit()
                added = con.execute("SELECT COUNT(*) FROM events").fetchone()[0] - before
                con.close()
                STATE["batches"] += 1; STATE["received"] += len(rows); STATE["duplicates_ignored"] += len(rows) - added
                refresh(db_path, status_path)
            self.send_response(204); self.end_headers()     # the acknowledgement: sent only after the commit

        def do_GET(self):
            if self.path.startswith("/stats"):
                with LOCK:
                    refresh(db_path, status_path); b = json.dumps(STATE).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)
            else:
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers(); self.wfile.write(PAGE.encode())

        def log_message(self, *a):
            pass
    return H


def main() -> int:
    ap = argparse.ArgumentParser(description="sink: the demo's consumer and its view (outside the pipeline)")
    ap.add_argument("--listen", default="127.0.0.1:8790"); ap.add_argument("--db", required=True); ap.add_argument("--status", required=True)
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.execute("CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, stored_at REAL, family TEXT, time TEXT, src TEXT, dst TEXT, action_id TEXT, bytes TEXT, raw_hash TEXT, ocsf TEXT)")
    con.commit(); con.close()
    host, port = a.listen.rsplit(":", 1)
    STATE["listen"] = a.listen
    srv = http.server.ThreadingHTTPServer((host, int(port)), make_handler(a.db, a.status))

    def heartbeat():   # the UI shows this app as DOWN when the status file goes stale
        while True:
            with LOCK:
                refresh(a.db, a.status)
            time.sleep(1)
    threading.Thread(target=heartbeat, daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
