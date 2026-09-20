#!/usr/bin/env python3
"""sink — the demo's CONSUMER: receives what ULPF's egress connector delivers (HTTP POST, NDJSON, one normalized
OCSF event per line) and writes it to SQLite. Standard library only; entirely OUTSIDE the pipeline: it knows
nothing about ULPF except that events arrive as JSON with an `_lineage.event_id`.

    sink.py --listen 127.0.0.1:8790 --db events.sqlite --status consumer.json

Delivery from ULPF is at-least-once (after an interrupted batch the batch is sent again), so the consumer does what
any at-least-once consumer must: `event_id` is the primary key and a repeated event is ignored and counted.
A 2xx is returned only after the batch is committed — that answer is ULPF's acknowledgement.
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
STATE = {"app": "sink", "rows": 0, "batches": 0, "received": 0, "duplicates_ignored": 0, "by_family": {}, "last": None}


def dig(d, path):
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def write_status(path):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({**STATE, "at": time.time(), "pid": os.getpid()}, f)
    os.replace(tmp, path)


def make_handler(db_path, status_path):
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            rows = []
            try:
                for l in body.splitlines():
                    if l.strip():
                        e = json.loads(l)
                        lin = e.get("_lineage", {})
                        rows.append((lin["event_id"], lin.get("family_id"), str(e.get("time")), dig(e, "src_endpoint.ip"), dig(e, "dst_endpoint.ip"),
                                     str(e.get("action_id")), e.get("class_uid"), lin.get("raw_hash"), l.decode("utf-8")))
            except (ValueError, KeyError) as ex:
                self.send_response(400); self.end_headers(); self.wfile.write(str(ex).encode())
                return
            with LOCK:
                con = sqlite3.connect(db_path)
                before = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                con.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)", rows)
                con.commit()
                after = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                STATE["by_family"] = dict(con.execute("SELECT family, COUNT(*) FROM events GROUP BY family").fetchall())
                con.close()
                STATE["rows"] = after; STATE["batches"] += 1; STATE["received"] += len(rows); STATE["duplicates_ignored"] += len(rows) - (after - before)
                if rows:
                    r = rows[-1]
                    STATE["last"] = {"event_id": r[0], "family": r[1], "time": r[2], "src_ip": r[3], "dst_ip": r[4], "action_id": r[5]}
                write_status(status_path)
            self.send_response(204); self.end_headers()     # the acknowledgement: sent only after the commit

        def do_GET(self):
            with LOCK:
                b = json.dumps(STATE).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)

        def log_message(self, *a):
            pass
    return H


def main() -> int:
    ap = argparse.ArgumentParser(description="sink: the demo's consumer (outside the pipeline)")
    ap.add_argument("--listen", default="127.0.0.1:8790"); ap.add_argument("--db", required=True); ap.add_argument("--status", required=True)
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.execute("CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, family TEXT, time TEXT, src_ip TEXT, dst_ip TEXT, action_id TEXT, class_uid INTEGER, raw_hash TEXT, ocsf TEXT)")
    con.commit()
    STATE["rows"] = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    con.close()
    host, port = a.listen.rsplit(":", 1)
    STATE["listen"] = a.listen; STATE["db"] = a.db
    write_status(a.status)
    srv = http.server.ThreadingHTTPServer((host, int(port)), make_handler(a.db, a.status))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
