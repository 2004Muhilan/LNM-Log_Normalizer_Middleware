#!/usr/bin/env python3
"""DATABASE — the demo's consumer application: it stores what ULPF delivers in SQLite and shows it
(http://127.0.0.1:8790/). Standard library only, offline, entirely OUTSIDE the pipeline.

    database.py --db events.sqlite --file RUN/egress-stdout.ndjson [--listen 127.0.0.1:8790] [--tcp 127.0.0.1:8791]

It can be reached through any of ULPF's three egress connectors, chosen with a button (POST /api/set):
  http   ULPF POSTs NDJSON batches to /ingest; the 2xx, sent only after the commit, is ULPF's acknowledgement
  tcp    ULPF sends RFC 5424 over TCP with RFC 6587 octet counting; the event is the MSG part (no acknowledgement exists
         in syslog: ULPF re-sends its last batch after a reconnect, which is why event_id is the primary key)
  file   ULPF's stdout connector, redirected to a file by whoever runs it; this app tails it from its own saved offset
  none   disconnected: /ingest answers 503, the TCP port is closed, the file is not read

Each connector is an independent at-least-once delivery with ITS OWN cursor inside ULPF. Disconnect and reconnect on the
same connector: delivery resumes where it stopped. Switch connector: that connector delivers from where IT stopped, so
events already stored arrive again and are ignored (counted as duplicates) — nothing is stored twice, nothing is lost.
"""
import argparse
import http.server
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from pathlib import Path

UI = Path(__file__).resolve().parents[1] / "ui"
LOCK = threading.Lock()
S = {"app": "events database (SQLite)", "connector": "none", "received": 0, "duplicates_ignored": 0, "batches": 0, "last_stored_at": None, "by_via": {}, "connectors": {}}
DB = None


def dig(d, path):
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def store(lines, via):
    rows, now = [], time.time()
    for l in lines:
        if not l.strip():
            continue
        e = json.loads(l); lin = e["_lineage"]
        rows.append((lin["event_id"], now, via, lin.get("parser_id"), lin.get("family_id"), e.get("time"), f"{dig(e, 'src_endpoint.ip')}:{dig(e, 'src_endpoint.port')}",
                     f"{dig(e, 'dst_endpoint.ip')}:{dig(e, 'dst_endpoint.port')}", e.get("action_id"), f"{dig(e, 'traffic.bytes_out')} / {dig(e, 'traffic.bytes_in')}", lin.get("raw_hash"),
                     l.decode("utf-8") if isinstance(l, bytes) else l))
    if not rows:
        return
    with LOCK:
        con = sqlite3.connect(DB)
        before = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        con.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.commit()
        added = con.execute("SELECT COUNT(*) FROM events").fetchone()[0] - before
        con.close()
        S["batches"] += 1; S["received"] += len(rows); S["duplicates_ignored"] += len(rows) - added
        if added:
            S["last_stored_at"] = now; S["by_via"][via] = S["by_via"].get(via, 0) + added


def tcp_server(addr):
    host, port = addr.rsplit(":", 1)
    srv, conns = None, []

    def serve(c):
        buf = b""
        c.settimeout(0.5)
        while S["connector"] == "tcp":
            try:
                d = c.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d:
                break
            buf += d
            out = []
            while True:
                sp = buf.find(b" ")
                if sp <= 0 or not buf[:sp].isdigit():
                    break
                n = int(buf[:sp])
                if len(buf) < sp + 1 + n:
                    break
                frame, buf = buf[sp + 1:sp + 1 + n], buf[sp + 1 + n:]
                at = frame.find(b'] {')
                if at >= 0:
                    out.append(frame[at + 2:])
            try:
                store(out, "syslog/TCP")
            except (ValueError, KeyError):
                pass
        c.close()

    while True:
        want = S["connector"] == "tcp"
        if want and srv is None:
            srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind((host, int(port))); srv.listen(8); srv.settimeout(0.3)
        if not want and srv is not None:
            srv.close(); srv = None
            for c in conns:
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            conns = []
        if srv is None:
            time.sleep(0.2); continue
        try:
            c, _ = srv.accept()
            conns.append(c); threading.Thread(target=serve, args=(c,), daemon=True).start()
        except socket.timeout:
            pass


def file_tail(path):
    while True:
        if S["connector"] != "file" or not path or not os.path.exists(path):
            time.sleep(0.3); continue
        with LOCK:
            con = sqlite3.connect(DB); r = con.execute("SELECT v FROM meta WHERE k='file_offset'").fetchone(); con.close()
        off = int(r[0]) if r else 0
        with open(path, "rb") as f:
            f.seek(off); data = f.read(1 << 20)
        end = data.rfind(b"\n") + 1   # complete lines only
        if end:
            try:
                store(data[:end].split(b"\n"), "file")
            except (ValueError, KeyError):
                pass
            with LOCK:
                con = sqlite3.connect(DB); con.execute("INSERT OR REPLACE INTO meta VALUES ('file_offset', ?)", (str(off + end),)); con.commit(); con.close()
        else:
            time.sleep(0.3)


def state():
    with LOCK:
        con = sqlite3.connect(DB)
        rows = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        fam = dict(con.execute("SELECT family, COUNT(*) FROM events GROUP BY family").fetchall())
        latest = [{"event_id": r[0], "stored_at": time.strftime("%H:%M:%S", time.localtime(r[1])), "via": r[2], "pack": r[3], "family": r[4], "time": r[5], "src": r[6], "dst": r[7], "action_id": r[8], "bytes": r[9]}
                  for r in con.execute("SELECT event_id, stored_at, via, pack, family, time, src, dst, action_id, bytes FROM events ORDER BY stored_at DESC, event_id DESC LIMIT 40")]
        con.close()
        return {**S, "rows": rows, "by_family": fam, "latest": latest, "at": time.time()}


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Cache-Control", "no-store"); self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.startswith("/ingest"):
            if S["connector"] != "http":
                return self._send(503, b"not connected through the HTTP connector", "text/plain")
            try:
                store(body.splitlines(), "HTTP POST")
            except (ValueError, KeyError) as ex:
                return self._send(400, str(ex).encode(), "text/plain")
            return self._send(204)     # the acknowledgement: sent only after the commit
        if self.path == "/api/set":
            try:
                c = json.loads(body or b"{}").get("connector")
            except ValueError:
                c = None
            if c not in ("none", "http", "tcp", "file"):
                return self._send(400, b"connector: none | http | tcp | file", "text/plain")
            S["connector"] = c
            return self._send(204)
        self._send(404, b"not found", "text/plain")

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/api/state":
            return self._send(200, json.dumps(state()).encode())
        if p == "/api/row":
            eid = self.path.split("id=", 1)[-1]
            with LOCK:
                con = sqlite3.connect(DB); r = con.execute("SELECT ocsf FROM events WHERE event_id = ?", (eid,)).fetchone(); con.close()
            return self._send(200 if r else 404, (r[0] if r else "{}").encode())
        f = {"/": "database.html", "/theme.css": "theme.css"}.get(p)
        if not f:
            return self._send(404, b"not found", "text/plain")
        self._send(200, (UI / f).read_bytes(), "text/css" if f.endswith(".css") else "text/html; charset=utf-8")

    def log_message(self, *a):
        pass


def main() -> int:
    global DB
    ap = argparse.ArgumentParser(description="the demo's consumer application and its page")
    ap.add_argument("--listen", default="127.0.0.1:8790"); ap.add_argument("--tcp", default="127.0.0.1:8791"); ap.add_argument("--db", required=True)
    ap.add_argument("--file", default="", help="the file ULPF's stdout connector is redirected to"); ap.add_argument("--status", help="write the state as JSON to this file every second (the scripted live sequence reads it)"); ap.add_argument("--connector", default="none", choices=["none", "http", "tcp", "file"])
    a = ap.parse_args()
    DB = a.db
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, stored_at REAL, via TEXT, pack TEXT, family TEXT, time INTEGER, src TEXT, dst TEXT, action_id INTEGER, bytes TEXT, raw_hash TEXT, ocsf TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    con.commit(); con.close()
    S["connector"] = a.connector
    S["connectors"] = {"http": {"label": "HTTP POST", "at": f"http://{a.listen}/ingest"}, "tcp": {"label": "Syslog over TCP", "at": a.tcp}, "file": {"label": "File (stdout connector)", "at": a.file}}
    threading.Thread(target=tcp_server, args=(a.tcp,), daemon=True).start()
    threading.Thread(target=file_tail, args=(a.file,), daemon=True).start()
    if a.status:
        def heartbeat():
            while True:
                tmp = a.status + ".tmp"
                with open(tmp, "w") as f:
                    json.dump({**state(), "pid": os.getpid()}, f)
                os.replace(tmp, a.status)
                time.sleep(1)
        threading.Thread(target=heartbeat, daemon=True).start()
    host, port = a.listen.rsplit(":", 1)
    print(f"database: http://{a.listen}/", flush=True)
    try:
        http.server.ThreadingHTTPServer((host, int(port)), H).serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
