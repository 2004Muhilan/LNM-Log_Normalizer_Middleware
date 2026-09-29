#!/usr/bin/env python3
"""The lake writer — a DESTINATION ADAPTER that ships with ULPF, like any other destination on the far side of egress:
ULPF delivers normalized OCSF events to it over plain HTTP (NDJSON), and it writes them as Parquet, one path per OCSF
class, partitioned by day, following Amazon Security Lake's layout convention:

    <lake>/ext/ulpf_<class_name>/region=<region>/accountId=<account>/eventDay=<YYYYMMDD>/part-<spool>-<first>-<last>.parquet

We claim this FOLLOWS Security Lake's layout conventions; it has not been tested against Security Lake. Local disk only.

    python adapters/lake/lakewriter.py --lake DIR [--listen 127.0.0.1:8792] [--rotate-bytes 128MiB] [--rotate-seconds 300] [--writer-id ID]
    ulpf-runtime run ... --spool SPOOL --forward "http://127.0.0.1:8792/ingest?batch=1000"

Speed (profiled 2026-09-27, scripts/bench/lake_profile.py, docs/throughput.md): the time went to (1) a FIXED COST PER
FILE of ~0.45 s — the full fixed schema from the pinned tables (~3,600 elements) is set up and written for every file —
times many small files (rotation every few seconds, per class, per event day); (2) writing the wide rows; (3) an fsync
pair per 100-event batch. Hence: production rotates on SIZE (128 MiB staged, or 5 minutes at most) and the demo keeps
its short rotation on the command line; DuckDB is told that row order inside a file carries no meaning
(preserve_insertion_order=false: 1.6x on the wide write — exactly-once rests on the spool marks and the file names,
never on row order); ULPF sends the lake 1,000-event batches (?batch=1000). The full fixed schema is kept. Scale-out:
one writer per ULPF process (--writer-id), all writing into the same lake root — their files are named by their own
spool ids, their staging and state are their own.

Why each event lands exactly once, through outages and crashes of either side:
  * ULPF sends every batch with its place in its spool (X-ULPF-Spool-Id / -Start / -End). The writer keeps a DURABLE
    high-water mark per spool: a batch (or the part of one) below it was already staged and is acknowledged without
    being staged again. A request without the headers is refused (400): run ULPF with --spool.
  * A batch is acknowledged only after it is appended to the staging file and fsynced AND the state (high-water mark,
    staging length) is replaced atomically. On start, the staging file is cut back to the length the state names, so a
    batch staged but not committed is simply staged again when ULPF redelivers it.
  * Rotation (by size or by age) groups the staged events by (spool, class, day), writes each group to a hidden
    temporary file, fsyncs it and RENAMES it into place — a crash never leaves a half-written Parquet file visible —
    and names it by the spool range of its rows, so a flush repeated after a crash replaces the same file with the same
    rows. Only then is the staging file emptied.
  * The schema of every file of a class comes from the pinned OCSF table (schema.py), never from inference.
A conversion failure is loud: the rows stay staged (never dropped), /status carries the error, and the next rotation
tries again.
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.server
import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def parse_bytes(s: str) -> int:
    for suf, mul in (("KiB", 1 << 10), ("MiB", 1 << 20), ("GiB", 1 << 30), ("B", 1)):
        if s.endswith(suf):
            return int(float(s[:-len(suf)]) * mul)
    return int(s)


def fsync_dir(d: Path):
    fd = os.open(str(d), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Lake:
    def __init__(self, lake: Path, pinned: Path, rotate_bytes: int, rotate_seconds: float, region: str, account: str, writer_id: str = "", keep_order: bool = False):
        import duckdb  # noqa: F401  (fail at start, not at the first rotation, when the wheel is missing)
        self.lake, self.pinned = Path(lake), str(pinned)
        self.rotate_bytes, self.rotate_seconds, self.region, self.account = rotate_bytes, rotate_seconds, region, account
        self.keep_order = keep_order
        self.wdir = self.lake / ("_writer" + (f"-{writer_id}" if writer_id else ""))   # one staging area and state per writer
        self.wdir.mkdir(parents=True, exist_ok=True)
        self.staging, self.state_path = self.wdir / "staging.jsonl", self.wdir / "state.json"
        self.rejected = self.wdir / "rejected.jsonl"   # rows the lake refuses (see flush), with the reason — never silently dropped
        self.lock = threading.Lock()
        self.st = {"marks": {}, "staging_bytes": 0, "staged_rows": 0, "oldest_staged_at": None}
        if self.state_path.exists():
            self.st.update(json.loads(self.state_path.read_text(encoding="utf-8")))
        size = self.staging.stat().st_size if self.staging.exists() else 0
        if size > self.st["staging_bytes"]:
            with open(self.staging, "r+b") as f:   # a batch staged but never committed: ULPF will send it again
                f.truncate(self.st["staging_bytes"])
                f.flush()
                os.fsync(f.fileno())
        self.stats = {"received_batches": 0, "received_rows": 0, "duplicate_rows_ignored": 0, "rows_written": 0, "files_written": 0, "rows_rejected": 0,
                      "last_flush": None, "last_error": None, "started": time.time()}

    # ------------------------------------------------------------------ ingest
    def _commit_state(self):
        tmp = self.state_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.st, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    def ingest(self, body: bytes, spool: str, start: int, end: int) -> int:
        """Stage the lines of [start, end) that lie at or above the spool's high-water mark; returns rows staged."""
        with self.lock:
            mark = int(self.st["marks"].get(spool, 0))
            self.stats["received_batches"] += 1
            if end <= mark:
                self.stats["duplicate_rows_ignored"] += body.count(b"\n")
                return 0
            out, off = [], start
            for line in body.split(b"\n"):
                if not line.strip():
                    continue
                if off >= mark:
                    out.append(f"{spool} {off} ".encode() + line + b"\n")
                else:
                    self.stats["duplicate_rows_ignored"] += 1
                off += len(line) + 1   # the spool line and its newline, exactly as ULPF counted it
            if off != end:
                raise ValueError(f"the batch's lines cover spool bytes {start}–{off}, the headers say {start}–{end}")
            data = b"".join(out)
            with open(self.staging, "ab") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.st["marks"][spool] = end
            self.st["staging_bytes"] += len(data)
            self.st["staged_rows"] += len(out)
            if out and not self.st["oldest_staged_at"]:
                self.st["oldest_staged_at"] = time.time()
            self._commit_state()   # the acknowledgement's commit point
            self.stats["received_rows"] += len(out)
            return len(out)

    # ------------------------------------------------------------------ rotation
    def due(self) -> bool:
        return self.st["staging_bytes"] > 0 and (self.st["staging_bytes"] >= self.rotate_bytes or time.time() - (self.st["oldest_staged_at"] or time.time()) >= self.rotate_seconds)

    def flush(self, force: bool = False) -> int:
        import duckdb
        with self.lock:
            if not self.st["staging_bytes"] or not (force or self.due()):
                return 0
            groups: dict[tuple, list] = {}
            refused = []
            with open(self.staging, "rb") as f:
                for line in f:
                    spool, off, ev = line.split(b" ", 2)
                    e = json.loads(ev)
                    cu = e.get("class_uid")
                    if e.get("time") is not None and (not isinstance(e["time"], int) or isinstance(e["time"], bool)):
                        # the pinned schema's `time` is epoch milliseconds (BIGINT). A row that carries text there (found live,
                        # 2026-09-30: Suricata's ISO 8601 "+0000" timestamp, uncoerced) is REFUSED — kept with its reason in
                        # rejected.jsonl — instead of failing the whole rotation for every other source's rows
                        refused.append(json.dumps({"spool": spool.decode(), "offset": int(off), "reason": f"time is {type(e['time']).__name__}, not epoch milliseconds: {str(e['time'])[:60]}",
                                                   "event_id": (e.get("_lineage") or {}).get("event_id"), "event": e}).encode() + b"\n")
                        continue
                    ms = e.get("time") or (e.get("_lineage") or {}).get("ingest_time") or 0
                    day = dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y%m%d")
                    groups.setdefault((spool.decode(), cu, day), []).append((int(off), ev))
            classes = schema.pinned_classes(self.pinned)
            written = 0
            try:
                con = duckdb.connect()
                if not self.keep_order:
                    con.execute("SET preserve_insertion_order=false")   # row order inside a file carries no meaning here
                for (spool, cu, day), rows in sorted(groups.items(), key=lambda kv: (kv[0][0], str(kv[0][1]), kv[0][2])):
                    name = f"ulpf_{classes[cu]['name']}" if cu in classes else f"ulpf_class_{cu}"
                    d = self.lake / "ext" / name / f"region={self.region}" / f"accountId={self.account}" / f"eventDay={day}"
                    d.mkdir(parents=True, exist_ok=True)
                    final = d / f"part-{spool[:12]}-{rows[0][0]:020d}-{rows[-1][0]:020d}.parquet"
                    src, tmp = self.wdir / "group.jsonl", d / ("." + final.name + ".tmp")
                    src.write_bytes(b"".join(ev.rstrip(b"\n") + b"\n" for _, ev in rows))
                    reader = (f"read_json('{src}', format='newline_delimited', columns={schema.read_columns(self.pinned, cu)})" if cu in classes
                              else f"read_json_objects('{src}', format='newline_delimited')")
                    con.execute(f"COPY (SELECT {schema.select_list(self.pinned, cu if cu in classes else None)} FROM {reader}) TO '{tmp}' (FORMAT parquet, COMPRESSION zstd)")
                    with open(tmp, "rb") as fh:
                        os.fsync(fh.fileno())
                    os.replace(tmp, final)
                    fsync_dir(d)
                    written += len(rows)
                    self.stats["files_written"] += 1
                con.close()
            except Exception as ex:   # loud, and nothing is lost: the rows stay staged and the next rotation tries again
                self.stats["last_error"] = f"{type(ex).__name__}: {str(ex)[:400]}"
                return 0
            if refused:   # before the staging is emptied: a crash here repeats them in rejected.jsonl, never loses them
                with open(self.rejected, "ab") as f:
                    f.write(b"".join(refused))
                    f.flush()
                    os.fsync(f.fileno())
                self.stats["rows_rejected"] += len(refused)
            with open(self.staging, "r+b") as f:
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())
            self.st.update(staging_bytes=0, staged_rows=0, oldest_staged_at=None)
            self._commit_state()
            self.stats.update(rows_written=self.stats["rows_written"] + written, last_flush=time.time(), last_error=None)
            return written

    def status(self) -> dict:
        """Answers at once. A rotation holds the lock for its whole Parquet write — seconds under load — and a health probe
        that waited on it read a busy writer as DOWN (gate, 2026-09-30); then the last snapshot is returned, marked so."""
        if not self.lock.acquire(timeout=0.25):
            return {**getattr(self, "_last_status", {"app": "ulpf lake writer", "lake": str(self.lake)}), "busy": "rotating: this is the last snapshot", "at": time.time()}
        try:
            self._last_status = {"app": "ulpf lake writer", "lake": str(self.lake), **self.stats, "staged_rows": self.st["staged_rows"], "staging_bytes": self.st["staging_bytes"],
                                 "high_water_marks": dict(self.st["marks"]), "at": time.time()}
            return self._last_status
        finally:
            self.lock.release()


def handler(lake: Lake):
    class H(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body=b"", ctype="application/json"):
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

        def do_POST(self):
            if not self.path.startswith("/ingest"):
                return self._send(404, b"not found", "text/plain")
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            spool, start, end = self.headers.get("X-ULPF-Spool-Id"), self.headers.get("X-ULPF-Spool-Start"), self.headers.get("X-ULPF-Spool-End")
            if not (spool and start and end):
                return self._send(400, b"the lake writer needs X-ULPF-Spool-Id/-Start/-End: run ULPF with --spool DIR", "text/plain")
            try:
                lake.ingest(body, spool, int(start), int(end))
            except (ValueError, OSError) as ex:
                return self._send(400 if isinstance(ex, ValueError) else 503, str(ex).encode(), "text/plain")
            self._send(204)   # after the fsync and the state commit: ULPF may advance its cursor

        def do_GET(self):
            if self.path.startswith("/status"):
                return self._send(200, json.dumps(lake.status()).encode())
            if self.path.startswith("/flush"):
                n = lake.flush(force=True)
                return self._send(200, json.dumps({"rows_written": n, **lake.status()}).encode())
            self._send(404, b"not found", "text/plain")

        def log_message(self, *a):
            pass
    return H


def main() -> int:
    ap = argparse.ArgumentParser(description="ULPF lake writer: OCSF Parquet in Security Lake's layout convention")
    ap.add_argument("--lake", required=True); ap.add_argument("--listen", default="127.0.0.1:8792")
    ap.add_argument("--pinned", default=str(ROOT / "ocsf" / "pinned"))
    ap.add_argument("--rotate-bytes", default="128MiB", help="rotate when this much is staged (production: few, large files — every file pays a fixed ~0.45 s for the full schema)")
    ap.add_argument("--rotate-seconds", type=float, default=300, help="rotate at the latest this long after the oldest staged row (the demo passes 10)")
    ap.add_argument("--writer-id", default="", help="scale-out: one writer per ULPF process into the same lake root; its staging and state live in _writer-<id>")
    ap.add_argument("--keep-insertion-order", action="store_true", help="measurement only: the writer as it was before 2026-09-27 (slower wide writes)")
    ap.add_argument("--region", default="local"); ap.add_argument("--account-id", default="000000000000"); ap.add_argument("--status")
    a = ap.parse_args()
    lake = Lake(Path(a.lake), Path(a.pinned), parse_bytes(a.rotate_bytes), a.rotate_seconds, a.region, a.account_id, a.writer_id, a.keep_insertion_order)
    stop = threading.Event()

    def rotator():
        while not stop.is_set():
            try:
                lake.flush()
            except Exception as ex:   # never let one bad rotation stop every later one (the thread died once, 2026-09-30)
                lake.stats["last_error"] = f"{type(ex).__name__}: {str(ex)[:400]}"
            if a.status:
                tmp = a.status + ".tmp"
                Path(tmp).write_text(json.dumps(lake.status()), encoding="utf-8")
                os.replace(tmp, a.status)
            stop.wait(1.0)
    threading.Thread(target=rotator, daemon=True).start()
    host, port = a.listen.rsplit(":", 1)
    srv = http.server.ThreadingHTTPServer((host, int(port)), handler(lake))
    print(f"lake writer: http://{a.listen}/ingest -> {a.lake}", flush=True)
    import signal
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        lake.flush(force=True)   # a clean stop leaves nothing staged
    return 0


if __name__ == "__main__":
    sys.exit(main())
