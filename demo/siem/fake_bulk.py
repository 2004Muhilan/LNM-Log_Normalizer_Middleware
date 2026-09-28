#!/usr/bin/env python3
"""A stand-in for the `_bulk` API, for the scripted gate only (the interactive demo uses real OpenSearch). Standard library.

It reproduces the behaviours ULPF's bulk encoding depends on — and `demo/siem/contract-check.py` compares it with a real
OpenSearch, request for request, before any demo, so it cannot quietly drift from the real thing:
  * per-document results in a 200 answer (`errors`, `items[].index.status`, `.result`, `._version`, `.error.type`);
  * `index` by `_id` OVERWRITES: 201 `created` at version 1, then 200 `updated` with the version incremented — never a duplicate;
  * a permanent document rejection: a field named `ip` that is not an IP address, and a field whose type conflicts with the
    type it was first seen with, answer 400 `mapper_parsing_exception` for that document only (OpenSearch 2.19 words it so);
  * throttling: --throttle-every N answers the whole request 429 every N-th request; --throttle-doc-every M answers 429 for
    every M-th document (once per document, like a full write queue);
  * --max-body BYTES answers 413 above it (OpenSearch's http.max_content_length);
  * --state FILE keeps the documents across a kill and a restart, as OpenSearch's container keeps its data across
    `docker stop` / `docker start` — the scripted outage kills this process and starts it again.

    python3 demo/siem/fake_bulk.py --listen 127.0.0.1:9201 [--status FILE]
"""
import argparse
import ipaddress
import json
import os
import sys
import threading
import time
import http.server

LOCK = threading.Lock()
DOCS = {}        # index -> {_id: [version, doc]}
TYPES = {}       # index -> {path: type}
STATS = {"requests": 0, "documents": 0, "created": 0, "updated": 0, "rejected": 0, "throttled_requests": 0, "throttled_docs": 0, "too_large": 0}
CFG = {"throttle_every": 0, "throttle_doc_every": 0, "max_body": 0, "ids": None}
THROTTLED_ONCE = set()


def kind(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "long"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "keyword"
    return None


def check(index, doc, path=""):
    """None, or (type, reason) for the first field that cannot be indexed."""
    types = TYPES.setdefault(index, {})
    for k, v in doc.items():
        p = f"{path}.{k}" if path else k
        if isinstance(v, dict):
            if k == "unmapped":      # flat_object in the template: any keys, any values
                continue
            r = check(index, v, p)
            if r:
                return r
            continue
        if isinstance(v, list) or v is None:
            continue
        if k == "ip":
            try:
                ipaddress.ip_address(str(v))
            except ValueError:
                return p, f"failed to parse field [{p}] of type [ip]"
            continue
        t = kind(v)
        seen = types.get(p)
        if seen is None:
            types[p] = t   # dynamic mapping: the first value decides (strings -> keyword by the template)
            continue
        # OpenSearch coerces: a number or a boolean into a keyword field is its text; a numeric string into a number
        # field is the number; anything else that does not fit is a document-level mapper_parsing_exception
        ok = (seen == "keyword" or seen == t or {seen, t} <= {"long", "float"}
              or (seen in ("long", "float") and t == "keyword" and _numeric(v))
              or (seen == "boolean" and t == "keyword" and v in ("true", "false")))
        if not ok:
            return p, f"failed to parse field [{p}] of type [{seen}]"
    return None


def _numeric(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # the headers and the body leave in two writes: with Nagle on, the second waits for the client's delayed ACK (~40 ms
    # per request) — found by scripts/bench/capacity.py, where it capped a forwarder at ~20 requests per second
    disable_nagle_algorithm = True

    def _send(self, code, obj=None):
        b = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_HEAD(self):
        self._send(200)

    def do_PUT(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._send(200, {"acknowledged": True})

    def do_GET(self):
        p = self.path.split("?")[0]
        with LOCK:
            if p == "/_cluster/health":
                return self._send(200, {"status": "green", "fake": True})
            if p.endswith("/_count"):
                idx = p[1:-len("/_count")]
                n = sum(len(d) for i, d in DOCS.items() if not idx or idx == "_all" or i == idx or (idx.endswith("*") and i.startswith(idx[:-1])))
                return self._send(200, {"count": n})
            if p == "/ulpf/stats":
                return self._send(200, {**STATS, "unique_documents": sum(len(d) for d in DOCS.values()), "indices": {i: len(d) for i, d in DOCS.items()},
                                        "overwritten_documents": sum(1 for d in DOCS.values() for v in d.values() if v[0] > 1)})
            if p == "/ulpf/ids":
                return self._send(200, {i: sorted(d) for i, d in DOCS.items()})
        self._send(200, {"name": "fake-bulk", "version": {"number": "fake"}})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.split("?")[0] != "/_bulk":
            return self._send(404, {"error": "not found"})
        with LOCK:
            STATS["requests"] += 1
            if CFG["max_body"] and len(body) > CFG["max_body"]:
                STATS["too_large"] += 1
                return self._send(413)
            if CFG["throttle_every"] and STATS["requests"] % CFG["throttle_every"] == 0:
                STATS["throttled_requests"] += 1
                return self._send(429, {"error": {"type": "rejected_execution_exception", "reason": "rejected execution (fake)"}, "status": 429})
            if CFG["ids"]:
                return self._measure(body)
            lines = body.split(b"\n")
            items, errors, i = [], False, 0
            try:
                while i < len(lines):
                    if not lines[i].strip():
                        i += 1
                        continue
                    action = json.loads(lines[i])
                    (act, meta), = action.items()
                    doc = json.loads(lines[i + 1])
                    i += 2
                    idx, _id = meta["_index"], meta["_id"]
                    STATS["documents"] += 1
                    if CFG["throttle_doc_every"] and STATS["documents"] % CFG["throttle_doc_every"] == 0 and _id not in THROTTLED_ONCE:
                        THROTTLED_ONCE.add(_id)
                        STATS["throttled_docs"] += 1
                        errors = True
                        items.append({act: {"_index": idx, "_id": _id, "status": 429, "error": {"type": "rejected_execution_exception", "reason": "rejected execution (fake)"}}})
                        continue
                    bad = check(idx, doc)
                    if bad:
                        STATS["rejected"] += 1
                        errors = True
                        items.append({act: {"_index": idx, "_id": _id, "status": 400, "error": {"type": "mapper_parsing_exception",
                                                                                                "reason": f"{bad[1]} in document with id '{_id}'."}}})
                        continue
                    d = DOCS.setdefault(idx, {})
                    if act == "create" and _id in d:
                        errors = True
                        items.append({act: {"_index": idx, "_id": _id, "status": 409, "error": {"type": "version_conflict_engine_exception", "reason": "document already exists"}}})
                        continue
                    ver = d[_id][0] + 1 if _id in d else 1
                    d[_id] = [ver, doc]
                    STATS["created" if ver == 1 else "updated"] += 1
                    items.append({act: {"_index": idx, "_id": _id, "_version": ver, "result": "created" if ver == 1 else "updated", "status": 201 if ver == 1 else 200}})
            except (ValueError, KeyError, IndexError):
                return self._send(400, {"error": {"type": "illegal_argument_exception", "reason": "malformed bulk request (fake)"}, "status": 400})
        self._send(200, {"took": 1, "errors": errors, "items": items})

    def _measure(self, body):
        """Measurement mode (called under LOCK): count, append the ids, answer as OpenSearch does for new documents."""
        lines, items, ids, i = body.split(b"\n"), [], [], 0
        try:
            while i < len(lines):
                if not lines[i].strip():
                    i += 1
                    continue
                (act, meta), = json.loads(lines[i]).items()
                i += 2
                ids.append(meta["_id"])
                items.append({act: {"_index": meta["_index"], "_id": meta["_id"], "_version": 1, "result": "created", "status": 201}})
        except (ValueError, KeyError, IndexError):
            return self._send(400, {"error": {"type": "illegal_argument_exception", "reason": "malformed bulk request (fake)"}, "status": 400})
        CFG["ids"].write("\n".join(ids) + "\n")
        STATS["documents"] += len(ids)
        STATS["created"] += len(ids)
        self._send(200, {"took": 1, "errors": False, "items": items})

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:9201"); ap.add_argument("--status")
    ap.add_argument("--state", help="load the documents from this file at start, save them there at exit")
    ap.add_argument("--throttle-every", type=int, default=0); ap.add_argument("--throttle-doc-every", type=int, default=0); ap.add_argument("--max-body", type=int, default=0)
    ap.add_argument("--ids", help="measurement mode (scripts/bench/capacity.py): documents are neither kept nor type-checked; each _id is appended to this file, "
                                  "for the exactly-once count afterwards (millions of documents; the checks are the SIEM's cost, not the sender's)")
    a = ap.parse_args()
    CFG.update(throttle_every=a.throttle_every, throttle_doc_every=a.throttle_doc_every, max_body=a.max_body, ids=open(a.ids, "a", buffering=1 << 20) if a.ids else None)
    if a.state and os.path.exists(a.state):
        saved = json.load(open(a.state))
        DOCS.update({i: {k: v for k, v in d.items()} for i, d in saved["docs"].items()}); TYPES.update(saved["types"]); STATS.update(saved["stats"])
    host, port = a.listen.rsplit(":", 1)
    srv = http.server.ThreadingHTTPServer((host, int(port)), H)
    import signal
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    if a.status:
        def beat():
            while True:
                with LOCK:
                    s = {**STATS, "unique_documents": sum(len(d) for d in DOCS.values()), "overwritten_documents": sum(1 for d in DOCS.values() for v in d.values() if v[0] > 1), "at": time.time(), "pid": os.getpid()}
                tmp = a.status + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(s, f)
                os.replace(tmp, a.status)
                time.sleep(0.5)
        threading.Thread(target=beat, daemon=True).start()
    print(f"fake bulk receiver: http://{a.listen}/_bulk", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if CFG["ids"]:
            with LOCK:
                CFG["ids"].close()
        if a.state:
            with LOCK:
                tmp = a.state + ".tmp"
                with open(tmp, "w") as f:
                    json.dump({"docs": DOCS, "types": TYPES, "stats": STATS}, f)
                os.replace(tmp, a.state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
