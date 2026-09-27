#!/usr/bin/env python3
"""The fake must not drift from the real thing: the SAME bulk requests go to demo/siem/fake_bulk.py and to a real
OpenSearch, and what matters in the answers must agree — the `errors` flag, and per document the status, the result
(created / updated), the _version and the error type — plus the document count afterwards. Byte-for-byte equality is
not the test (timings, sequence numbers and shard details always differ). Outside the gate; run it before any demo:

    python3 demo/siem/contract-check.py --os http://127.0.0.1:9200            # scenarios 1-6 on the demo OpenSearch
    python3 demo/siem/contract-check.py --os http://127.0.0.1:9200 --limits   # + 413 and 429 on a throwaway container

Scenarios: new documents; the same documents again (overwrite, not duplicate); a mixed batch with an invalid IP; the
coercions the template allows (a numeric string into a long, a number into a keyword); a type conflict (text into a
long); `create` on an existing _id (409 — why ULPF uses `index`). With --limits, a second OpenSearch container is started
with http.max_content_length and a one-slot write queue: a request over the limit must answer 413 on both; the write
queue is flooded to provoke 429 — whether a real 429 could be provoked is REPORTED, and if it could not, 429 is covered
by the fake alone (said so, not hidden).
"""
import argparse
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import http.client
import http.server
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_bulk  # noqa: E402
import setup      # noqa: E402

PREFIX = "ulpf-contract-"


def call(base, method, path, body=None, ctype="application/json"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b or b"{}")
        except ValueError:
            return e.code, {}
    except (OSError, http.client.HTTPException):   # not up yet, or reset while starting
        return 0, {}


def bulk(base, docs, action="index", refresh=True):
    b = b"".join(json.dumps({action: {"_index": idx, "_id": i}}).encode() + b"\n" + json.dumps(d).encode() + b"\n" for idx, i, d in docs)
    return call(base, "POST", "/_bulk" + ("?refresh=true" if refresh else ""), b, "application/x-ndjson")


def norm(res):
    st, body = res
    if st != 200:
        return {"http": st}
    return {"http": 200, "errors": body.get("errors"), "items": [
        {k: v.get(k) for k in ("status", "result", "_version")} | {"error": (v.get("error") or {}).get("type")} for it in body.get("items", []) for v in it.values()]}


def ev(i, **kw):
    e = {"class_uid": 4001, "time": 1790467200000 + i, "action_id": 1, "src_endpoint": {"ip": f"10.4.1.{i}", "port": 40000 + i}, "_lineage": {"event_id": f"ev_c{i:03d}", "raw_hash": "sha256:0"}}
    e.update(kw)
    return e


SCENARIOS = [
    ("new documents: 201 created, version 1", lambda ix: [(ix, f"ev_c{i:03d}", ev(i)) for i in range(4)], "index"),
    ("the same documents again: 200 updated, version 2 — overwrite, never a duplicate", lambda ix: [(ix, f"ev_c{i:03d}", ev(i)) for i in range(4)], "index"),
    ("mixed batch: one invalid IP is rejected alone (400 mapper_parsing_exception), the others are stored", lambda ix: [(ix, "ev_c010", ev(10)), (ix, "ev_c011", ev(11, src_endpoint={"ip": "not-an-ip"})), (ix, "ev_c012", ev(12))], "index"),
    ("coercions the mapping allows: a numeric string into a long, a number into a keyword", lambda ix: [(ix, "ev_c020", ev(20, action_id="2", severity=5)), (ix, "ev_c021", ev(21, severity="high"))], "index"),
    ("a type conflict: text into a long field", lambda ix: [(ix, "ev_c030", ev(30, action_id="denied"))], "index"),
    ("`create` on an existing _id: 409 (why ULPF's encoding uses `index`)", lambda ix: [(ix, "ev_c000", ev(0))], "create"),
]


def start_fake(**cfg):
    fake_bulk.DOCS.clear(); fake_bulk.TYPES.clear(); fake_bulk.THROTTLED_ONCE.clear()
    for k in fake_bulk.STATS:
        fake_bulk.STATS[k] = 0
    fake_bulk.CFG.update({"throttle_every": 0, "throttle_doc_every": 0, "max_body": 0, **cfg})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), fake_bulk.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def scenarios(real):
    srv, fake = start_fake()
    ix = PREFIX + "4001"
    call(real, "DELETE", "/" + PREFIX + "*")
    tmpl = json.loads(json.dumps(setup.TEMPLATE)); tmpl["index_patterns"] = [PREFIX + "*"]; tmpl["priority"] = 200
    call(real, "PUT", "/_index_template/ulpf-contract", tmpl)
    bad = 0
    for title, docs, action in SCENARIOS:
        a, b = norm(bulk(real, docs(ix), action)), norm(bulk(fake, docs(ix), action))
        same = a == b
        bad += not same
        print(f"  {'SAME  ' if same else 'DIFFER'} {title}")
        if not same:
            print(f"         real: {json.dumps(a)}\n         fake: {json.dumps(b)}")
    ca, cb = call(real, "GET", f"/{ix}/_count")[1].get("count"), call(fake, "GET", f"/{ix}/_count")[1].get("count")
    print(f"  {'SAME  ' if ca == cb else 'DIFFER'} document count afterwards: real {ca}, fake {cb}")
    bad += ca != cb
    call(real, "DELETE", "/" + PREFIX + "*"); call(real, "DELETE", "/_index_template/ulpf-contract")
    srv.shutdown()
    return bad


def limits(image):
    name, port = "ulpf-contract-os", 9291
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:9200", "-e", "discovery.type=single-node", "-e", "DISABLE_SECURITY_PLUGIN=true",
                    "-e", "DISABLE_INSTALL_DEMO_CONFIG=true", "-e", "OPENSEARCH_JAVA_OPTS=-Xms256m -Xmx256m", "-e", "http.max_content_length=4kb",
                    "-e", "thread_pool.write.size=1", "-e", "thread_pool.write.queue_size=1", image], check=True, capture_output=True)
    real = f"http://127.0.0.1:{port}"
    bad = 0
    try:
        for _ in range(180):
            if call(real, "GET", "/_cluster/health")[0] == 200:
                break
            time.sleep(1)
        big = [(PREFIX + "4001", f"ev_b{i}", ev(i, message="x" * 400)) for i in range(20)]   # ~10 KB > 4 KB
        srv, fake = start_fake(max_body=4096)
        a, b = norm(bulk(real, big)), norm(bulk(fake, big))
        print(f"  {'SAME  ' if a == b else 'DIFFER'} a request over the size limit: real HTTP {a.get('http')}, fake HTTP {b.get('http')}")
        bad += a != b
        srv.shutdown()
        small = lambda k: [(PREFIX + "4001", f"ev_t{k}_{i}", ev(i)) for i in range(5)]
        with cf.ThreadPoolExecutor(32) as ex:
            got = list(ex.map(lambda k: bulk(real, small(k), refresh=False), range(200)))
        top = sum(1 for st, _ in got if st == 429)
        doc = sum(1 for st, b in got if st == 200 for it in b.get("items", []) for v in it.values() if v.get("status") == 429)
        if top or doc:
            types = {(v.get("error") or {}).get("type") for st, b in got if st == 200 for it in b.get("items", []) for v in it.values() if v.get("status") == 429}
            types |= {(b.get("error") or {}).get("type") for st, b in got if st == 429}
            same = types <= {"rejected_execution_exception", None} and "rejected_execution_exception" in types
            print(f"  {'SAME  ' if same else 'DIFFER'} throttling provoked: {top} request(s) answered 429, {doc} document(s) answered 429 inside a 200; error types {sorted(t for t in types if t)} — the fake answers both shapes with rejected_execution_exception")
            bad += not same
        else:
            print("  NOTE   a real 429 could not be provoked on this machine (one write thread, a one-slot queue, 32 concurrent clients): 429 is covered by the fake ALONE")
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--os", default="http://127.0.0.1:9200"); ap.add_argument("--limits", action="store_true")
    ap.add_argument("--image", default="opensearchproject/opensearch:" + os.environ.get("ULPF_OPENSEARCH_VERSION", "2.19.2"))
    a = ap.parse_args()
    if call(a.os, "GET", "/_cluster/health")[0] != 200:
        print(f"contract-check: no OpenSearch at {a.os} (bash demo/siem/siem.sh start)"); return 2
    print(f"contract check: fake_bulk.py against the real OpenSearch at {a.os}")
    bad = scenarios(a.os)
    if a.limits:
        print("limits (throwaway container, 4 KB request limit, one-slot write queue):")
        bad += limits(a.image)
    print(f"contract-check: {'PASS — the fake answers like the real OpenSearch' if not bad else f'FAIL — {bad} difference(s): fix the fake before trusting the gate'}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
