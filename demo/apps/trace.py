#!/usr/bin/env python3
"""The traceability round trip: a SIEM finding -> its event_id -> the original raw bytes in the evidence log -> a
Merkle inclusion proof under a signed checkpoint, verified -> the same event in the lake. Requirements (a) and (d),
end to end, with the tools that already exist (ulpf-committer, `ulpf-runtime export`, ulpf-verify); this is where Proof
of Derivation will plug in later.

    python3 demo/apps/trace.py --event-id ev_... --evidence EV --lake LAKE [--os http://127.0.0.1:9200] [--archive A --commit C]
    python3 demo/apps/trace.py --latest-finding --evidence EV --lake LAKE

Evidence archive (2026-09-27): the local evidence directory is a short buffer. With --archive, the raw bytes are read
from the local copy while it exists and otherwise from the ARCHIVED copy (the event is found through the local
catalogue of deleted segments); the page says which. With --commit, the always-running committer's checkpoints are
used (no second committer is started: two would race on the checkpoint chain) — the trace waits for the checkpoint
that covers the event's segment.

Commit mode, stated: the committer runs with ULPF_COMMIT_SEALED=1 — it commits SEALED segments without the kernel
immutable flag (the development seam the six-step demo's step 6 also uses; the kernel-flag version is
scripts/p5-boundary-test.sh). A segment seals about two seconds after it opened, on the next event; a finding on an event
in the segment still being written is proven a moment later.
"""
import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "runtime" / "bin"


def http_json(url, body=None):
    r = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method="POST" if body is not None else "GET",
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=10) as resp:
        return json.loads(resp.read())


def findings(os_url, n=20):
    """The detector's latest findings: rule, time, the documents it names (their _id is ULPF's event_id)."""
    f = http_json(f"{os_url}/_plugins/_security_analytics/findings/_search?detectorType=ulpf_ocsf_network&size=100")
    out = []
    for x in f.get("findings", []):
        rule = ", ".join(q.get("name", "") for q in x.get("queries", []))
        out.append({"id": x["id"], "rule": "ULPF deny spike" if rule == "bucket_level_monitor" else rule, "at": x.get("timestamp"), "event_ids": x.get("related_doc_ids", [])})
    return sorted(out, key=lambda x: -(x["at"] or 0))[:n]


def archive_path(ev_dir, archive, seg, suffix):
    """The archived copy of a segment file: <archive>/<store_id>/segments/<seg><suffix>."""
    try:
        sid = json.load(open(os.path.join(ev_dir, "store.json")))["store_id"]
    except (OSError, ValueError, KeyError):
        return None
    return os.path.join(archive, sid, "segments", seg + suffix)


def seg_file(ev_dir, archive, seg, suffix):
    """(path, where): the local copy while it exists, else the archived copy — the one lookup path."""
    p = os.path.join(ev_dir, seg + suffix)
    if os.path.exists(p):
        return p, "local"
    if archive:
        a = archive_path(ev_dir, archive, seg, suffix)
        if a and os.path.exists(a):
            return a, "archive"
    return None, None


def find_record(ev_dir, archive, event_id):
    """The evidence index record of an event: the local indexes, then the catalogue of shipped-and-deleted segments."""
    for f in sorted(glob.glob(os.path.join(ev_dir, "seg_*.idx.jsonl"))):
        try:
            for l in open(f, encoding="utf-8"):
                if event_id in l:
                    r = json.loads(l)
                    if r["event_id"] == event_id:
                        return r, "local"
        except OSError:   # deleted between the listing and the read: it is in the archive now
            continue
    needle = event_id + "\n"
    for c in sorted(glob.glob(os.path.join(ev_dir, "catalog", "seg_*.ids"))):
        if needle in open(c, encoding="utf-8").read():
            seg = os.path.basename(c)[:-4]
            p, where = seg_file(ev_dir, archive, seg, ".idx.jsonl")
            if p:
                for l in open(p, encoding="utf-8"):
                    r = json.loads(l)
                    if r["event_id"] == event_id:
                        return r, where
    return None, None


def read_raw(ev_dir, archive, rec):
    p, where = seg_file(ev_dir, archive, rec["segment_id"], ".raw")
    if not p:
        return None, None
    with open(p, "rb") as fh:
        fh.seek(rec["offset"]); return fh.read(rec["length"]), where


def covered(commit_dir, seg):
    for f in sorted(glob.glob(os.path.join(commit_dir, "checkpoints", "ckpt_*.json"))):
        try:
            if any(s["segment_id"] == seg for s in json.load(open(f)).get("segments", [])):
                return os.path.basename(f)[:-5]
        except (OSError, ValueError):
            continue
    return None


def trace(event_id, ev_dir, lake_dir, os_url, work, archive=None, commit_dir=None):
    steps, ok_all = [], True

    def step(name, ok, detail, **extra):
        nonlocal ok_all
        ok_all = ok_all and ok
        steps.append({"step": name, "ok": ok, "detail": detail, **extra})
        return ok

    # 1. the SIEM's document
    lin, doc = None, None
    try:
        r = http_json(f"{os_url}/ulpf-ocsf-*/_search", {"query": {"ids": {"values": [event_id]}}, "size": 1})
        hit = (r.get("hits", {}).get("hits") or [None])[0]
        if hit:
            lin, doc = hit["_source"]["_lineage"], hit["_source"]
            step("SIEM document", True, f"index {hit['_index']}, _id {hit['_id']} (= ULPF's event_id); its lineage names raw_hash {lin['raw_hash'][:23]}… at {lin['segment_id']} + {lin['offset']}",
                 document={k: hit["_source"].get(k) for k in ("time", "action_id", "src_endpoint", "dst_endpoint", "class_uid")})
        else:
            step("SIEM document", False, f"no document with _id {event_id} in ulpf-ocsf-*")
    except OSError as e:
        step("SIEM document", False, f"the SIEM did not answer ({e}); continuing from the evidence log alone")
    # 2. the raw bytes, re-hashed
    idx, where = find_record(ev_dir, archive, event_id)
    if not idx:
        step("raw bytes in the evidence log", False, f"{event_id} is not in the evidence index (local buffer{' or the archive' if archive else ''})")
        return {"event_id": event_id, "ok": False, "steps": steps}
    raw, where = read_raw(ev_dir, archive, idx)
    if raw is None:
        step("raw bytes in the evidence log", False, f"{idx['segment_id']} is neither in the local buffer nor in the archive")
        return {"event_id": event_id, "ok": False, "steps": steps}
    h = "sha256:" + hashlib.sha256(raw).hexdigest()
    match = h == idx["raw_hash"] and (lin is None or lin["raw_hash"] == h)
    src = "the EVIDENCE ARCHIVE (the local copy was deleted after shipping)" if where == "archive" else "the local evidence buffer"
    step("raw bytes in the evidence log", match, f"{idx['length']} bytes at {idx['segment_id']} + {idx['offset']}, read from {src}, re-hashed now: {h[:23]}… — "
         + ("equal to the evidence index and to the SIEM document's lineage" if match else "MISMATCH"), raw=raw.decode("utf-8", "replace"), ingest_channel=idx.get("ingest_channel"), peer=idx.get("peer"),
         evidence_source=where)
    # 3. commit (sealed segments), 4. export the bundle, 5. verify it with the public key only
    if commit_dir:   # the always-running committer: wait for the checkpoint that covers the segment (no second committer)
        ck = None
        for _ in range(60):
            ck = covered(commit_dir, idx["segment_id"])
            if ck:
                break
            time.sleep(0.5)
        step("commit", bool(ck), f"{idx['segment_id']} is covered by the signed checkpoint {ck} (the always-running committer; development seam: SEALED, not kernel-IMMUTABLE — said so)" if ck
             else f"no checkpoint covers {idx['segment_id']} after 30 s: is the committer running? ({commit_dir})")
        if not ck:
            return {"event_id": event_id, "ok": False, "steps": steps}
    else:
        env = {**os.environ, "ULPF_COMMIT_SEALED": "1"}
        c = subprocess.run([str(BIN / "ulpf-committer"), "commit", "--evidence", ev_dir, "--key", str(ROOT / "keys" / "dev" / "ulpf-committer-dev.json")], capture_output=True, text=True, env=env, cwd=ROOT)
        step("commit", c.returncode == 0, "signed Merkle checkpoint over the sealed segments (development seam: SEALED, not kernel-IMMUTABLE — said so)" if c.returncode == 0 else (c.stderr or c.stdout)[-300:])
    bundle = Path(work) / f"bundle-{event_id}"
    subprocess.run(["rm", "-rf", str(bundle)])
    extra = (["--commit", commit_dir] if commit_dir else []) + (["--evidence-archive", archive] if archive else [])
    e = subprocess.run([str(BIN / "ulpf-runtime"), "export", "--evidence", ev_dir, *extra, "--event-id", event_id, "--out", str(bundle)], capture_output=True, text=True, cwd=ROOT)
    if e.returncode != 0:
        step("export", False, (e.stderr or e.stdout).strip()[-300:] + " — if the segment is still open it seals within ~2 s: try again")
        return {"event_id": event_id, "ok": False, "steps": steps}
    step("export", True, e.stderr.strip()[-240:])
    v = subprocess.run([str(BIN / "ulpf-verify"), "bundle", "--bundle", str(bundle), "--trust", str(ROOT / "keys" / "trust")], capture_output=True, text=True, cwd=ROOT)
    out = (v.stdout + v.stderr).strip()
    step("Merkle proof verified", v.returncode == 0 and "VERIFY: OK" in out, out.splitlines()[-1] if out else "no output", verifier=out[-800:])
    # 5b. Proof of Derivation: the exact logged pack, re-run on these raw bytes, must reproduce the SIEM's document
    if doc is not None:
        exp = Path(work) / f"expected-{event_id}.json"; exp.write_text(json.dumps(doc), encoding="utf-8")
        bpath = Path(work) / f"derivation-{event_id}.json"
        d = subprocess.run([str(BIN / "ulpf-runtime"), "derive", "--evidence", ev_dir, *extra, "--event-id", event_id, "--expected", str(exp), "--out", str(bpath)],
                           capture_output=True, text=True, cwd=ROOT, env={**os.environ, "ULPF_ROOT": str(ROOT)})
        if d.returncode != 0:
            step("Proof of Derivation", False, (d.stderr or d.stdout).strip()[-300:])
        else:
            vv = subprocess.run([str(BIN / "ulpf-verify"), "derivation", "--bundle", str(bpath), "--trust", str(ROOT / "keys" / "trust"), "--json"],
                                capture_output=True, text=True, cwd=ROOT, env={**os.environ, "ULPF_ROOT": str(ROOT)})
            try:
                rep = json.loads(vv.stdout)
            except ValueError:
                rep = {"ok": False, "steps": [], "culprit": "verifier", "error": (vv.stderr or vv.stdout)[-300:]}
            tl = rep.get("transparency_log") or {}
            e = tl.get("Entry") or {}
            detail = (f"the logged pack {e.get('PackID')} v{e.get('PackVersion')} (entry {tl.get('Index')} of {tl.get('Log')}, {e.get('ProducedBy')}, logged {e.get('LoggedAt')}), re-run on these raw bytes, "
                      f"reproduces the SIEM document field for field (excluded: {', '.join(rep.get('excluded_from_comparison', {}))}) — checked offline by ulpf-verify" if rep.get("ok") else
                      f"FAILED — {rep.get('culprit')}: " + "; ".join(x["name"] + ": " + x["detail"][:120] for x in rep.get("steps", []) if not x["ok"])[:400])
            step("Proof of Derivation", bool(rep.get("ok")), detail, derivation=rep, bundle=str(bpath))
    # 6. the same event in the lake
    try:
        import duckdb
        fs = sorted(glob.glob(os.path.join(lake_dir, "ext", "*", "*", "*", "*", "*.parquet")))
        row = duckdb.connect().execute(f"SELECT event_id, raw_hash, segment_id, \"offset\", filename FROM read_parquet({fs!r}, filename=true) WHERE event_id = ?", [event_id]).fetchone() if fs else None
        if row:
            step("the same event in the lake", row[1] == idx["raw_hash"], f"{os.path.relpath(row[4], lake_dir)}: raw_hash {row[1][:23]}…, {row[2]} + {row[3]} — the lineage survived into Parquet")
        else:
            step("the same event in the lake", False, "not in a Parquet file yet (the lake writer rotates every few seconds) — try again", pending=True)
    except Exception as ex:   # the lake is a separate destination: its absence does not unprove the evidence
        step("the same event in the lake", False, f"{type(ex).__name__}: {ex}")
    return {"event_id": event_id, "ok": ok_all, "steps": steps}


def main():
    ap = argparse.ArgumentParser(description="SIEM finding -> original evidence, provably unaltered")
    ap.add_argument("--event-id"); ap.add_argument("--latest-finding", action="store_true")
    ap.add_argument("--evidence", required=True); ap.add_argument("--lake", required=True); ap.add_argument("--os", default="http://127.0.0.1:9200")
    ap.add_argument("--work", default="/tmp/ulpf-trace")
    ap.add_argument("--archive", help="the evidence archive (read when the local copy was deleted after shipping)")
    ap.add_argument("--commit", help="the always-running committer's commit tree (no committer is started)")
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    eid = a.event_id
    if a.latest_finding:
        fs = findings(a.os)
        if not fs:
            print("no finding yet (the detector runs every minute)"); return 2
        print(f"finding: {fs[0]['rule']} naming {len(fs[0]['event_ids'])} event(s)")
        eid = fs[0]["event_ids"][0]
    t = trace(eid, a.evidence, a.lake, a.os, a.work, a.archive, a.commit)
    for s in t["steps"]:
        print(f"{'OK  ' if s['ok'] else 'FAIL'} {s['step']}: {s['detail']}")
    print(f"TRACE {'OK' if t['ok'] else 'INCOMPLETE'}: {eid}")
    return 0 if t["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
