#!/usr/bin/env python3
"""Log inspector: for EVERY log ULPF received — what arrived, and what ULPF made of it. Standard library only, offline,
read-only: it reads the evidence store and the files a run wrote; it never writes and never parses a log itself.

    python3 demo/inspect-logs.py --evidence EV --run RUN_DIR [--run RUN_DIR ...] [--port 8770]     # a page
    python3 demo/inspect-logs.py --evidence EV --run RUN_DIR --event-id ev_…                        # one log, as JSON
    python3 demo/inspect-logs.py --evidence EV --out OUT.jsonl --quarantine Q.jsonl                   # explicit files

A RUN_DIR holds out.jsonl (normalized events) and q.jsonl (quarantine records), e.g. ~/ulpf-demo/live/run-1 or, for the
six-step demo, --evidence ~/ulpf-demo/ev --out ~/ulpf-demo/step5/out.jsonl --quarantine ~/ulpf-demo/step5/q.jsonl.

For each log it shows:
  RAW        the exact bytes from the evidence segment (re-hashed here and compared with the recorded raw_hash), their
             length, where they are stored (segment, offset), when and how they arrived (ingest channel, peer, framing)
  FORMAT     what the runtime detected: the transport/application envelope chain (syslog RFC 3164 / 5424, CEF, LEEF),
             the payload surface (JSON, XML, key=value, CSV, positional tokens), the arity / token-class sketch
  PARSED     the pack, family and parser that handled it, and the normalized OCSF event with its lineage —
             or, when it was quarantined, the stage and the reason (the bytes are kept either way)
"""
import argparse
import base64
import glob
import hashlib
import html
import http.server
import json
import os
import sys
from urllib.parse import parse_qs, urlparse

ENVELOPES = {"raw": "no envelope", "none": "no envelope", "rfc3164": "syslog RFC 3164", "rfc5424": "syslog RFC 5424", "cef": "CEF header", "leef": "LEEF header"}
SURFACES = {"tokens": "positional / free text (whitespace tokens)", "kv": "key=value pairs", "csv": "CSV", "json": "JSON", "xml": "XML", "positional": "positional", "template": "message template"}


def read_jsonl(path):
    rows = []
    if path and os.path.exists(path):
        for l in open(path, encoding="utf-8", errors="replace"):
            try:
                rows.append(json.loads(l))
            except ValueError:
                pass   # the last line of a file still being written
    return rows


class Store:
    def __init__(self, evidence, outs, quars):
        self.evidence, self.outs, self.quars = evidence, outs, quars

    def load(self):
        idx = {}
        for f in sorted(glob.glob(os.path.join(self.evidence, "seg_*.idx.jsonl"))):
            for r in read_jsonl(f):
                idx[r["event_id"]] = r
        events = {e["_lineage"]["event_id"]: e for p in self.outs for e in read_jsonl(p) if "_lineage" in e}
        quar = {q["event_id"]: q for p in self.quars for q in read_jsonl(p)}
        return idx, events, quar

    def raw(self, rec):
        try:
            with open(os.path.join(self.evidence, rec["segment_id"] + ".raw"), "rb") as f:
                f.seek(rec["offset"]); return f.read(rec["length"])
        except OSError:
            return None

    def describe(self, event_id):
        idx, events, quar = self.load()
        rec = idx.get(event_id)
        if rec is None:
            return None
        ev, q = events.get(event_id), quar.get(event_id)
        raw = self.raw(rec)
        lin = (ev or {}).get("_lineage", {})
        sig = lin.get("routing_signature") or (q or {}).get("routing_signature") or ""
        parts = sig.split("|")
        env = lin.get("envelope") or {}
        chain = [e.get("kind") for e in lin.get("relay_chain", [])] or ([env["kind"]] if env.get("kind") else ([parts[0]] if parts and parts[0] else []))
        is_record = rec["framing"].get("method") == "gap_record"
        text = raw.decode("utf-8", "replace") if raw is not None else None
        return {
            "event_id": event_id,
            "raw": {"text": text, "base64": base64.b64encode(raw).decode() if raw is not None else None, "bytes": rec["length"], "raw_hash": rec["raw_hash"],
                    "hash_verified_now": raw is not None and "sha256:" + hashlib.sha256(raw).hexdigest() == rec["raw_hash"],
                    "stored_at": {"segment": rec["segment_id"], "offset": rec["offset"]}, "ingest_time_ms": rec.get("ingest_time"), "ingest_channel": rec.get("ingest_channel"),
                    "peer": rec.get("peer"), "source_id": rec.get("source_id"), "collector_id": rec.get("collector_id"), "framing": rec["framing"]},
            "format": {"kind": "evidence-log record (not a received log)" if is_record else None,
                       "envelope_chain": [ENVELOPES.get(k, k) for k in chain] or ["no envelope"], "envelope": env or None,
                       "payload_surface": SURFACES.get(parts[1], parts[1]) if len(parts) > 1 else None, "anchors": parts[2] if len(parts) > 2 and parts[2] else None,
                       "arity": parts[3] if len(parts) > 3 else None, "token_classes": parts[4].split(",") if len(parts) > 4 and parts[4] else None, "routing_signature": sig or None},
            "parsed": ({"status": "normalized", "pack": lin.get("parser_id"), "pack_version": lin.get("parser_version"), "family": lin.get("family_id"), "ocsf_class_uid": ev.get("class_uid"),
                        "normalization_version": lin.get("normalization_version"), "event": {k: v for k, v in ev.items() if k != "_lineage"}, "lineage": lin} if ev else
                       {"status": "quarantined — bytes kept, nothing guessed", "stage": q["stage"], "reason": q["reason"]} if q else
                       {"status": "evidence-log record" if is_record else "not processed yet (or the run's files were not given)"}),
        }

    def listing(self, limit):
        idx, events, quar = self.load()
        rows = []
        for eid in sorted(idx, reverse=True)[:limit]:
            rec, ev, q = idx[eid], events.get(eid), quar.get(eid)
            sig = ((ev or {}).get("_lineage", {}).get("routing_signature") or (q or {}).get("routing_signature") or "").split("|")
            fmt = " → ".join(x for x in (ENVELOPES.get(sig[0], sig[0]) if sig and sig[0] not in ("", "raw") else "", SURFACES.get(sig[1], sig[1]).split(" (")[0] if len(sig) > 1 else "") if x)
            rows.append({"event_id": eid, "channel": rec.get("ingest_channel"), "bytes": rec["length"], "format": fmt or ("record" if rec["framing"].get("method") == "gap_record" else "?"),
                         "outcome": (ev["_lineage"].get("parser_id", "") + " / " + ev["_lineage"].get("family_id", "")) if ev else ("QUARANTINED: " + q["stage"]) if q else "—", "quarantined": bool(q)})
        return {"total": len(idx), "normalized": len(events), "quarantined": len(quar), "rows": rows}


PAGE = """<!doctype html><meta charset=utf-8><title>ULPF — log inspector</title>
<style>body{margin:0;padding:24px 32px;background:#fff;color:#000;font:18px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif}h1{font-size:1.4rem;margin:0 0 12px}h2{font-size:1.05rem;margin:18px 0 6px}
.wrap{display:flex;gap:28px;align-items:flex-start}.list{flex:0 0 46%;max-height:86vh;overflow:auto}.detail{flex:1;min-width:0}table{border-collapse:collapse;width:100%;font-size:.9rem}
td,th{text-align:left;padding:5px 10px 5px 0;border-bottom:1px solid #ddd}th{color:#666;font-weight:400}tr.sel{background:#eee}tr{cursor:pointer}.red{color:#c00000}.muted{color:#666}
pre{background:#f4f4f4;padding:10px;white-space:pre-wrap;word-break:break-all;font:.88rem ui-monospace,Consolas,monospace;margin:0}.kv td:first-child{color:#666;width:11em}</style>
<h1>ULPF — log inspector <span class=muted id=tot style="font-weight:400;font-size:1rem"></span></h1>
<div class=wrap><div class=list><table><thead><tr><th>event</th><th>arrived on</th><th>format</th><th>outcome</th></tr></thead><tbody id=rows></tbody></table></div><div class=detail id=d><p class=muted>choose a log</p></div></div>
<script>
const esc=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));let sel=null;
const kv=o=>'<table class=kv>'+Object.entries(o).filter(([k,v])=>v!=null&&v!=='').map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(typeof v==='object'?JSON.stringify(v):v)}</td></tr>`).join('')+'</table>';
async function list(){const d=await (await fetch('/api/list')).json();tot.textContent=`· ${d.total} records · ${d.normalized} normalized · ${d.quarantined} quarantined`;
rows.innerHTML=d.rows.map(r=>`<tr data-id="${r.event_id}" class="${r.event_id===sel?'sel':''}"><td>${esc(r.event_id.slice(-8))}</td><td>${esc(r.channel)}</td><td>${esc(r.format)}</td><td class="${r.quarantined?'red':''}">${esc(r.outcome)}</td></tr>`).join('');
for(const tr of rows.querySelectorAll('tr'))tr.onclick=()=>show(tr.dataset.id)}
async function show(id){sel=id;const x=await (await fetch('/api/event?id='+encodeURIComponent(id))).json();const r=x.raw,f=x.format,p=x.parsed;
d.innerHTML=`<h2>Raw log — exactly as received</h2><pre>${esc(r.text)}</pre>`+kv({bytes:r.bytes,'raw hash':r.raw_hash,'hash re-checked now':r.hash_verified_now?'matches':'DOES NOT MATCH','stored at':r.stored_at.segment+' @ '+r.stored_at.offset,'arrived on':r.ingest_channel,peer:r.peer,'framing':r.framing.method+(r.framing.truncation_status!=='none'?' ('+r.framing.truncation_status+')':''),'ingest time (ms)':r.ingest_time_ms})+
`<h2>Format — what the runtime detected</h2>`+kv({'':f.kind,'envelope':f.envelope_chain.join(' → '),'payload':f.payload_surface,'anchors':f.anchors,'arity':f.arity,'token classes':f.token_classes&&f.token_classes.join(' '),'envelope fields':f.envelope})+
`<h2>Parsed / normalized</h2>`+(p.event?kv({pack:p.pack+' v'+p.pack_version,family:p.family,'OCSF class':p.ocsf_class_uid,'normalization version':p.normalization_version})+`<pre>${esc(JSON.stringify(p.event,null,1))}</pre><h2>Lineage</h2><pre>${esc(JSON.stringify(p.lineage,null,1))}</pre>`:`<p class="${p.stage?'red':''}"><b>${esc(p.status)}</b></p>`+kv({stage:p.stage,reason:p.reason}));list()}
list();setInterval(list,1500)</script>"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--evidence", required=True); ap.add_argument("--run", action="append", default=[]); ap.add_argument("--out", action="append", default=[]); ap.add_argument("--quarantine", action="append", default=[])
    ap.add_argument("--event-id"); ap.add_argument("--port", type=int, default=8770); ap.add_argument("--bind", default="127.0.0.1"); ap.add_argument("--limit", type=int, default=300)
    a = ap.parse_args()
    ev = os.path.expanduser(a.evidence)
    store = Store(ev, [os.path.expanduser(p) for p in a.out] + [os.path.join(os.path.expanduser(r), "out.jsonl") for r in a.run],
                  [os.path.expanduser(p) for p in a.quarantine] + [os.path.join(os.path.expanduser(r), "q.jsonl") for r in a.run])
    if a.event_id:
        d = store.describe(a.event_id)
        print(json.dumps(d, indent=1) if d else f"no evidence record {a.event_id}")
        return 0 if d else 1

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/api/list":
                body, ct = json.dumps(store.listing(a.limit)).encode(), "application/json"
            elif u.path == "/api/event":
                body, ct = json.dumps(store.describe(parse_qs(u.query).get("id", [""])[0])).encode(), "application/json"
            else:
                body, ct = PAGE.encode(), "text/html; charset=utf-8"
            self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

        def log_message(self, *x):
            pass
    print(f"log inspector: http://localhost:{a.port}/  (evidence: {ev})", flush=True)
    try:
        http.server.ThreadingHTTPServer((a.bind, a.port), H).serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
