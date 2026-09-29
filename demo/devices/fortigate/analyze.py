#!/usr/bin/env python3
"""Does the corpus-built FortiGate pack parse a REAL FortiGate's output? (docs/real-device-fortigate.md)

    python3 demo/devices/fortigate/analyze.py --raw capture/all.raw --packs ~/ulpf-demo/p6/source-packs --out analysis/

1. Splits the raw syslog/TCP capture into frames (RFC 6587 octet counting, as the device sends in `reliable` mode) and
   classifies each: the syslog format (default key=value, csv, cef, json, rfc5424) and FortiGate's own type/subtype.
2. Replays each format, byte for byte, over TCP into the real runtime loaded with the corpus-built packs (the golden
   Squid pack, Cisco ASA, PAN-OS and FortiGate — exactly what the demo loads), no learning, no healing.
3. Reports, per format and per FortiGate type/subtype: parsed or quarantined, the quarantine reasons, the parser and
   family that took the line, and whether the event time is right (the device's eventtime, UTC, against the time ULPF
   received it).
Nothing is changed to make the device fit: this measures the pack as it is.
"""
import argparse
import collections
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RT = ROOT / "runtime/bin/ulpf-runtime"


def frames(raw):
    out, i = [], 0
    while i < len(raw):
        m = re.match(rb"(\d+) ", raw[i:i + 12])
        if not m:   # not octet counting here: take a newline-delimited line
            j = raw.find(b"\n", i)
            j = len(raw) if j < 0 else j
            if raw[i:j].strip():
                out.append(raw[i:j])
            i = j + 1
            continue
        n = int(m.group(1)); s = i + len(m.group(0))
        out.append(raw[s:s + n]); i = s + n
    return out


def fmt_of(f):
    body = re.sub(rb"^<\d+>", b"", f)
    if body.startswith(b"1 ") and re.match(rb"1 \d{4}-", body):
        return "rfc5424"
    if b"CEF:" in body[:80]:
        return "cef"
    if body.lstrip().startswith(b"{"):
        return "json"
    if re.match(rb'date=[^ ,]+,time=', body) or body.count(b",") > body.count(b" ") and b'",' in body:
        return "csv"
    return "default"


def kind_of(f):
    t = re.search(rb'(?:type=|"type":\s*|cat=|cs\d?Label=)"?([a-z]+)"?', f)
    st = re.search(rb'(?:subtype=|"subtype":\s*)"?([a-z-]+)"?', f)
    if b"CEF:" in f:   # CEF: the class in the header: CEF:0|Fortinet|Fortigate|v7.4.12|<logid>|<type>:<subtype> ...
        h = f.split(b"|")
        if len(h) > 5:
            return h[5].decode(errors="replace").strip()
    return f"{t.group(1).decode() if t else '?'}:{st.group(1).decode() if st else '?'}"


def replay(fr, packs, work):
    port = 7811
    ev, out, q = work / "ev", work / "out.jsonl", work / "q.jsonl"
    args = [str(RT), "run", "--dev-no-evidence-archive", "--pack", str(ROOT / "contracts/golden/squid-native")]
    for v in ("cisco-asa", "panos", "fortigate"):
        args += ["--pack", str(Path(packs) / v)]
    args += ["--source-id", "fortigate-lab-01", "--listen", f"tcp:127.0.0.1:{port}", "--evidence", str(ev), "--out", str(out), "--quarantine", str(q), "--idle-timeout", "30s"]
    err = open(work / "rt.err", "wb")
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err)
    for _ in range(100):
        if b"listening for syslog over TCP" in (work / "rt.err").read_bytes():
            break
        time.sleep(0.1)
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(b"".join(str(len(f)).encode() + b" " + f for f in fr))
    s.close()
    time.sleep(2)
    p.send_signal(signal.SIGTERM); p.wait(60)
    outs = [json.loads(l) for l in open(out)] if out.exists() else []
    qs = [json.loads(l) for l in open(q)] if q.exists() else []
    return outs, qs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True); ap.add_argument("--packs", default=os.path.expanduser("~/ulpf-demo/p6/source-packs")); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    od = Path(a.out); od.mkdir(parents=True, exist_ok=True)
    fr = frames(Path(a.raw).read_bytes())
    by = collections.defaultdict(list)
    for f in fr:
        by[fmt_of(f)].append(f)
    report = {"frames": len(fr), "formats": {}}
    for fmt, fs in by.items():
        (od / f"{fmt}.frames").write_bytes(b"".join(str(len(f)).encode() + b" " + f for f in fs))
        (od / f"{fmt}.sample.txt").write_bytes(b"\n".join(fs[:6]) + b"\n")
        work = Path(tempfile.mkdtemp(prefix=f"fgt-{fmt}-"))
        outs, qs = replay(fs, a.packs, work)
        kinds = collections.Counter(kind_of(f) for f in fs)
        parsed_kinds = collections.Counter()
        for e in outs:
            parsed_kinds[(e.get("_lineage", {}).get("parser_id"), e.get("_lineage", {}).get("family_id"), e.get("class_uid"))] += 1
        reasons = collections.Counter(f"{x.get('stage')}: {x.get('reason')}" for x in qs)
        detail = collections.Counter((f"{x.get('stage')}: {x.get('reason')}", (x.get("routing_signature") or "")[:160]) for x in qs)
        # time: the device's own eventtime (epoch ns) against ULPF's normalized time (ms, UTC)
        skew = []
        for e in outs:
            lin = e.get("_lineage", {})
            if e.get("time") and lin.get("ingest_time"):
                skew.append(round((lin["ingest_time"] - e["time"]) / 1000, 1))
        ocsf_fields = collections.Counter()
        for e in outs:
            for k, v in e.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, dict):
                    for kk in v:
                        ocsf_fields[f"{k}.{kk}"] += 1
                else:
                    ocsf_fields[k] += 1
        report["formats"][fmt] = {"frames": len(fs), "fortigate_kinds": dict(kinds), "parsed": len(outs), "quarantined": len(qs),
                                  "parsed_by": {f"{k[0]} / {k[1]} / class {k[2]}": v for k, v in parsed_kinds.items()},
                                  "quarantine_reasons": dict(reasons), "quarantine_detail": [{"reason": r, "routing_signature": d, "n": n} for (r, d), n in detail.most_common(8)],
                                  "ingest_minus_event_time_s": {"min": min(skew), "max": max(skew)} if skew else None,
                                  "ocsf_fields_filled": dict(ocsf_fields.most_common(40)), "first_parsed": outs[0] if outs else None,
                                  "first_quarantined": qs[0] if qs else None}
        print(f"{fmt:8} frames {len(fs):5}  parsed {len(outs):5}  quarantined {len(qs):5}  kinds {dict(kinds)}  reasons {dict(reasons)}  "
              f"time skew {report['formats'][fmt]['ingest_minus_event_time_s']}", flush=True)
    (od / "report.json").write_text(json.dumps(report, indent=1, default=str) + "\n")
    print("report:", od / "report.json")


if __name__ == "__main__":
    main()
