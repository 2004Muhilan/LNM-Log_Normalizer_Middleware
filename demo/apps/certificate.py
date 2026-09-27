#!/usr/bin/env python3
"""A DRAFT certificate under Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 (BSA), for one log event, printable
from the "Prove it" view — with a technical report for the expert. Standard library only.

What this produces, and what it does not:
  * Part A is PRE-FILLED with what ULPF knows: the source device and its identifiers, how the record was produced and
    stored, the hash algorithm and the hash values. The declarant's name, capacity, affirmations, signature, date and
    place are LEFT BLANK: a person produces the record and affirms Part A, not software.
  * Part B (the expert's certificate) is LEFT BLANK. An expert must review and sign it. Nothing is auto-signed, and the
    document says on every page that it is not complete without that signature.
  * The structure follows the Schedule to the BSA as the authors understand it; check the official text before use.
    This is not legal advice.
"""
import html
import json
import time


def esc(x):
    return html.escape("" if x is None else str(x))


def ts(ms):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime((ms or 0) / 1000)) if ms else "—"


CSS = """
body{font:11pt/1.45 Georgia,'Times New Roman',serif;color:#111;background:#fff;max-width:800px;margin:24px auto;padding:0 16px}
h1{font-size:15pt;margin:0 0 4px}h2{font-size:12.5pt;margin:22px 0 6px;border-bottom:1px solid #999;padding-bottom:2px}h3{font-size:11pt;margin:14px 0 4px}
.banner{border:3px solid #b00;color:#b00;padding:10px 12px;margin:12px 0;font-weight:bold;font-family:Arial,sans-serif;font-size:10pt}
.note{border:1px solid #888;padding:8px 12px;margin:12px 0;font-size:9.5pt;font-family:Arial,sans-serif;background:#f6f6f6}
table{border-collapse:collapse;width:100%;margin:4px 0}td,th{border:1px solid #bbb;padding:4px 6px;vertical-align:top;text-align:left;font-size:10pt}th{width:34%;background:#f3f3f3;font-weight:normal}
.mono{font-family:Consolas,'Courier New',monospace;font-size:9pt;word-break:break-all}.blank{height:1.6em;border-bottom:1px solid #333}
.sig{height:3.2em;border-bottom:1px solid #333}.ok{color:#060}.bad{color:#b00}pre{white-space:pre-wrap;word-break:break-all;background:#f6f6f6;padding:6px;font-size:8.5pt}
@media print{.noprint{display:none}body{margin:0}h2{page-break-after:avoid}.pb{page-break-before:always}}
"""


def render(event_id, trace, record, device, doc, archive_note, process):
    steps = {s["step"]: s for s in trace.get("steps", [])}
    der = (steps.get("Proof of Derivation") or {}).get("derivation") or {}
    tl = der.get("transparency_log") or {}
    entry = tl.get("Entry") or {}
    lin = (doc or {}).get("_lineage", {})
    raw_step = steps.get("raw bytes in the evidence log", {})
    raw_text = raw_step.get("raw") or ""
    merkle = steps.get("Merkle proof verified", {})
    commit = steps.get("commit", {})
    lake = steps.get("the same event in the lake", {})
    all_ok = bool(trace.get("ok"))
    rows = lambda pairs: "".join(f"<tr><th>{esc(k)}</th><td>{v}</td></tr>" for k, v in pairs)
    blank = '<div class="blank"></div>'
    now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    partA = rows([
        ("Electronic record", f"One log event received by ULPF (event id <span class=mono>{esc(event_id)}</span>), {esc(record.get('length'))} bytes, received {esc(ts(record.get('ingest_time')))}"),
        ("The record (as received, byte-exact)", f"<pre>{esc(raw_text)}</pre>"),
        ("Produced by (device / application)", f"{esc(device.get('name', 'unknown application'))}<br>vendor {esc(device.get('vendor', '—'))}, product {esc(device.get('product', '—'))}"),
        ("Identifiers of the source", f"source id <span class=mono>{esc(device.get('source_id') or lin.get('source_id'))}</span>; sender address <span class=mono>{esc(record.get('peer'))}</span>; "
                                      f"connector <span class=mono>{esc(record.get('ingest_channel'))}</span>"),
        ("Received and stored by", f"ULPF runtime process {esc(process)} (collector <span class=mono>{esc(record.get('collector_id'))}</span>), evidence store <span class=mono>{esc(lin.get('store_id'))}</span>, "
                                   f"segment <span class=mono>{esc(record.get('segment_id'))}</span> at byte offset {esc(record.get('offset'))}"),
        ("How the record was produced and kept", "Received over the network by ULPF; its bytes were written to an append-only evidence segment and made durable on disk (fsync) "
                                                 "BEFORE any interpretation; the segment was sealed, committed in a Merkle tree under a signed checkpoint, and "
                                                 + esc(archive_note)),
        ("Hash algorithm", "SHA-256"),
        ("Hash value of the record", f"<span class=mono>{esc(record.get('raw_hash'))}</span>"),
        ("Hash values that commit it", f"segment root and signed checkpoint: {esc((merkle.get('detail') or '')[:260])}<br>{esc(commit.get('detail') or '')}"),
    ])
    declar = rows([
        ("Name of the person producing the record", blank), ("Capacity / designation", blank),
        ("Affirmation that the device/system was in lawful control and operating properly during the relevant period, and "
         "that the record was produced in its ordinary course", '<div class="sig"></div><span style="font-size:9pt">[to be affirmed by the person — ULPF cannot affirm this]</span>'),
        ("Signature", '<div class="sig"></div>'), ("Date", blank), ("Place", blank)])
    partB = rows([
        ("Name of the expert", blank), ("Qualification / designation", blank),
        ("Hash value(s) obtained by the expert and the algorithm used", '<div class="sig"></div>'),
        ("Opinion / certification by the expert", '<div class="sig"></div><div class="sig"></div>'),
        ("Signature of the expert", '<div class="sig"></div>'), ("Date", blank), ("Place", blank)])
    der_rows = rows([
        ("Result", f"<b class={'ok' if der.get('ok') else 'bad'}>{'the derivation reproduces the SIEM document' if der.get('ok') else 'FAILED — ' + esc(der.get('culprit'))}</b>"),
        ("Parser pack", f"{esc(entry.get('PackID'))} v{esc(entry.get('PackVersion'))}<br><span class=mono>{esc(entry.get('PackSHA256'))}</span><br>produced: {esc(entry.get('ProducedBy'))}; signed by {esc(entry.get('SignedBy'))}"),
        ("Parser transparency log", f"entry {esc(tl.get('Index'))} of log <span class=mono>{esc(tl.get('Log'))}</span>, logged {esc(entry.get('LoggedAt'))}; checkpoint size {esc((tl.get('Checkpoint') or {}).get('Size'))}; "
                                    f"witness cosignatures: {esc(', '.join(tl.get('Witnesses') or []) or 'none')}"),
        ("Engine", esc(der.get("engine"))),
        ("Fields excluded from the comparison", "<br>".join(f"<span class=mono>{esc(k)}</span> — {esc(v)}" for k, v in (der.get("excluded_from_comparison") or {}).items())),
        ("Steps", "<br>".join(f"<span class={'ok' if s['ok'] else 'bad'}>{'✓' if s['ok'] else '✗'}</span> [{esc(s['part'])}] {esc(s['name'])}: {esc(s['detail'][:200])}" for s in der.get("steps", []))),
    ])
    chain = "".join(f"<li><span class={'ok' if s['ok'] else 'bad'}>{'✓' if s['ok'] else '✗'}</span> <b>{esc(s['step'])}</b>: {esc(s['detail'][:400])}</li>" for s in trace.get("steps", []))
    bundle = (steps.get("Proof of Derivation") or {}).get("bundle") or "derivation-" + event_id + ".json"
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><title>BSA 63(4) draft — {esc(event_id)}</title><style>{CSS}</style></head><body>
<div class="noprint" style="text-align:right;font-family:Arial,sans-serif;font-size:10pt"><button onclick="print()">Print</button></div>
<h1>Certificate under Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 — DRAFT</h1>
<div style="font-family:Arial,sans-serif;font-size:9.5pt">electronic record: log event <span class=mono>{esc(event_id)}</span> · generated by ULPF {esc(now)}</div>
<div class="banner">NOT COMPLETE. This draft was generated by software and is not signed. Part A's declaration must be affirmed and signed by the
person producing the record, and Part B must be reviewed, completed and signed by an expert. It has no effect as a certificate until then.</div>
<div class="note"><b>Not legal advice.</b> The Part A / Part B structure follows the Schedule to the Bharatiya Sakshya Adhiniyam, 2023, as its authors
understand it. Check it against the official text, and take legal advice, before relying on it.</div>
<h2>Part A — particulars of the electronic record (pre-filled from ULPF's records)</h2><table>{partA}</table>
<h3>Declaration (to be completed by the person producing the record)</h3><table>{declar}</table>
<h2>Part B — certificate of the expert (left blank: to be completed and signed by the expert)</h2><table>{partB}</table>
<div class="banner">Part B is blank by design: ULPF never signs it and never presents this certificate as complete.</div>
<h2 class="pb">Technical report for the expert</h2>
<p>Every statement below can be re-checked offline, with no network and no ULPF running, from the derivation bundle
<span class=mono>{esc(bundle.rsplit('/', 1)[-1])}</span> and the public keys of the trust store.</p>
<h3>1. The evidence chain</h3><ol>{chain}</ol>
<h3>2. The derivation — the exact parser, re-run</h3><table>{der_rows}</table>
<h3>3. How to verify (offline)</h3>
<pre>sha256 of the record's bytes           -> must equal {esc(record.get('raw_hash'))}
ulpf-verify derivation --bundle {esc(bundle.rsplit('/', 1)[-1])} --trust keys/trust
    the raw bytes hash to the evidence record; the record is in the segment index the signed checkpoint commits;
    the Merkle proof reaches the committed segment root; the checkpoint's signature verifies;
    the pack is the entry of the parser transparency log its proof names (c2sp.org/tlog-proof, offline);
    the pack re-run on the raw bytes reproduces the SIEM document, field for field, except the excluded field(s).
    On failure it names the part: the raw bytes, the pack, or the SIEM document.</pre>
<h3>4. Limits, stated</h3><ul>
<li>Demonstration keys: the signing, committer, log and witness keys are development keys generated on this machine.</li>
<li>The witness runs on the same machine as the log in this demonstration; it stands in for an independent site. Real deployments put witnesses on separate machines.</li>
<li>The demonstration commits sealed segments without the kernel immutable flag (development mode, stated in the checkpoint as <span class=mono>sealed_only_dev</span>).</li>
<li>The evidence archive in the demonstration is a plain folder: tampering there is detected by the proofs, not prevented; prevention needs write-once storage.</li>
<li>{esc((lake.get('detail') or '')[:200])}</li></ul>
<div class="banner">DRAFT — NOT COMPLETE WITHOUT THE SIGNATURES ABOVE. Not legal advice.</div>
</body></html>"""
