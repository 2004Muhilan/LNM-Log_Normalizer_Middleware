"""Certificate review interface — the surface on which the evidence request and its resolution happen.

    python -m ulpf_learn onboard --samples F --source-id S --operator O --session DIR
    python -m ulpf_learn status --session DIR
    python -m ulpf_learn certificates --session DIR
    python -m ulpf_learn respond --session DIR --discriminator device_logformat_configuration --input "logformat ..."
    python -m ulpf_learn promote --session DIR --out PACKDIR --pack-id ID
    python -m ulpf_learn review --session DIR          # interactive: shows the request, reads the response, loops
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .session import Session


def show_status(s: Session):
    st = s.state
    print(f"source {st['source_id']}  state: {st['state']}  samples: {st['sample_count']}  arity: {st['structure']['arity']}")
    v = st.get("verdict", {})
    print(f"promotable: {v.get('promotable')}  critical coverage: {v.get('critical_coverage', 0):.2f}  semantic coverage: {v.get('coverage', {}).get('semantic_coverage', 0):.2f}")
    for b in v.get("blockers", []):
        print("  blocker:", b)
    req = st.get("pending_request")
    if req:
        print("\nREQUEST")
        print("  " + req["text"])
        print(f"  discriminator: {req['discriminator_id']}  resolves: {', '.join(req['resolves'])}")
        for a in req.get("alternatives", []):
            print(f"  alternative rank {a['rank']}: {a['discriminator_id']} ({a['cost_tier']}) resolves {', '.join(a['resolves'])}")
    print("\nmetrics:", json.dumps(s.metrics()))


def show_certificates(s: Session):
    for cid, c in s.state["certificates"].items():
        print(f"{cid}: field {c['field']['path']} slot {c['context']['slot_index'] + 1} [{c['context']['token_class']}] status={c['status']}")
        print("   candidates: " + " > ".join(f"{r['rank']}. {r['attribute']} ({r['proposed_by']})" for r in c["ranked_candidates"]))
        e = c["evidence"]
        print(f"   evidence: vendor_metadata={e['vendor_metadata']} structural={e['structural']['status']} held_out={e['held_out_consistency']} type={e['type_validity']} discriminator={e['discriminator']['status']}"
              + (f" ({e['discriminator']['ambiguity_class']})" if e['discriminator']['status'] == 'available' else ""))
        print(f"   enumeration: {len(c['enumeration']['candidates'])} candidates, {len(c['enumeration']['survivors'])} survivors over table {c['enumeration']['table_hash'][:19]}…")
        if c["status"] == "unresolved":
            print(f"   UNRESOLVED: {c['unresolved_reason']} — no guess is made")
        if c["status"] == "resolved":
            r = c["resolution"]
            print(f"   resolved -> {r['resolved_to']} via {r['discriminator_id']} ({r['provenance']}) by {r['operator_id']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ulpf_learn")
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("onboard"); o.add_argument("--samples", required=True); o.add_argument("--source-id", required=True); o.add_argument("--operator", required=True); o.add_argument("--session", required=True); o.add_argument("--fixture"); o.add_argument("--vendor", default="squid")
    o.add_argument("--provider", choices=["fixture", "model"], default="fixture", help="fixture (default; the P3 path, unchanged) or model (P4: llama-server)")
    o.add_argument("--model-id", help="manifest id; the weights digest is verified before any call"); o.add_argument("--server", default="http://127.0.0.1:8080")
    o.add_argument("--mode", choices=["whole", "per-slot"], default="whole"); o.add_argument("--backend", default="unknown", help="recorded in provenance, e.g. 'cuda ngl=all' or 'cpu'")
    for name in ("status", "certificates", "review"):
        p = sub.add_parser(name); p.add_argument("--session", required=True)
    r = sub.add_parser("respond"); r.add_argument("--session", required=True); r.add_argument("--discriminator", required=True); r.add_argument("--input", required=True)
    r.add_argument("--field"); r.add_argument("--attribute"); r.add_argument("--initiator-ip"); r.add_argument("--sample-line")
    pr = sub.add_parser("promote"); pr.add_argument("--session", required=True); pr.add_argument("--out", required=True); pr.add_argument("--pack-id", required=True)
    a = ap.parse_args(argv)

    if a.cmd == "onboard":
        from .provider import FixtureProvider
        s = Session(Path(a.session))
        prov = FixtureProvider(Path(a.fixture)) if a.fixture else None
        if a.provider == "model":
            from .model.client import LlamaClient
            from .model.provider import ModelProvider, verified_model_hash
            if not a.model_id:
                ap.error("--model-id is required with --provider model")
            client = LlamaClient(a.server)
            client.wait_ready(60)
            prov = ModelProvider(client, a.model_id, verified_model_hash(a.model_id), mode=a.mode, backend=a.backend)
        s.onboard(Path(a.samples), a.source_id, a.operator, prov, a.vendor)
        show_status(s)
        return 0
    s = Session.load(Path(a.session))
    if a.cmd == "status":
        show_status(s)
    elif a.cmd == "certificates":
        show_certificates(s)
    elif a.cmd == "respond":
        text = Path(a.input[1:]).read_text() if a.input.startswith("@") else a.input
        s.respond(a.discriminator, text, field=a.field, attribute=a.attribute, initiator_ip=a.initiator_ip, sample_line=a.sample_line)
        show_status(s)
    elif a.cmd == "promote":
        p = s.promote(Path(a.out), a.pack_id)
        print("promoted:", p)
        print("metrics:", json.dumps(s.metrics()))
    elif a.cmd == "review":
        while s.state["state"] == "awaiting_evidence":
            show_certificates(s)
            show_status(s)
            req = s.state["pending_request"]
            print(f"\nEnter evidence for {req['discriminator_id']} (or 'q' to stop):")
            line = sys.stdin.readline().strip()
            if not line or line == "q":
                return 1
            s.respond(req["discriminator_id"], line)
        show_status(s)
    return 0
