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
    print(f"source {st['source_id']}  state: {st['state']}  samples: {st['sample_count']}  arity: {st['structure']['arity']}" + (f"  family: {st['family_id']}" if st.get("family_id") else ""))
    if st.get("propagated"):
        print(f"propagated: {len(st['propagated'])} slot(s) resolved from {sorted({h['from_family'] for h in st['propagated']})} under the §4.4 key — no request issued for them")
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
    o.add_argument("--provider", choices=["fixture", "model", "recorded"], default="fixture", help="fixture (default; the P3 path, unchanged), model (P4: llama-server), or recorded (P6: replay a spike recording of the model's proposals)")
    o.add_argument("--recording", help="with --provider recorded: spike/results/<machine>/<model>__<backend>__<case>__<mode>.json")
    o.add_argument("--propagation-store", help="P6: JSON store of resolutions for this operator; hits resolve slots under the §4.4 key before any request is issued")
    os_ = sub.add_parser("onboard-spec", help="P6: onboard a source whose structure is a given spec (csv/kv/regex drafts); the model labels the spec's fields")
    for name, kw in (("--samples", {}), ("--spec", {}), ("--source-id", {}), ("--operator", {}), ("--session", {}), ("--vendor", {}), ("--family-id", {})):
        os_.add_argument(name, required=True, **kw)
    os_.add_argument("--unwrap-envelope", action="store_true", help="samples still carry their syslog header: strip one level exactly as the runtime does")
    os_.add_argument("--provider", choices=["fixture", "model", "recorded"], default="recorded"); os_.add_argument("--recording"); os_.add_argument("--fixture")
    os_.add_argument("--model-id"); os_.add_argument("--server", default="http://127.0.0.1:8080"); os_.add_argument("--mode", choices=["whole", "per-slot"], default="whole"); os_.add_argument("--backend", default="unknown")
    os_.add_argument("--propagation-store")
    o.add_argument("--model-id", help="manifest id; the weights digest is verified before any call"); o.add_argument("--server", default="http://127.0.0.1:8080")
    o.add_argument("--mode", choices=["whole", "per-slot"], default="whole"); o.add_argument("--backend", default="unknown", help="recorded in provenance, e.g. 'cuda ngl=all' or 'cpu'")
    for name in ("status", "certificates", "review"):
        p = sub.add_parser(name); p.add_argument("--session", required=True)
    r = sub.add_parser("respond"); r.add_argument("--session", required=True); r.add_argument("--discriminator", required=True); r.add_argument("--input", required=True)
    r.add_argument("--field"); r.add_argument("--attribute"); r.add_argument("--initiator-ip"); r.add_argument("--sample-line")
    pr = sub.add_parser("promote"); pr.add_argument("--session", required=True); pr.add_argument("--out", required=True); pr.add_argument("--pack-id", required=True)
    mg = sub.add_parser("merge", help="P6: merge promoted single-family packs of one source into a signed source pack (anchors from the vendor table)")
    mg.add_argument("packs", nargs="+"); mg.add_argument("--out", required=True); mg.add_argument("--pack-id", required=True); mg.add_argument("--vendor")
    a = ap.parse_args(argv)

    if a.cmd in ("onboard", "onboard-spec"):
        from .provider import FixtureProvider, RecordedProvider
        s = Session(Path(a.session))
        prov = FixtureProvider(Path(a.fixture)) if a.fixture else None
        if a.provider == "recorded":
            if not a.recording:
                ap.error("--recording is required with --provider recorded")
            prov = RecordedProvider(Path(a.recording))
        if a.provider == "model":
            from .model.client import LlamaClient
            from .model.provider import ModelProvider, verified_model_hash
            if not a.model_id:
                ap.error("--model-id is required with --provider model")
            client = LlamaClient(a.server)
            client.wait_ready(60)
            prov = ModelProvider(client, a.model_id, verified_model_hash(a.model_id), mode=a.mode, backend=a.backend)
        store = Path(a.propagation_store) if a.propagation_store else None
        if a.cmd == "onboard":
            s.onboard(Path(a.samples), a.source_id, a.operator, prov, a.vendor, propagation_store=store)
        else:
            s.onboard_spec(Path(a.samples), Path(a.spec), a.source_id, a.operator, a.vendor, a.family_id, prov, a.unwrap_envelope, propagation_store=store)
        show_status(s)
        return 0
    if a.cmd == "merge":
        from .anchors import load_declared
        from .discriminators import load_vendor_table
        from .sourcepack import merge
        anchors = load_declared(load_vendor_table(a.vendor)) if a.vendor else []
        out = merge([Path(p) for p in a.packs], Path(a.out), a.pack_id, anchors)
        print("merged:", out)
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
