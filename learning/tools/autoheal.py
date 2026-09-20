"""Automatic drift healing for a source that is ALREADY ONBOARDED — with an alert that is the audit trail.

    python tools/autoheal.py heal --source-id S --signature SIG --run-dir RUN [--run-dir RUN ...] --evidence EV \
        --family-pack PACK [--family-pack PACK ...] --propagation-store STORE --work DIR --packs-file FILE [--runtime-pid PID]
        [--provider model --model-id M --server URL | --provider fixture --fixture F] [--vendor V --product P]
    python tools/autoheal.py rollback --alert ALERT.json --packs-file FILE [--runtime-pid PID]

THE POLICY (2026-09-20; supersedes "a human re-onboards" for this one case):
  * Healing is automatic ONLY for drift on a source that a human already onboarded (Tier 1) AND only when the drifted
    traffic is bound to that source: every sampled event must have arrived on an ingest channel and from a peer host that
    has already delivered events this source's families emitted. "Already onboarded" alone is not enough — anything that
    can reach the listener could otherwise send a look-alike format and inherit the operator's old answers by column
    position. (The binding is as strong as the transport: plain syslog/TCP and HTTP authenticate nobody; say so.)
  * A field is promoted automatically only on SUFFICIENT provenance — here: propagation of an earlier resolution under the
    §4.4 key (same source, same slot, same class), or a vendor table. A model proposal is never sufficient (invariant 4
    is untouched), for a mandatory field or any other: what rests on a proposal alone is WITHHELD — carried unmapped, its
    certificate retained — and the operator is asked. Picking a candidate for an ambiguous field would be a guess.
  * If a MANDATORY attribute is among what did not resolve, nothing can be promoted (the acceptance policy is unchanged):
    the alert says so and the operator is asked before any event of the new format is normalized.
  * The pack is activated by hot reload (the runtime records `pack_activated` in the evidence log, naming the pack's
    sha256); the ALERT written here names the same sha256 and records what changed, what propagated, what the model
    proposed, what was promoted, what was withheld and why, the new and the previous pack, and the rollback command.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import drift  # noqa: E402

POLICY_VERSION = "autoheal-1.0"


def _sha(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def _idx(evidence: Path) -> dict[str, dict]:
    out = {}
    for f in sorted(evidence.glob("seg_*.idx.jsonl")):
        for r in drift._read_jsonl(f):
            out[r.get("event_id", "")] = r
    return out


def source_binding(run_dirs: list[Path], evidence: Path, source_pack_id: str, drifted_ids: list[str]) -> dict:
    """(ingest_channel, peer host) of the drifted events must be a subset of those that already delivered this source's events."""
    idx = _idx(evidence)
    host = lambda peer: (peer or "").rsplit(":", 1)[0]
    known = set()
    for d in run_dirs:
        for e in drift._read_jsonl(d / "out.jsonl"):
            lin = e.get("_lineage", {})
            if lin.get("parser_id") == source_pack_id and lin.get("event_id") in idx:
                r = idx[lin["event_id"]]; known.add((r.get("ingest_channel"), host(r.get("peer"))))
    seen = {(idx[i].get("ingest_channel"), host(idx[i].get("peer"))) for i in drifted_ids if i in idx}
    ok = bool(seen) and bool(known) and seen <= known
    return {"bound": ok, "drifted_from": sorted(map(list, seen)), "source_known_from": sorted(map(list, known)),
            "limit": "binding is by ingest channel and peer host; the transports in use authenticate nobody"}


def heal(a) -> int:
    from ulpf_learn.plan import SUFFICIENT
    from ulpf_learn.session import Session
    from ulpf_learn.sourcepack import merge
    work = Path(a.work); work.mkdir(parents=True, exist_ok=True)
    run_dirs = [Path(d) for d in a.run_dir]
    q = [r for d in run_dirs for r in drift._read_jsonl(d / "q.jsonl")]
    mine = [r for r in q if r["stage"] == "routing" and r.get("routing_signature") == a.signature]
    alert = {"alert": "drift_auto_heal", "policy_version": POLICY_VERSION, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source_id": a.source_id,
             "trigger": {"unknown_signature": a.signature, "quarantined_events": len(mine)}}
    prev_packs = [Path(p) for p in a.family_pack]
    prev_doc = json.loads((prev_packs[0] / "pack.json").read_text(encoding="utf-8"))
    alert["previous_pack"] = {"packs_file": Path(a.packs_file).read_text(encoding="utf-8").split() if Path(a.packs_file).exists() else []}
    alert["source_binding"] = source_binding(run_dirs, Path(a.evidence), a.source_pack_id or prev_doc["pack_id"], [r["event_id"] for r in mine])

    def finish(outcome: str, rc: int) -> int:
        alert["outcome"] = outcome
        out = work / f"alert-{int(time.time() * 1000)}.json"
        out.write_text(json.dumps(alert, indent=1) + "\n", encoding="utf-8")
        (work / "alert-latest.json").write_text(json.dumps(alert, indent=1) + "\n", encoding="utf-8")
        print(f"ALERT {outcome}: {out}")
        return rc

    if not alert["source_binding"]["bound"]:
        return finish("refused: the drifted traffic is not bound to the onboarded source — a human decides (this is a new, unauthenticated source until then)", 2)
    lines = drift.extract_signature(mine, a.signature, Path(a.evidence), a.limit)
    samples = work / "samples.log"; samples.write_bytes(b"".join(l.rstrip(b"\r\n") + b"\n" for l in lines))
    if a.provider == "model":
        from ulpf_learn.model.client import LlamaClient
        from ulpf_learn.model.provider import ModelProvider, assert_served_model, verified_model_hash
        client = LlamaClient(a.server); client.wait_ready(60)
        served = assert_served_model(client, a.model_id)
        prov = ModelProvider(client, a.model_id, verified_model_hash(a.model_id), mode="whole", backend=a.backend); prov.served_model = served
    else:
        from ulpf_learn.provider import FixtureProvider
        prov = FixtureProvider(Path(a.fixture))
    s = Session(work / "session")
    s.onboard(samples, a.source_id, a.operator, prov, a.vendor, propagation_store=Path(a.propagation_store), product=a.product, transport_hint=a.transport_hint)
    (work / "session-before.json").write_text((work / "session" / "session.json").read_text(encoding="utf-8"), encoding="utf-8")
    st = s.state
    alert["what_changed"] = {"new_signature": a.signature, "new_arity": st["structure"]["arity"], "previous_families": [f["family_id"] for p in prev_packs for f in json.loads((p / "pack.json").read_text())["families"]],
                             "samples": {"count": len(lines), "from": "the evidence log, raw_hash checked"}}
    alert["propagated"] = [{"slot": h["slot_index"] + 1, "attributes": h["attributes"], "from_family": h["from_family"]} for h in st.get("propagated", [])]
    alert["model_proposed"] = {"provider": st["proposal"]["provider"], "event_class_uid": st["proposal"]["event_class_uid"],
                               "slots": [{"slot": p["slot"], "candidates": p["candidates"]} for p in st["proposal"]["slots"] if p["candidates"]]}
    pending = []
    for sl, p in s.plan.parts():
        cats = {m.provenance.get("category") for m in p.mappings}
        if p.kind == "semantic" and not (p.mappings and cats <= SUFFICIENT):
            cert = next((c for c in st["certificates"].values() if c["context"]["slot_index"] == sl.index and c["status"] != "resolved"), None)
            pending.append({"field": p.field, "slot": sl.index + 1, "samples": sl.samples[:3], "proposed": [m.attribute for m in p.mappings] or list(p.candidates),
                            "certificate_id": cert and cert["certificate_id"], "ambiguity_class": cert and cert["evidence"]["discriminator"].get("ambiguity_class"),
                            "why_withheld": ("ambiguous between " + ", ".join(r["attribute"] for r in cert["ranked_candidates"])) if cert else "a proposal is not evidence" if p.mappings or p.candidates else "nobody has said what this column is"})
    alert["withheld"] = pending
    alert["operator_request"] = (st.get("pending_request") or {}).get("text") if pending else None
    if st["verdict"]["blockers"]:
        alert["blockers"] = st["verdict"]["blockers"]
        return finish("blocked: a mandatory attribute did not resolve — nothing is promoted until the operator answers", 3)
    ver = a.pack_version
    fam_pack = work / "family-pack"
    s.promote(fam_pack, f"{a.source_id}-{st['structure']['arity']}", "1.0", withhold_unevidenced=True)
    merged = work / f"source-pack-{ver}"
    merge(prev_packs + [fam_pack], merged, prev_doc["pack_id"], [], pack_version=ver)
    alert["auto_promoted"] = [{"field": p.field, "attribute": m.attribute, "provenance": m.provenance.get("category")} for _, p in s.plan.parts() for m in p.mappings]
    alert["pack"] = {"pack_id": prev_doc["pack_id"], "pack_version": ver, "path": str(merged), "sha256": _sha(merged / "pack.json"), "signed_by": json.loads((merged / "pack.json").read_text())["signing"]["authority_id"]}
    pf = Path(a.packs_file)
    alert["rollback"] = {"command": f"python tools/autoheal.py rollback --alert {work / 'alert-latest.json'} --packs-file {pf}" + (f" --runtime-pid {a.runtime_pid}" if a.runtime_pid else ""),
                         "restores_packs_file": alert["previous_pack"]["packs_file"]}
    tmp = pf.with_suffix(".tmp"); tmp.write_text(str(merged) + "\n", encoding="utf-8"); os.replace(tmp, pf)
    if a.runtime_pid:
        os.kill(a.runtime_pid, signal.SIGHUP)
        alert["activation"] = "SIGHUP sent: the runtime records pack_activated (naming this sha256) in the evidence log"
    return finish(("healed: every column resolved on sufficient evidence" if not pending else f"healed in part: {len(alert['auto_promoted'])} mapping(s) promoted on sufficient evidence, {len(pending)} column(s) withheld — the operator is asked"), 0)


def rollback(a) -> int:
    alert = json.loads(Path(a.alert).read_text(encoding="utf-8"))
    pf = Path(a.packs_file)
    pf.write_text("\n".join(alert["rollback"]["restores_packs_file"]) + "\n", encoding="utf-8")
    if a.runtime_pid:
        os.kill(a.runtime_pid, signal.SIGHUP)
    print(f"rolled back {alert['pack']['pack_id']} v{alert['pack']['pack_version']}: packs file restored to {alert['rollback']['restores_packs_file']}" + ("; SIGHUP sent (the runtime records the change in the evidence log)" if a.runtime_pid else ""))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0]); sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("heal")
    for n in ("--source-id", "--signature", "--evidence", "--propagation-store", "--work", "--packs-file"):
        h.add_argument(n, required=True)
    h.add_argument("--run-dir", action="append", required=True); h.add_argument("--family-pack", action="append", required=True); h.add_argument("--source-pack-id")
    h.add_argument("--runtime-pid", type=int); h.add_argument("--pack-version", default="1.1"); h.add_argument("--limit", type=int, default=24)
    h.add_argument("--operator", default="auto-heal", help="recorded as the pack's operator id: the policy acted, under the standing decision of whoever onboarded the source")
    h.add_argument("--provider", choices=["model", "fixture"], default="fixture"); h.add_argument("--fixture"); h.add_argument("--model-id"); h.add_argument("--server", default="http://127.0.0.1:8080"); h.add_argument("--backend", default="unknown")
    h.add_argument("--vendor", default="unknown"); h.add_argument("--product"); h.add_argument("--transport-hint")
    r = sub.add_parser("rollback"); r.add_argument("--alert", required=True); r.add_argument("--packs-file", required=True); r.add_argument("--runtime-pid", type=int)
    a = ap.parse_args(argv)
    return heal(a) if a.cmd == "heal" else rollback(a)


if __name__ == "__main__":
    sys.exit(main())
