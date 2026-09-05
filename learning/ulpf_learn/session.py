"""Onboarding session: state on disk, the certificate workflow, and effort instrumentation from the
first step (§8.4's curve cannot be reconstructed later)."""
from __future__ import annotations

import copy
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .acceptance import evaluate
from .analyze import analyze
from .discriminators import apply_labelled_session, apply_logformat, apply_operator_assertion, mandatory_for
from .emit import emit_pack
from .induce import induce
from .library import Library
from .plan import Mapping, Part, Plan, Slot
from .provider import FixtureProvider, Provider

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE = ROOT / "learning" / "fixtures" / "squid-native-proposals.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Session:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.file = self.path / "session.json"
        self.state: dict = {}
        self.plan: Plan | None = None
        self.lib = Library()

    # ------------------------------------------------------------------ persistence
    def save(self):
        self.path.mkdir(parents=True, exist_ok=True)
        self.state["plan"] = _plan_to_json(self.plan) if self.plan else None
        self.file.write_text(json.dumps(self.state, indent=2, default=str) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "Session":
        s = cls(path)
        s.state = json.loads(s.file.read_text(encoding="utf-8"))
        s.plan = _plan_from_json(s.state["plan"]) if s.state.get("plan") else None
        return s

    def log(self, step: str, **kw):
        self.state.setdefault("timeline", []).append({"step": step, "at": now_iso(), "t": time.time(), **kw})

    def metrics(self) -> dict:
        tl = self.state.get("timeline", [])
        return {
            "evidence_requests": sum(1 for e in tl if e["step"] == "request_issued"),
            "operator_responses": sum(1 for e in tl if e["step"] == "response_received"),
            "steps": len(tl),
            "wall_clock_seconds": round(tl[-1]["t"] - tl[0]["t"], 3) if len(tl) > 1 else 0.0,
            "promoted": self.state.get("state") == "promoted",
            "samples": self.state.get("sample_count"),
        }

    # ------------------------------------------------------------------ workflow
    def onboard(self, samples_path: Path, source_id: str, operator_id: str, provider: Provider | None = None, vendor: str = "squid"):
        raw = Path(samples_path).read_bytes()
        lines = [l.rstrip(b"\r") for l in raw.split(b"\n") if l.strip()]
        self.state = {"source_id": source_id, "operator_id": operator_id, "vendor": vendor, "created_at": now_iso(),
                      "samples_path": str(samples_path), "sample_count": len(lines), "state": "induced", "timeline": [], "certificates": {}, "resolutions": []}
        self.log("session_started", samples=len(lines))
        structure = induce(lines)
        self.state["structure"] = {"arity": structure.arity, "other_arities": dict(structure.other_arities),
                                  "slots": [asdict(s) for s in structure.slots], "routing_sketch": structure.routing_sketch()}
        self.log("induced", arity=structure.arity, families_seen=1 + len(structure.other_arities))
        provider = provider or FixtureProvider(DEFAULT_FIXTURE)
        prop = provider.propose(structure)
        self.log("proposed", provider=provider.name, event_class=prop.event_class_uid)
        slots = []
        by_idx = {p.slot_index: p for p in prop.slots}
        for obs in structure.slots:
            sp = by_idx.get(obs.index)
            part = Part(f"pos_{obs.index + 1}", obs.token_class, "semantic", None, None, [], sp.unmapped_name if sp else None,
                        list(sp.candidates) if sp else [], prop.proposed_by)
            if sp and sp.candidates:
                part.mappings = [Mapping(sp.candidates[0], {"category": "model_proposal"}, None, False)]
            slots.append(Slot(obs.index, obs.token_class, [part], None, obs.samples))
        self.plan = Plan(source_id, prop.event_class_uid, prop.event_class_name, slots, [], [], None, "unresolved", prop.proposed_by, prop.model_hash)
        self.state["proposal"] = {"provider": provider.name, "event_class_uid": prop.event_class_uid,
                                  "slots": [{"slot": p.slot_index + 1, "candidates": p.candidates, "note": p.note} for p in prop.slots]}
        self.analyze_and_evaluate()
        self.save()

    def current_spec(self) -> dict:
        return self.plan.spec(f"{self.state['source_id']}-positional-{len(self.plan.slots)}",
                              f"{self.plan.event_class_name} candidate for {self.state['source_id']}")

    def analyze_and_evaluate(self):
        samples = self._samples()
        mandatory = mandatory_for(self.plan)
        verdict = evaluate(self.plan, self.current_spec(), samples)
        analysis = analyze(self.plan, self.lib)
        for c in analysis.certificates:
            prev = self.state["certificates"].get(c["certificate_id"])
            if prev and prev.get("status") == "resolved":
                continue
            c.pop("_mandatory", None)
            self.state["certificates"][c["certificate_id"]] = c
        self.state["unevidenced"] = analysis.unevidenced
        self.state["verdict"] = {"promotable": verdict.promotable, "blockers": verdict.blockers, "critical_coverage": verdict.critical_coverage,
                                 "coverage": asdict(verdict.coverage), "provenance": verdict.provenance_report, "determinations": verdict.determinations}
        self.log("analyzed", certificates=len(analysis.certificates), unresolved=sum(1 for c in analysis.certificates if c["status"] == "unresolved"),
                 blockers=len(verdict.blockers))
        if analysis.request and self.state.get("state") != "promoted":
            if self.state.get("pending_request") != analysis.request:
                self.state["pending_request"] = analysis.request
                self.log("request_issued", discriminator=analysis.request["discriminator_id"], resolves=len(analysis.request["resolves"]))
            self.state["state"] = "awaiting_evidence"
        elif verdict.promotable:
            self.state["pending_request"] = None
            self.state["state"] = "promotable"
        else:
            self.state["pending_request"] = None
            self.state["state"] = "blocked"
        return verdict, analysis

    def respond(self, discriminator_id: str, evidence: str, **kw):
        """Apply operator evidence for the pending request (or for a named discriminator)."""
        mandatory = mandatory_for(self.plan)
        op = self.state["operator_id"]
        self.log("response_received", discriminator=discriminator_id)
        cert_for_slot = {c["context"]["slot_index"]: cid for cid, c in self.state["certificates"].items()}
        if discriminator_id == "device_logformat_configuration":
            new_plan, resolved = apply_logformat(self.plan, evidence, self.state["vendor"], mandatory, op, cert_for_slot)
            self.plan = new_plan
            touched = self._resolve_certificates(set(range(len(self.plan.slots))), discriminator_id, "vendor_schema_or_device_configuration", evidence, "operator_input")
            self.state["resolutions"].append({"discriminator_id": discriminator_id, "provenance": "vendor_schema_or_device_configuration", "fields": resolved, "certificate_ids": touched})
        elif discriminator_id == "operator_labelled_session":
            line, ip = kw["sample_line"], kw["initiator_ip"]
            cert = next((cid for cid, c in self.state["certificates"].items() if c["field"]["path"] == kw.get("field")), None)
            new_plan, field = apply_labelled_session(self.plan, line, ip, mandatory, op, cert)
            self.plan = new_plan
            slot_idx = {p.field: s.index for s, p in self.plan.parts()}[field]
            touched = self._resolve_certificates({slot_idx}, discriminator_id, "validated_discriminator", f"{ip} initiated: {line}", "labelled_sample")
            self.state["resolutions"].append({"discriminator_id": discriminator_id, "provenance": "validated_discriminator", "fields": [field], "certificate_ids": touched})
        elif discriminator_id == "operator_assertion":
            self.plan = apply_operator_assertion(self.plan, kw["field"], kw["attribute"], op, evidence, mandatory)
            slot_idx = {p.field: s.index for s, p in self.plan.parts()}[kw["field"]]
            touched = self._resolve_certificates({slot_idx}, discriminator_id, "operator_assertion", evidence, "operator_input")
            self.state["resolutions"].append({"discriminator_id": discriminator_id, "provenance": "operator_assertion", "fields": [kw["field"]], "certificate_ids": touched})
        else:
            raise ValueError(f"no applier for discriminator {discriminator_id!r} in v1 (listed as an alternative only)")
        self.log("resolved", fields=len(self.state["resolutions"][-1]["fields"]))
        self.state["pending_request"] = None
        verdict, _ = self.analyze_and_evaluate()
        self.save()
        return verdict

    def _resolve_certificates(self, slot_indices: set[int], discriminator_id: str, provenance: str, evidence: str, kind: str) -> list[str]:
        """Certificates are keyed to a slot (their propagation scope), not to a field name, because
        evidence rewrites field names. A certificate resolves only to an attribute in its own enumerated
        survivors; anything else is not a resolution of that certificate."""
        import hashlib
        touched = []
        for cid, c in self.state["certificates"].items():
            idx = c["context"]["slot_index"]
            if c["status"] == "resolved" or idx not in slot_indices:
                continue
            attr = None
            for p in self.plan.slots[idx].parts:
                for m in p.mappings:
                    if m.attribute in c["enumeration"]["survivors"]:
                        attr = m.attribute
                        break
                if attr:
                    break
            if attr is None:
                continue
            touched.append(cid)
            c["status"] = "resolved"
            c.pop("unresolved_reason", None)
            c["resolution"] = {
                "discriminator_id": discriminator_id, "provenance": provenance, "resolved_to": attr,
                "evidence_ref": {"kind": kind, "summary": evidence[:2000], "hash": "sha256:" + hashlib.sha256(evidence.encode()).hexdigest()},
                "operator_id": self.state["operator_id"], "resolved_at": now_iso(),
                "propagation_scope": {"source_id": self.state["source_id"], **c["context"]},
            }
        return touched

    def promote(self, out_dir: Path, pack_id: str) -> Path:
        verdict, _ = self.analyze_and_evaluate()
        if not verdict.promotable:
            raise RuntimeError("not promotable: " + "; ".join(verdict.blockers))
        certs = list(self.state["certificates"].values())
        for c in certs:
            c.pop("_mandatory", None)
        resolutions = []
        for r in self.state["resolutions"]:
            scope_cert = next((c for c in certs if c["certificate_id"] in r["certificate_ids"]), None)
            scope = {"source_id": self.state["source_id"], **(scope_cert["context"] if scope_cert else
                     {"l1_envelope": "raw", "l2_structure": "positional", "l3_anchors": [], "slot_index": 0, "token_class": self.plan.slots[0].token_class})}
            resolutions.append({"certificate_ids": r["certificate_ids"], "fields": r["fields"], "discriminator_id": r["discriminator_id"],
                                "provenance": r["provenance"], "propagation_scope": scope})
        spec = self.plan.spec(f"{self.state['source_id']}-positional-{len(self.plan.slots)}",
                              f"{self.plan.event_class_name} parser for {self.state['source_id']}, resolved by device configuration.")
        samples = Path(self.state["samples_path"]).read_bytes()
        path = emit_pack(self.plan, spec, verdict, certs, resolutions, samples, self.state["sample_count"], self.state["operator_id"],
                         pack_id, out_dir, now_iso(), self.state["structure"]["routing_sketch"], self.lib.version)
        self.state["state"] = "promoted"
        self.state["pack_path"] = str(path)
        self.log("promoted", pack=str(path))
        self.state["metrics"] = self.metrics()
        self.save()
        return path

    def _samples(self) -> list[bytes]:
        raw = Path(self.state["samples_path"]).read_bytes()
        return [l.rstrip(b"\r") for l in raw.split(b"\n") if l.strip()]


def _plan_to_json(p: Plan) -> dict:
    d = asdict(p)
    return d


def _plan_from_json(d: dict) -> Plan:
    slots = []
    for s in d["slots"]:
        parts = [Part(pp["field"], pp["cls"], pp["kind"], pp["coerce"], pp["null_values"],
                      [Mapping(**m) for m in pp["mappings"]], pp["unmapped_name"], pp["candidates"], pp["proposed_by"]) for pp in s["parts"]]
        slots.append(Slot(s["index"], s["token_class"], parts, s["split"], s["samples"]))
    return Plan(d["source_id"], d["event_class_uid"], d["event_class_name"], slots, d["null_values"],
                [Mapping(**m) for m in d["constants"]], d["source_timezone"], d["timezone_confidence"], d["proposed_by"], d["model_hash"])
