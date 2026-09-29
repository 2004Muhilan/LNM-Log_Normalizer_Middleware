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
from .discriminators import VENDOR_TABLES, apply_labelled_session, apply_logformat, apply_operator_assertion, apply_vendor_schema, load_vendor_table, mandatory_for, vendor_table_meta
from .anchors import load_declared
from .envelope import payload as envelope_payload
from .propagation import Store as PropagationStore
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
    def onboard(self, samples_path: Path, source_id: str, operator_id: str, provider: Provider | None = None, vendor: str = "squid",
                propagation_store: Path | None = None, product: str | None = None, transport_hint: str | None = None, family_keys: list[str] | None = None):
        """`family_keys`: the keys whose values name a family of this source (FortiGate `type`), as the source's bound packs
        or the operator's inventory declare them. One onboarding learns ONE family: when the samples hold several, the
        largest is kept and the rest stay quarantined for their own job. On a self-describing surface the family is part
        of the cross-format name key (propagation.py)."""
        raw = Path(samples_path).read_bytes()
        lines = [l.rstrip(b"\r") for l in raw.split(b"\n") if l.strip()]
        self.state = {"source_id": source_id, "operator_id": operator_id, "vendor": vendor, "created_at": now_iso(),
                      "samples_path": str(samples_path), "sample_count": len(lines), "state": "induced", "timeline": [], "certificates": {}, "resolutions": [],
                      "product": product, "transport_hint": transport_hint, "family_keys": list(family_keys or [])}
        self.log("session_started", samples=len(lines))
        from .draft import draft
        from .envelope import chain, chain_payload
        if family_keys:
            groups: dict[str, list[bytes]] = {}
            for l in lines:
                groups.setdefault(family_values(chain_payload(l), family_keys), []).append(l)
            fam = max(groups, key=lambda k: (len(groups[k]), k))
            if len(groups) > 1:
                self.log("family_split", kept=fam, left={k: len(v) for k, v in groups.items() if k != fam})
            lines = groups[fam]
            self.state["family"], self.state["sample_count"] = fam, len(lines)
        d = draft(lines, f"{source_id}-draft")   # None for whitespace-token text: induction, as before
        if d is not None:
            structure = d.structure
            d.spec["spec_id"] = f"{source_id}-{d.l2}-{structure.arity}"
            self.state["app_envelope"] = d.l1 if d.l1 != "raw" else None
            self.state["drafted"] = {"l1": d.l1, "l2": d.l2, "named": d.named,
                                     "names": {c["field"]: k for k, c in (d.spec["root"].get("keys") or d.spec["root"].get("paths") or {}).items()}}
            if d.l1 != "raw":   # onboarding sees the payload routing sees: every envelope removed, as frame.UnwrapChain removes it
                lines = [chain_payload(l) for l in lines]
            self.state["structure"] = {"arity": structure.arity, "other_arities": {}, "slots": [asdict(s) for s in structure.slots], "routing_sketch": d.routing}
            self.log("induced", arity=structure.arity, families_seen=1, structure_from=f"drafted_{d.l2}")
        else:
            l1s = {chain(l)["l1"] for l in lines} - {"raw"}
            if l1s:   # positional text inside an envelope: induce on the payload, as the router routes it (a raw family owns it)
                self.state["app_envelope"] = sorted(l1s)[0]
                lines = [chain_payload(l) for l in lines]
            structure = induce(lines)
            self.state["structure"] = {"arity": structure.arity, "other_arities": dict(structure.other_arities),
                                      "slots": [asdict(s) for s in structure.slots], "routing_sketch": structure.routing_sketch()}
            self.log("induced", arity=structure.arity, families_seen=1 + len(structure.other_arities))
        provider = provider or FixtureProvider(DEFAULT_FIXTURE)
        if hasattr(provider, "set_samples"):
            provider.set_samples(lines)   # the prompt shows the onboarding samples — and only those
        t_prop = time.time()
        prop = provider.propose(structure)
        self.log("proposed", provider=provider.name, event_class=prop.event_class_uid, seconds=round(time.time() - t_prop, 3))
        self.state["proposal_provenance"] = prop.notes.get("provenance") if isinstance(prop.notes, dict) else None
        self.plan = plan_from_proposal(structure, prop, source_id)
        if d is not None:
            self.plan.given_spec, self.plan.drafted, self.plan.family_id = d.spec, True, f"{d.l1 + '-' if d.l1 != 'raw' else ''}{d.l2}-{structure.arity}"
        self.state["proposal"] = {"provider": provider.name, "event_class_uid": prop.event_class_uid,
                                  "slots": [{"slot": p.slot_index + 1, "candidates": p.candidates, "note": p.note} for p in prop.slots]}
        self._propagate(propagation_store)
        self.analyze_and_evaluate()
        self.save()

    def _propagate(self, store_path: Path | None):
        """Resolution propagation (§4.4 key) BEFORE the first analysis: a slot whose key already carries a
        sufficient resolution for this source needs no certificate and no evidence request."""
        self.state["propagation_store"] = str(store_path) if store_path else None
        if not store_path:
            return
        store = PropagationStore(store_path)
        dr = self.state.get("drafted") or {}
        fc = store.family_class(self.state["source_id"], self.state.get("family", "")) if dr.get("named") and dr.get("l2") in ("json", "kv") else None
        if fc and fc[0] != self.plan.event_class_uid:
            # the family's class is evidence (earlier answers for this source's family); the model's other class is a
            # proposal — its per-field proposals were made for that other class and are dropped, so what does not carry is asked
            self.log("class_from_earlier_answers", family=self.state["family"], event_class=fc[0], proposed=self.plan.event_class_uid)
            self.plan.event_class_uid, self.plan.event_class_name = fc
            for _, part in self.plan.parts():
                part.mappings, part.candidates = [], []
        hits = store.apply(self.plan, self.state["source_id"], self.state["structure"]["routing_sketch"], by_name=bool(dr.get("named")),
                           family=self.state.get("family", "") if dr.get("named") else None, names=dr.get("names"))
        self.state["propagated"] = hits
        self.log("propagated", slots=len(hits), from_families=sorted({h["from_family"] for h in hits}))

    def onboard_spec(self, samples_path: Path, spec_path: Path, source_id: str, operator_id: str, vendor: str, family_id: str,
                     provider: Provider | None = None, unwrap_envelope: bool = False, propagation_store: Path | None = None):
        """P6: onboard a source whose structure is GIVEN by a spec (csv/kv/regex drafts) — the model labels the
        spec's fields, it does not rebuild the structure (P4 boundary: 'model labels, not specs'). The samples
        may still carry their syslog envelope; `unwrap_envelope` strips one level exactly as the runtime does."""
        from .model.structure_from_spec import structure_from_spec
        raw = Path(samples_path).read_bytes()
        lines = [l.rstrip(b"\r") for l in raw.split(b"\n") if l.strip()]
        if unwrap_envelope:
            lines = [envelope_payload(l) for l in lines]
        spec_bytes = Path(spec_path).read_bytes()
        spec = json.loads(spec_bytes)
        self.state = {"source_id": source_id, "operator_id": operator_id, "vendor": vendor, "family_id": family_id, "created_at": now_iso(),
                      "samples_path": str(samples_path), "spec_path": str(spec_path), "unwrap_envelope": unwrap_envelope, "sample_count": len(lines),
                      "state": "induced", "timeline": [], "certificates": {}, "resolutions": []}
        self.log("session_started", samples=len(lines), given_spec=spec["spec_id"])
        structure, kept = structure_from_spec(spec_bytes, lines)
        if len(kept) != len(lines):
            raise RuntimeError(f"{len(lines) - len(kept)} sample(s) do not parse under {spec['spec_id']}; the spec is not a parser for this capture")
        self.state["structure"] = {"arity": structure.arity, "other_arities": {}, "slots": [asdict(s) for s in structure.slots],
                                   "routing_sketch": {"l1_envelope": "raw", "l2_structure": _l2_of(spec), "l3_anchor_ids": [], "l3_structural_literals": [],
                                                      "l4_sketch": {"arity_bucket": str(structure.arity), "token_class_sequence": [s.token_class for s in structure.slots]}}}
        self.log("induced", arity=structure.arity, families_seen=1, structure_from="given_spec")
        provider = provider or FixtureProvider(DEFAULT_FIXTURE)
        if hasattr(provider, "set_samples"):
            provider.set_samples(lines)
        t_prop = time.time()
        prop = provider.propose(structure)
        self.log("proposed", provider=provider.name, event_class=prop.event_class_uid, seconds=round(time.time() - t_prop, 3))
        self.state["proposal_provenance"] = prop.notes.get("provenance") if isinstance(prop.notes, dict) else None
        self.plan = plan_from_proposal(structure, prop, source_id)
        self.plan.given_spec = spec
        self.plan.family_id = family_id
        self.state["proposal"] = {"provider": provider.name, "event_class_uid": prop.event_class_uid,
                                  "slots": [{"slot": p.slot_index + 1, "candidates": p.candidates, "note": p.note} for p in prop.slots]}
        self._propagate(propagation_store)
        self.analyze_and_evaluate()
        self.save()

    def current_spec(self) -> dict:
        return self.plan.spec(f"{self.state['source_id']}-positional-{len(self.plan.slots)}",
                              f"{self.plan.event_class_name} candidate for {self.state['source_id']}")

    def analyze_and_evaluate(self):
        samples = self._samples()
        mandatory = mandatory_for(self.plan)
        verdict = evaluate(self.plan, self.current_spec(), samples)
        analysis = analyze(self.plan, self.lib, document_evidence=self.state.get("vendor", "squid") in VENDOR_TABLES)
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
            prev = self.state.get("pending_request") or self.state.get("last_request")
            if self.state.get("pending_request") != analysis.request:
                # the SAME question with fewer fields left in it is not a new request: a per-field answer shrinks it. Counting each
                # shrink as an evidence request inflated the effort figures (9 requests for 9 assertions, live demo 2026-09-20).
                same = bool(prev) and prev["discriminator_id"] == analysis.request["discriminator_id"] and set(analysis.request["resolves"]) <= set(prev["resolves"])
                self.state["pending_request"] = analysis.request
                if not same:
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
        elif discriminator_id == "vendor_schema_field_order":
            new_plan, resolved = apply_vendor_schema(self.plan, self.state["vendor"], self.state["family_id"], mandatory, op, cert_for_slot)
            self.plan = new_plan
            touched = self._resolve_certificates(set(range(len(self.plan.slots))), discriminator_id, "vendor_schema_or_device_configuration", evidence, "vendor_document")
            self.state["resolutions"].append({"discriminator_id": discriminator_id, "provenance": "vendor_schema_or_device_configuration", "fields": resolved, "certificate_ids": touched})
        elif discriminator_id == "operator_assertion":
            self.plan = apply_operator_assertion(self.plan, kw["field"], kw["attribute"], op, evidence, mandatory, lookup=kw.get("lookup"))
            slot_idx = {p.field: s.index for s, p in self.plan.parts()}[kw["field"]]
            touched = self._resolve_certificates({slot_idx}, discriminator_id, "operator_assertion", evidence, "operator_input")
            self.state["resolutions"].append({"discriminator_id": discriminator_id, "provenance": "operator_assertion", "fields": [kw["field"]], "certificate_ids": touched})
        else:
            raise ValueError(f"no applier for discriminator {discriminator_id!r} in v1 (listed as an alternative only)")
        self.log("resolved", fields=len(self.state["resolutions"][-1]["fields"]))
        self.state["last_request"], self.state["pending_request"] = self.state.get("pending_request") or self.state.get("last_request"), None
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

    def promote(self, out_dir: Path, pack_id: str, pack_version: str = "1.0", withhold_unevidenced: bool = False) -> Path:
        """pack_version > 1.0 is a CORRECTION of an already promoted family (P8, invariant 8): the same session,
        a retained certificate resolved by new evidence, a new pack version. The runtime re-derives the affected
        events from the evidence under it as normalization@v2 (`ulpf-runtime renormalize`); v1 is never rewritten."""
        verdict, _ = self.analyze_and_evaluate()
        if not verdict.promotable:
            raise RuntimeError("not promotable: " + "; ".join(verdict.blockers))
        if withhold_unevidenced:
            # Nothing that rests on a proposal alone goes into the pack: the column stays parsed and carried as an unmapped
            # vendor field, its certificate (if any) is retained, and answering it later is a pack correction (P8). Without this a
            # non-mandatory model label is emitted as a mapping — a guess with a provenance tag — and two columns given the same
            # label make a pack the contract refuses.
            from .plan import SUFFICIENT
            withheld = []
            for _, p in self.plan.parts():
                if p.kind == "semantic" and any(m.provenance.get("category") not in SUFFICIENT for m in p.mappings):
                    withheld.append({"field": p.field, "proposed": [m.attribute for m in p.mappings]})
                    p.mappings, p.unmapped_name = [], p.unmapped_name or p.field
            self.state["withheld"] = withheld
            verdict, _ = self.analyze_and_evaluate()
            if not verdict.promotable:
                raise RuntimeError("not promotable once unevidenced fields are withheld: " + "; ".join(verdict.blockers))
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
        if self.state.get("unwrap_envelope"):
            samples = b"".join(envelope_payload(l.rstrip(b"\r")) + b"\n" for l in samples.split(b"\n") if l.strip())
        source_meta, anchors, routing = None, [], self.state["structure"]["routing_sketch"]
        if self.state.get("family_id"):
            meta = vendor_table_meta(self.state["vendor"], self.state["family_id"])
            source_meta = {"vendor": meta["vendor"], "product": meta["product"], "declared_envelope": meta["declared_envelope"], "transport_hint": meta["transport_hint"]}
            anchors = load_declared(load_vendor_table(self.state["vendor"]))
            fam = meta["family"]
            routing = dict(routing)
            routing["l1_envelope"] = meta["declared_envelope"]
            routing["l2_structure"] = fam.get("l2", routing["l2_structure"])
            routing["l3_anchor_ids"] = [a["anchor_id"] for a in anchors]
            if fam.get("arity_bucket"):
                routing["l4_sketch"] = {**routing["l4_sketch"], "arity_bucket": str(fam["arity_bucket"])}
            # the family's anchor VALUES ride in the family entry (anchor_values), keyed by anchor id
            av = fam.get("anchor_values")
            if isinstance(av, dict):
                anchor_values = {k: list(v) for k, v in av.items()}
            elif av and anchors:
                anchor_values = {anchors[0]["anchor_id"]: list(av)}
            else:
                anchor_values = {}
        else:
            anchor_values = {}
            if self.state.get("vendor", "squid") != "squid":
                # no vendor table: the pack says what the operator said the source is — never the Squid default
                source_meta = {"vendor": self.state["vendor"], "product": self.state.get("product") or "unknown", "declared_envelope": self.state.get("app_envelope") or "raw",
                               "transport_hint": self.state.get("transport_hint") or "file"}
        path = emit_pack(self.plan, spec, verdict, certs, resolutions, samples, self.state["sample_count"], self.state["operator_id"],
                         pack_id, out_dir, now_iso(), routing, self.lib.version,
                         proposal_provenance=self.state.get("proposal_provenance"), family_id=self.plan.family_id, source_meta=source_meta, anchors=anchors,
                         anchor_values=anchor_values, pack_version=pack_version,
                         description=None if self.state.get("vendor", "squid") == "squid" or self.state.get("family_id") else
                         f"{self.plan.event_class_name} family induced from {self.state['sample_count']} samples; resolved by: " + ", ".join(sorted({r["discriminator_id"] for r in self.state["resolutions"]} | ({"propagation"} if self.state.get("propagated") else set()))) + ".")
        if self.state.get("propagation_store"):
            store = PropagationStore(Path(self.state["propagation_store"]))
            dr = self.state.get("drafted") or {}
            n = store.record(self.plan, self.state["source_id"], routing, self.plan.family_id or f"positional-{len(self.plan.slots)}", str(self.path),
                             by_name=bool(dr.get("named")), family=self.state.get("family", "") if dr.get("named") else None, names=dr.get("names"))
            store.save()
            self.log("propagation_recorded", slots=n)
        self.state["state"] = "promoted"
        self.state["pack_path"] = str(path)
        self.log("promoted", pack=str(path))
        self.state["metrics"] = self.metrics()
        self.save()
        return path

    def _samples(self) -> list[bytes]:
        raw = Path(self.state["samples_path"]).read_bytes()
        lines = [l.rstrip(b"\r") for l in raw.split(b"\n") if l.strip()]
        if self.state.get("unwrap_envelope"):
            lines = [envelope_payload(l) for l in lines]   # the parser sees the payload, exactly as the runtime unwraps it
        if self.state.get("app_envelope"):
            from .envelope import chain_payload
            lines = [chain_payload(l) for l in lines]   # the payload routing sees, every envelope removed
        return lines


def family_values(payload: bytes, keys: list[str]) -> str:
    """The family a payload belongs to: the values it carries under the source's family keys (a JSON path, or a key=value
    key). A key the line does not carry contributes nothing, so such a line is its own (empty-valued) family."""
    import re
    from .propagation import family_of
    vals: dict[str, list[str]] = {}
    obj = None
    if payload[:1] == b"{":
        try:
            obj = json.loads(payload)
        except ValueError:
            obj = None
    for k in keys:
        v = None
        if isinstance(obj, dict):
            v = obj
            for part in k.split("."):
                v = v.get(part) if isinstance(v, dict) else None
        else:
            m = re.search(rb'(?:^|[\s,|])' + re.escape(k.encode()) + rb'="((?:[^"\\]|\\.)*)"', payload) or \
                re.search(rb'(?:^|[\s,|])' + re.escape(k.encode()) + rb'=([^\s,"]*)', payload)
            v = m.group(1).decode("utf-8", "replace") if m else None
        if v is not None and not isinstance(v, (dict, list)):
            vals[k] = [str(v)]
    return family_of(vals)


def _l2_of(spec: dict) -> str:
    root = spec["root"]
    if isinstance(root, list):   # a step sequence (the ASA regex drafts): a template family
        return "template"
    op = root["op"]
    return {"positional": "positional", "csv": "csv", "kv": "kv", "regex": "template", "json": "json", "xml": "xml"}.get(op, "mixed")


def plan_from_proposal(structure, prop, source_id: str) -> Plan:
    """The working plan from an induced structure and a provider's proposal: one part per slot, the
    rank-1 candidate mapped with `model_proposal` provenance (never sufficient on its own — invariant 4),
    the full ranking kept for the analyzer. Slot names come from the structure when it has them."""
    slots = []
    by_idx = {p.slot_index: p for p in prop.slots}
    for obs in structure.slots:
        sp = by_idx.get(obs.index)
        part = Part(obs.name or f"pos_{obs.index + 1}", obs.token_class, "semantic", None, None, [], sp.unmapped_name if sp else None,
                    list(sp.candidates) if sp else [], prop.proposed_by)
        if sp and sp.candidates:
            part.mappings = [Mapping(sp.candidates[0], {"category": "model_proposal"}, None, False)]
        slots.append(Slot(obs.index, obs.token_class, [part], None, obs.samples))
    return Plan(source_id, prop.event_class_uid, prop.event_class_name, slots, [], [], None, "unresolved", prop.proposed_by, prop.model_hash)


def _plan_to_json(p: Plan) -> dict:
    d = asdict(p)
    return d


def _plan_from_json(d: dict) -> Plan:
    from .plan import EnvelopeMapping
    slots = []
    for s in d["slots"]:
        parts = [Part(pp["field"], pp["cls"], pp["kind"], pp["coerce"], pp["null_values"],
                      [Mapping(**m) for m in pp["mappings"]], pp["unmapped_name"], pp["candidates"], pp["proposed_by"]) for pp in s["parts"]]
        slots.append(Slot(s["index"], s["token_class"], parts, s["split"], s["samples"]))
    return Plan(d["source_id"], d["event_class_uid"], d["event_class_name"], slots, d["null_values"],
                [Mapping(**m) for m in d["constants"]], d["source_timezone"], d["timezone_confidence"], d["proposed_by"], d["model_hash"],
                d.get("given_spec"), d.get("family_id"), [EnvelopeMapping(**e) for e in d.get("envelope_mappings", [])], d.get("drafted", False),
                timezone_field=d.get("timezone_field"))
