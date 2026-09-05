"""Ambiguity analyzer — the centrepiece.

For every field whose proposal is not sufficient evidence: enumerate survivors over the pinned table,
and either (a) leave structural determination to the acceptance engine (one survivor), (b) emit an
AMBIGUOUS certificate with the lowest-cost sufficient discriminator selected by direct library lookup,
(c) emit an UNRESOLVED certificate when the provider ranks competing survivors that no library class
covers — never a guess (invariant 5), or (d) record the field as UNEVIDENCED. Certificates that one
evidence item resolves share a sufficiency group and yield ONE request.

Who decides that a field is ambiguous (P3->P4 boundary decision): **the library, anchored on the
proposal, over the validator's survivors** — not the provider's ranking. For the rank-1 proposal X,
every ambiguity class X belongs to contributes its rivals: the class's candidates that also survive
enumeration (`pair_of` classes hold the leaf fixed and vary the role prefix). Two or more rivals →
ambiguous, whatever the provider ranked; the provider's ranking is only an ordering hint inside the
certificate. A single-proposal model therefore still produces certificates. A bare survivors ∩ class
intersection was tried and rejected: type compatibility alone makes every integer slot a
`volume_direction` and every word slot an `action_outcome`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .acceptance import policy_for
from .enumerate_ import enumerate_candidates
from .library import Library
from .plan import SUFFICIENT, Plan


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Analysis:
    certificates: list[dict]                 # contract documents
    request: dict | None                     # one consolidated request (sufficiency group) or None
    unevidenced: list[dict] = field(default_factory=list)  # single-proposal mandatory fields with no evidence


def _slug(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in s)


def _decide(lib: Library, ranked_in: list[str], survivors: list[str]) -> tuple[str | None, list[str], list[str]] | None:
    """Decide whether the slot is ambiguous and over which set.

    Returns (class or None, ranked candidates, provider candidates dropped) — or None when the field is
    merely unevidenced. Order of precedence:
      1. the provider ranked ≥2 survivors and one class covers them all → that class, the provider's
         order, then the class's remaining rivals in table order (the P3 rule, still honoured);
      2. otherwise the library, anchored on rank-1: the class with the fewest rivals ≥2 (the most
         specific claim; ties broken by library order) → its rivals, provider-ranked ones first;
      3. otherwise the provider ranked ≥2 survivors that no class covers → UNRESOLVED (invariant 5);
      4. otherwise None: a single proposal with no library-named rival.
    ranked_candidates ⊆ survivors holds by construction in every branch."""
    x = ranked_in[0]
    covering = lib.match_class(ranked_in) if len(ranked_in) >= 2 else None
    options = [(name, riv) for name, riv in lib.rivals(x, survivors) if len(riv) >= 2]
    if covering:
        riv = dict(options).get(covering, [])
        return covering, ranked_in + [a for a in riv if a not in ranked_in], []
    if options:
        options.sort(key=lambda o: len(o[1]))
        name, riv = options[0]
        ordered = [a for a in ranked_in if a in riv] + [a for a in riv if a not in ranked_in]
        return name, ordered, [a for a in ranked_in if a not in riv]
    if len(ranked_in) >= 2:
        return None, ranked_in, []
    return None


def analyze(plan: Plan, lib: Library, configurable_format: bool = True) -> Analysis:
    pol = policy_for(plan.event_class_uid)
    mandatory = set(pol["mandatory_attributes"])
    certs, unevidenced = [], []
    pending_fields: list[str] = []   # every field the configuration discriminator would resolve
    for slot, part in plan.parts():
        if part.kind != "semantic":
            continue
        cats = {m.provenance.get("category") for m in part.mappings}
        if part.mappings and cats <= SUFFICIENT:
            continue
        # every field without sufficient provenance is pending: configuration/documentation evidence
        # resolves all of them at once (the trace's "resolves both, plus positions 2, 4, 9")
        pending_fields.append(part.field)
        is_mandatory = any(m.attribute in mandatory for m in part.mappings) or any(c in mandatory for c in part.candidates)
        ranked = list(part.candidates) or [m.attribute for m in part.mappings]
        if not ranked:
            continue  # nothing proposed (compound awaiting a split, or a vendor-extension slot)
        en = enumerate_candidates(plan.event_class_uid, part.cls, slot.samples)
        if len(en.survivors) == 1 and en.survivors[0] == ranked[0]:
            continue  # structural determination is granted by the acceptance engine, with the set recorded
        ranked_in = [a for a in ranked if a in en.survivors]
        if not ranked_in:
            # The validator refutes the proposal outright: nothing proposed is type-compatible with the
            # slot. Not a certificate (nobody has evidence for any rival) — a refuted proposal, covered
            # by the request like every other unevidenced field.
            unevidenced.append({"field": part.field, "attribute": ranked[0], "reason": "refuted: no proposed candidate is type-compatible with the slot"})
            continue
        decision = _decide(lib, ranked_in, en.survivors)
        if decision is None:
            # Rank-1 belongs to no ambiguity class (or its classes have no surviving rival) and the
            # provider ranked nothing else that survives: an unevidenced proposal. The competing set is
            # never fabricated from the enumeration (tried and rejected in P3: it produced
            # device.location.lat as a rival for an epoch timestamp). The request covers the field.
            unevidenced.append({"field": part.field, "attribute": ranked_in[0], "reason": f"{part.proposed_by} proposal alone; enumeration leaves {len(en.survivors)} survivors and no library class names a rival"})
            continue
        cls_name, ranked_in, dropped = decision
        cert_id = f"cert_{_slug(plan.source_id)}_pos{slot.index + 1}"
        cert = {
            "schema_version": "1.0.0", "certificate_id": cert_id, "created_at": now_iso(),
            "source_id": plan.source_id, "family_id": f"positional-{len(plan.slots)}",
            "context": {"l1_envelope": "raw", "l2_structure": "positional", "l3_anchors": [], "slot_index": slot.index, "token_class": part.cls},
            "field": {"path": part.field, "sample_values": slot.samples[:6]},
            "event_class": {"uid": plan.event_class_uid, "name": plan.event_class_name, "ocsf_version": "1.3.0"},
            "enumeration": en.record(),
            "ranked_candidates": [{"rank": i + 1, "attribute": a, "proposed_by": part.proposed_by if a in ranked else "enumeration"} for i, a in enumerate(ranked_in)],
            "evidence": {"vendor_metadata": "absent",
                         "structural": {"status": "weak", "note": f"slot {slot.index + 1}: {part.cls} token; {len(en.survivors)} type-compatible attributes survive"
                                        + (f"; rivals named by library class {cls_name}" if cls_name else "; no library class names a rival")
                                        + (f"; provider also ranked {dropped}, outside the class" if dropped else "")},
                         "held_out_consistency": "tied", "type_validity": "tied",
                         "discriminator": {"status": "none"}},
        }
        if cls_name:
            cert["evidence"]["discriminator"] = {"status": "available", "ambiguity_class": cls_name, "library_version": lib.version}
            cert["status"] = "ambiguous"
            cert["_class"] = cls_name
        else:
            cert["status"] = "unresolved"
            cert["unresolved_reason"] = "no_library_discriminator"
        cert["_mandatory"] = is_mandatory
        certs.append(cert)

    request = None
    ambiguous = [c for c in certs if c["status"] == "ambiguous"]
    if ambiguous:
        # resolves_by_discriminator: configuration/documentation resolve every pending field of the
        # source; sample-based discriminators resolve their own certificate's field only
        group = f"sg_{_slug(plan.source_id)}_evidence"
        all_fields = pending_fields
        for c in ambiguous:
            cls_name = c["_class"]
            per = {}
            for d in lib.classes[cls_name]["discriminators"]:
                if d in ("device_logformat_configuration", "vendor_schema_field_order"):
                    per[d] = list(all_fields) if (configurable_format or d == "vendor_schema_field_order") else []
                else:
                    per[d] = [c["field"]["path"]]
            if not configurable_format:
                per.pop("device_logformat_configuration", None)
            choices = lib.rank(cls_name, per)
            choices = [ch for ch in choices if ch.resolves]
            sel, alts = choices[0], choices[1:]
            c["request"] = {
                "ambiguity_class": cls_name, "sufficiency_group": group if sel.discriminator_id in ("device_logformat_configuration", "vendor_schema_field_order") else f"sg_{_slug(c['certificate_id'])}",
                "selected": {"discriminator_id": sel.discriminator_id, "cost_tier": sel.cost_tier, "rank": 1, "resolves": sel.resolves},
                "alternatives": [{"discriminator_id": a.discriminator_id, "cost_tier": a.cost_tier, "rank": a.rank, "resolves": a.resolves} for a in alts],
                "text": "",
            }
        selected = ambiguous[0]["request"]["selected"]["discriminator_id"]
        others = len(all_fields) - len(ambiguous)
        text = (f"{len(ambiguous)} field(s) cannot be resolved from the samples alone"
                + (f" ({sum(1 for c in ambiguous if c['_mandatory'])} mandatory). " if any(c['_mandatory'] for c in ambiguous) else ". ")
                + lib.request_text(selected, vendor="the device", product="", resolves=", ".join(all_fields), slot_index="")
                + (f" This resolves {len(ambiguous)} ambiguous field(s) and {others} other field(s) at the same time." if selected in ("device_logformat_configuration", "vendor_schema_field_order") else ""))
        for c in ambiguous:
            c["request"]["text"] = text
        request = {"discriminator_id": selected, "sufficiency_group": ambiguous[0]["request"]["sufficiency_group"], "certificates": [c["certificate_id"] for c in ambiguous],
                   "resolves": all_fields, "text": text, "alternatives": ambiguous[0]["request"]["alternatives"]}
    for c in certs:
        c.pop("_class", None)
    return Analysis(certs, request, unevidenced)
