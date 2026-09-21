"""Resolution propagation under the §4.4 key (plan v1.1 §4 item 4; architecture §3.1 as corrected):

    same source_id + identical L1–L3 signature + same slot index + same token class

A resolution made while onboarding one family is reused, without a new evidence request, for a
slot of a later family of the SAME source that has the same key. Deliberately conservative: for
anchored vendors the family anchor lives in L3, so propagation never crosses ASA family boundaries;
it applies to anchor-sparse structures (Squid), which is what the P6 demo shows. The propagated slot
keeps the ORIGINAL provenance category (the evidence is the same device configuration) and records
where it came from; the acceptance engine judges it exactly as it judged the original.

The unit is the SLOT — its split (a compound token such as `TCP_MISS/200`), its parts, their coercions
and mappings — because that is what the key names and what a certificate's propagation_scope names.
The store is a JSON file per operator workspace; it holds only slots whose every mapped part rests on
sufficient provenance.
"""
from __future__ import annotations

import copy
import json
from dataclasses import asdict
from pathlib import Path

from .plan import SUFFICIENT, Mapping, Part, Plan, Slot


def key_of(source_id: str, l1: str, l2: str, l3_anchor_values: list, slot_index, token_class: str) -> str:
    """slot_index is the position — or, for a DRAFTED self-describing family (json/xml/kv), `name:<field>`: a key that
    moves when a new key is inserted before it must not inherit its neighbour's answer (laptop branch)."""
    anchors = ",".join(sorted(f"{a['anchor_id']}={v}" for a in l3_anchor_values for v in a.get("values", [])))
    return f"{source_id}|{l1}|{l2}|{anchors}|{slot_index}|{token_class}"


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.entries: dict[str, dict] = {}
        if self.path.exists():
            self.entries = json.loads(self.path.read_text(encoding="utf-8"))

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def record(self, plan: Plan, source_id: str, routing: dict, family_id: str, session_dir: str, by_name: bool = False) -> int:
        """Store every slot whose mapped parts all rest on sufficient provenance, under its key."""
        n = 0
        for slot in plan.slots:
            mapped = [m for p in slot.parts for m in p.mappings]
            if any(m.provenance.get("category") not in SUFFICIENT for m in mapped):
                continue
            if not mapped and any(p.proposed_by in ("fixture", "model") for p in slot.parts):
                continue   # an unmapped slot counts only when the evidence (not a proposal) named it — e.g. Squid's `%[un` carried as a vendor extension
            k = key_of(source_id, routing["l1_envelope"], routing["l2_structure"], routing.get("l3_anchor_values", []), f"name:{slot.parts[0].field}" if by_name else slot.index, slot.token_class)
            self.entries[k] = {"split": slot.split, "parts": [asdict(p) for p in slot.parts], "from": {"family_id": family_id, "session": session_dir}}
            n += 1
        return n

    def apply(self, plan: Plan, source_id: str, routing: dict, by_name: bool = False) -> list[dict]:
        """Rewrite the plan's slots from stored resolutions with the same key. Returns what propagated."""
        hits = []
        for slot in plan.slots:
            k = key_of(source_id, routing["l1_envelope"], routing["l2_structure"], routing.get("l3_anchor_values", []), f"name:{slot.parts[0].field}" if by_name else slot.index, slot.token_class)
            e = self.entries.get(k)
            if e is None:
                continue
            parts = []
            for pd in e["parts"]:
                pd = copy.deepcopy(pd)
                maps = []
                for m in pd.pop("mappings"):
                    prov = m["provenance"]
                    prov["evidence_ref"] = ((prov.get("evidence_ref") or "")[:800] + f" [propagated from {e['from']['family_id']} under the §4.4 key]").strip()
                    maps.append(Mapping(m["attribute"], prov, m.get("transform"), m.get("mandatory", False)))
                pd["candidates"] = []
                parts.append(Part(**pd, mappings=maps))
            slot.parts, slot.split = parts, e["split"]
            hits.append({"slot_index": slot.index, "token_class": slot.token_class, "fields": [p.field for p in parts], "from_family": e["from"]["family_id"],
                         "attributes": [m.attribute for p in parts for m in p.mappings], "key": k})
        return hits
