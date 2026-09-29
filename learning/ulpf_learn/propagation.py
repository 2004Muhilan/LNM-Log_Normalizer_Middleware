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

CHANGE TO THE SETTLED KEY (laptop branch, 2026-09-30, the user's decision after the real FortiGate): for a SELF-DESCRIBING
surface — JSON and key=value, where every value is labelled with its field's name — an answer carries across FORMATS by
name. The key there is

    same source_id + same family (the values of the source's family keys, e.g. FortiGate type=traffic) + same field name
    + same token class

with no L1 and no L2: the name is the evidence, so nothing is guessed. The token class stays: a field whose values
changed class (a protocol number that became a name) changed meaning, and inherits nothing. The family part keeps two families
of one source apart (FortiGate's `action` is a session verdict in traffic logs and login/logout in event logs); a
family key that is declared but absent from the new lines gives an empty family, which matches nothing declared. An
answer carries only into a plan of the same OCSF class as the one it was given for. What carries is the SEMANTIC
answer (mappings, unmapped name, the value's coercion); the structure (the cell's observed class) is the new format's
own. Everything else — positional text, csv, xml — keeps the structure-based key above.
"""
from __future__ import annotations

import copy
import json
from dataclasses import asdict
from pathlib import Path

from .plan import SUFFICIENT, Mapping, Part, Plan, Slot


SELF_DESCRIBING = ("json", "kv")


def name_key(source_id: str, family: str, name: str, token_class: str) -> str:
    """The cross-format key of a self-describing field: source, family, the name the line itself carries, its value class."""
    return f"{source_id}|named|{family}|name:{name}|{token_class}"


def family_of(values: dict) -> str:
    """{'type': ['traffic']} -> 'type=traffic'; several values of one key stay together, so they match no single family."""
    return ",".join(f"{k}={'|'.join(sorted(set(v)))}" for k, v in sorted(values.items()))


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

    def _key(self, slot: Slot, source_id: str, routing: dict, by_name: bool, family: str | None, names: dict | None) -> str:
        if by_name and routing["l2_structure"] in SELF_DESCRIBING and family is not None:
            f = slot.parts[0].field
            return name_key(source_id, family, (names or {}).get(f, f), slot.token_class)
        return key_of(source_id, routing["l1_envelope"], routing["l2_structure"], routing.get("l3_anchor_values", []), f"name:{slot.parts[0].field}" if by_name else slot.index, slot.token_class)

    def record(self, plan: Plan, source_id: str, routing: dict, family_id: str, session_dir: str, by_name: bool = False,
               family: str | None = None, names: dict | None = None) -> int:
        """Store every slot whose mapped parts all rest on sufficient provenance, under its key. `family` (a family_of
        string, '' when the source declares no family key) selects the cross-format name key on a self-describing surface;
        `names` maps a drafted field to the key/path the line carries."""
        n = 0
        for slot in plan.slots:
            mapped = [m for p in slot.parts for m in p.mappings]
            if any(m.provenance.get("category") not in SUFFICIENT for m in mapped):
                continue
            if not mapped and any(p.proposed_by in ("fixture", "model") for p in slot.parts):
                continue   # an unmapped slot counts only when the evidence (not a proposal) named it — e.g. Squid's `%[un` carried as a vendor extension
            k = self._key(slot, source_id, routing, by_name, family, names)
            self.entries[k] = {"split": slot.split, "parts": [asdict(p) for p in slot.parts], "event_class_uid": plan.event_class_uid, "event_class_name": plan.event_class_name,
                               "from": {"family_id": family_id, "session": session_dir}}
            n += 1
        return n

    def seed_from_pack(self, pack_dir: Path, source_id: str, samples: list[bytes] | None = None) -> int:
        """Record a promoted pack's answers for `source_id` under the cross-format name key. The caller's source binding
        ties the pack to this source (its families parsed this source's lines); the fields of its self-describing families
        are answers already given — by the vendor's documentation, a certificate or an operator. Recorded: fields whose
        every mapping rests on sufficient provenance, and fields the evidence itself named unmapped. Nothing else.
        The token class of each key is OBSERVED, by the same drafter a new format goes through: on `samples` (lines the
        pack parsed from this source — the console passes them out of the evidence store), else on the pack's own
        samples. A key seen in none of them has no observed class and is not recorded."""
        from .draft import draft
        pack_dir = Path(pack_dir)
        doc = json.loads((pack_dir / "pack.json").read_text(encoding="utf-8"))
        keyof = {a["anchor_id"]: a["locator"].get("key") for a in doc.get("anchors", []) if a.get("locator", {}).get("kind") == "key"}
        n = 0
        for fam in doc.get("families", []):
            rs = fam.get("routing_signature", {})
            if rs.get("l2_structure") not in SELF_DESCRIBING:
                continue
            family = family_of({keyof[a["anchor_id"]]: a["values"] for a in rs.get("l3_anchor_values", []) if keyof.get(a["anchor_id"])})
            spec = json.loads((pack_dir / fam["parser"]["spec_ref"]).read_text(encoding="utf-8"))
            obs = samples
            if not obs:
                obs = [l.rstrip(b"\r") for f in sorted((pack_dir / "samples").glob(f"{fam['family_id']}*")) for l in f.read_bytes().split(b"\n") if l.strip()]
            try:
                d = draft(obs, "seed") if obs else None
            except ValueError:
                d = None
            if d is None or d.l2 != rs.get("l2_structure"):
                continue
            path_of = {c["field"]: k for k, c in (d.spec["root"].get("keys") or {}).items()}
            observed = {path_of[sl.name]: sl.token_class for sl in d.structure.slots if sl.name in path_of}
            cells = spec["root"].get("keys") or {}
            m = fam["mapping"]
            by_field: dict[str, list] = {}
            for f in m.get("fields", []):
                if "path" in f:
                    by_field.setdefault(f["path"], []).append(f)
            unmapped = {u["path"]: u["name"] for u in m.get("unmapped", [])}
            for path, cell in cells.items():
                fs = by_field.get(cell["field"], [])
                if fs and any(f["provenance"].get("category") not in SUFFICIENT for f in fs):
                    continue
                if not fs and cell["field"] not in unmapped:
                    continue
                if path not in observed:
                    continue
                part = Part(cell["field"], cell.get("class", "text"), cell.get("kind", "semantic"), cell.get("coerce"), cell.get("null_values"),
                            [Mapping(f["ocsf_attribute"], dict(f["provenance"]), f.get("transform"), f.get("mandatory", False)) for f in fs],
                            unmapped.get(cell["field"]), [], "vendor_pack")
                cname = next((c["name"] for c in doc.get("ocsf", {}).get("pinned_classes", []) if c["uid"] == fam["event_class_uid"]), None)
                self.entries[name_key(source_id, family, path, observed[path])] = {"split": None, "parts": [asdict(part)], "event_class_uid": fam["event_class_uid"], "event_class_name": cname,
                                                                   "from": {"family_id": f"{doc['pack_id']}/{fam['family_id']}", "session": f"pack {doc['pack_id']} {doc['pack_version']}"}}
                n += 1
        return n

    def family_class(self, source_id: str, family: str) -> tuple[int, str] | None:
        """The one OCSF class earlier answers for this source's FAMILY were given in (None when there are none, when the
        source declares no family, or when they disagree). The family is named by the source's own key (type=traffic);
        its class was settled by evidence — a model's different proposal for the same family is not."""
        if not family:
            return None
        cs = {(e.get("event_class_uid"), e.get("event_class_name")) for k, e in self.entries.items() if k.startswith(f"{source_id}|named|{family}|")}
        return cs.pop() if len(cs) == 1 and None not in next(iter(cs)) else None

    def apply(self, plan: Plan, source_id: str, routing: dict, by_name: bool = False, family: str | None = None, names: dict | None = None) -> list[dict]:
        """Rewrite the plan's slots from stored resolutions with the same key. Returns what propagated."""
        hits = []
        for slot in plan.slots:
            k = self._key(slot, source_id, routing, by_name, family, names)
            e = self.entries.get(k)
            if e is None:
                continue
            if "|named|" in k:
                # across formats by name: an answer given for one OCSF class carries only into that class; the cell's
                # observed class stays the new format's own (the structure is the format's, the meaning is the name's)
                if e.get("event_class_uid") != plan.event_class_uid or len(e["parts"]) != 1 or len(slot.parts) != 1:
                    continue
                pd = copy.deepcopy(e["parts"][0])
                maps = []
                for m in pd.pop("mappings"):
                    prov = m["provenance"]
                    prov["evidence_ref"] = ((prov.get("evidence_ref") or "")[:800] + f" [carried by name from {e['from']['family_id']}: self-describing format, same source and family]").strip()
                    maps.append(Mapping(m["attribute"], prov, m.get("transform"), m.get("mandatory", False)))
                old = slot.parts[0]
                pd.update(field=old.field, cls=old.cls, candidates=[])
                if pd.get("coerce") is None:
                    pd["coerce"] = old.coerce
                slot.parts, slot.split = [Part(**pd, mappings=maps)], None
                hits.append({"slot_index": slot.index, "token_class": slot.token_class, "fields": [old.field], "from_family": e["from"]["family_id"],
                             "attributes": [m.attribute for m in maps], "unmapped_name": pd.get("unmapped_name"), "key": k, "by": "name"})
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
