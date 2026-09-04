from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import re2
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
PINNED_INDEX = ROOT / "ocsf" / "pinned" / "index.json"

KINDS = ("parser-spec", "span-map", "ambiguity-certificate", "parser-pack")
SUPPORTED_VERSIONS = {kind: {"1.0.0"} for kind in KINDS}
FORBIDDEN_KEYS = {"confidence", "probability", "score", "likelihood"}
CONSUMING_OPS = {"literal", "regex", "csv", "kv", "positional", "quoted", "optional", "repeated"}


class ValidationError(Exception):
    pass


_schema_cache: dict[str, Draft202012Validator] = {}


def schema_for(kind: str) -> Draft202012Validator:
    if kind not in _schema_cache:
        doc = json.loads((CONTRACTS / f"{kind}.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(doc)
        _schema_cache[kind] = Draft202012Validator(doc)
    return _schema_cache[kind]


def sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ----------------------------------------------------------------------------- generic

def _forbidden_keys(obj, path="$") -> list[str]:
    errs = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in FORBIDDEN_KEYS:
                errs.append(f"{path}.{k}: forbidden key (no numeric confidence in any contract)")
            errs.extend(_forbidden_keys(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            errs.extend(_forbidden_keys(v, f"{path}[{i}]"))
    return errs


def _schema_errors(kind: str, doc) -> list[str]:
    v = schema_for(kind)
    return [f"schema: {'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message}" for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))]


# ----------------------------------------------------------------------------- parser spec

def _re2_ok(pattern: str) -> str | None:
    try:
        re2.compile(pattern)
        return None
    except Exception as ex:  # noqa: BLE001
        return str(ex)


def _named_groups(pattern: str) -> set[str]:
    try:
        return set(re2.compile(pattern).groupindex.keys())
    except Exception:  # noqa: BLE001
        return set()


def _walk_spec(step, ctx: dict, depth: int, path: str):
    errs = ctx["errs"]
    if depth > ctx["bounds"]["max_nesting"]:
        errs.append(f"{path}: nesting depth {depth} exceeds bounds.max_nesting")
        return
    if isinstance(step, list):
        for i, s in enumerate(step):
            _walk_spec(s, ctx, depth, f"{path}[{i}]")
        return
    op = step.get("op")
    if op == "regex":
        err = _re2_ok(step["pattern"])
        if err:
            errs.append(f"{path}: regex does not compile under RE2: {err}")
        else:
            groups = _named_groups(step["pattern"])
            caps = set(step.get("captures", {}))
            if groups != caps:
                errs.append(f"{path}: named groups {sorted(groups)} != captures {sorted(caps)}")
        for name, cell in step.get("captures", {}).items():
            _cell(cell, ctx, depth + 1, f"{path}.captures.{name}")
    elif op == "literal":
        pass
    elif op == "csv":
        for i, c in enumerate(step["fields"]):
            _csv_cell(c, ctx, depth + 1, f"{path}.fields[{i}]")
    elif op == "kv":
        err = _re2_ok(step["key_pattern"])
        if err:
            errs.append(f"{path}: key_pattern does not compile under RE2: {err}")
        for k, c in step["keys"].items():
            _csv_cell(c, ctx, depth + 1, f"{path}.keys[{k}]")
    elif op == "positional":
        for i, s in enumerate(step["slots"]):
            if "field" in s:
                _cell(s, ctx, depth + 1, f"{path}.slots[{i}]")
            elif "token" in s:
                _walk_spec(s["token"]["parse"], ctx, depth + 1, f"{path}.slots[{i}].token.parse")
            elif "step" in s:
                _walk_spec(s["step"], ctx, depth + 1, f"{path}.slots[{i}].step")
        if step.get("tail"):
            _cell(step["tail"], ctx, depth + 1, f"{path}.tail")
    elif op == "quoted":
        _cell(step["content"], ctx, depth + 1, f"{path}.content")
        if "parse" in step:
            _walk_spec(step["parse"], ctx, depth + 1, f"{path}.parse")
    elif op == "optional":
        _walk_spec(step["step"], ctx, depth + 1, f"{path}.step")
    elif op == "repeated":
        if step["min"] > step["max"]:
            errs.append(f"{path}: repeated.min > max")
        if step["max"] > ctx["bounds"]["max_repeat"]:
            errs.append(f"{path}: repeated.max exceeds bounds.max_repeat")
        _walk_spec(step["step"], ctx, depth + 1, f"{path}.step")
        if "separator" in step:
            _walk_spec(step["separator"], ctx, depth + 1, f"{path}.separator")
    else:
        errs.append(f"{path}: unknown op {op!r}")


def _csv_cell(c, ctx, depth, path):
    if "parse" in c:
        _walk_spec(c["parse"], ctx, depth, f"{path}.parse")
    else:
        _cell(c, ctx, depth, path)


def _cell(cell, ctx, depth, path):
    f = cell["field"]
    if f in ctx["fields"]:
        ctx["errs"].append(f"{path}: duplicate field path {f!r}")
    ctx["fields"].add(f)
    if "decode" in cell and "then" in cell["decode"]:
        _walk_spec(cell["decode"]["then"], ctx, depth + 1, f"{path}.decode.then")
    if len(ctx["fields"]) > ctx["bounds"]["max_fields"]:
        ctx["errs"].append(f"{path}: field count exceeds bounds.max_fields")


def spec_fields(spec: dict) -> set[str]:
    ctx = {"errs": [], "fields": set(), "bounds": spec["bounds"]}
    _walk_spec(spec["root"], ctx, 1, "$.root")
    return ctx["fields"]


def _check_parser_spec(doc: dict) -> list[str]:
    ctx = {"errs": [], "fields": set(), "bounds": doc["bounds"]}
    _walk_spec(doc["root"], ctx, 1, "$.root")
    root = doc["root"]
    first = root[0] if isinstance(root, list) else root
    while isinstance(first, list):
        first = first[0]
    if first.get("op") not in CONSUMING_OPS:
        ctx["errs"].append("$.root: root must begin with a consuming op")
    return ctx["errs"]


# ----------------------------------------------------------------------------- span map

def _check_span_map(doc: dict) -> list[str]:
    errs = []
    if doc["status"] != "ok":
        return errs
    lengths = {b["id"]: b["length"] for b in doc["buffers"]}
    if "raw" not in lengths:
        errs.append("buffers: no 'raw' buffer")
        return errs
    if lengths["raw"] != doc["event"]["raw_length"]:
        errs.append("buffers[raw].length != event.raw_length")
    by_buf: dict[str, list] = {b: [] for b in lengths}
    for i, s in enumerate(doc["spans"]):
        if s["buffer"] not in lengths:
            errs.append(f"spans[{i}]: unknown buffer {s['buffer']!r}")
            continue
        if s["start"] >= s["end"]:
            errs.append(f"spans[{i}]: start >= end")
        by_buf[s["buffer"]].append((s["start"], s["end"], i, s))
    for buf, spans in by_buf.items():
        spans.sort()
        pos = 0
        for start, end, i, s in spans:
            if start < pos:
                errs.append(f"spans[{i}]: overlap in buffer {buf!r} at {start} (expected >= {pos})")
            elif start > pos:
                errs.append(f"spans[{i}]: gap in buffer {buf!r} [{pos}:{start})")
            pos = max(pos, end)
            if s["kind"] == "literal" and "text" in s and len(s["text"].encode("utf-8")) != end - start:
                errs.append(f"spans[{i}]: literal text length != span length")
        if pos != lengths[buf]:
            errs.append(f"buffer {buf!r}: spans cover [0:{pos}) but length is {lengths[buf]}")
        elif lengths[buf] > 0 and not spans:
            errs.append(f"buffer {buf!r}: no spans")
    raw_b64 = doc["event"].get("raw_base64")
    if raw_b64 is not None:
        raw = base64.b64decode(raw_b64)
        if len(raw) != doc["event"]["raw_length"]:
            errs.append("event.raw_base64 length != raw_length")
        if sha256_bytes(raw) != doc["event"]["raw_hash"]:
            errs.append("event.raw_base64 sha256 != raw_hash")
        for i, s in enumerate(doc["spans"]):
            if s["buffer"] != "raw":
                continue
            seg = raw[s["start"]:s["end"]]
            if s["kind"] == "literal" and "text" in s and seg != s["text"].encode("utf-8"):
                errs.append(f"spans[{i}]: literal text does not match raw bytes")
            if s["kind"] == "semantic" and "value" in s and "encoding" not in s and seg != s["value"].encode("utf-8"):
                errs.append(f"spans[{i}]: value does not match raw bytes")
    return errs


# ----------------------------------------------------------------------------- certificate

def _check_certificate(doc: dict) -> list[str]:
    errs = _forbidden_keys(doc)
    cand = {c["attribute"] for c in doc["enumeration"]["candidates"]}
    surv = set(doc["enumeration"]["survivors"])
    class_leaves = _pinned_leaf_paths().get(doc["event_class"]["uid"])
    if class_leaves is not None:
        unknown = sorted(cand - class_leaves)
        if unknown:
            errs.append(f"enumeration.candidates not in the pinned class table: {unknown}")
    if not surv <= cand:
        errs.append(f"enumeration.survivors not a subset of candidates: {sorted(surv - cand)}")
    ranked = [r["attribute"] for r in doc["ranked_candidates"]]
    if len(set(ranked)) != len(ranked):
        errs.append("ranked_candidates: duplicate attribute")
    if not set(ranked) <= surv:
        errs.append(f"ranked_candidates not a subset of survivors: {sorted(set(ranked) - surv)}")
    ranks = [r["rank"] for r in doc["ranked_candidates"]]
    if ranks != list(range(1, len(ranks) + 1)):
        errs.append("ranked_candidates: ranks must be 1..n in order")
    if doc["status"] in ("ambiguous", "unresolved") and len(surv) < 2:
        errs.append(f"status {doc['status']} requires at least two survivors")
    if doc["status"] == "ambiguous":
        if doc["request"]["ambiguity_class"] != doc["evidence"]["discriminator"].get("ambiguity_class"):
            errs.append("request.ambiguity_class != evidence.discriminator.ambiguity_class")
        if doc["request"]["selected"]["rank"] != 1:
            errs.append("request.selected must have rank 1")
        if doc["field"]["path"] not in doc["request"]["selected"]["resolves"]:
            errs.append("request.selected.resolves must include this certificate's field")
    if doc["status"] == "resolved":
        if doc["resolution"]["resolved_to"] not in surv:
            errs.append("resolution.resolved_to must be one of enumeration.survivors")
        if doc["resolution"]["propagation_scope"]["source_id"] != doc["source_id"]:
            errs.append("resolution.propagation_scope.source_id != source_id")
        ps, cx = doc["resolution"]["propagation_scope"], doc["context"]
        for k in ("l1_envelope", "l2_structure", "l3_anchors", "slot_index", "token_class"):
            if ps[k] != cx[k]:
                errs.append(f"resolution.propagation_scope.{k} != context.{k}")
    return errs


# ----------------------------------------------------------------------------- pack

_leaf_cache: dict[int, set[str]] | None = None


def _pinned_leaf_paths() -> dict[int, set[str]]:
    """uid -> set of leaf attribute paths from the pinned (complete) class tables; empty when absent."""
    global _leaf_cache
    if _leaf_cache is None:
        _leaf_cache = {}
        if PINNED_INDEX.exists():
            for c in json.loads(PINNED_INDEX.read_text())["classes"]:
                table = json.loads((ROOT / c["file"]).read_text(encoding="utf-8"))
                _leaf_cache[c["uid"]] = {l["path"] for l in table["leaf_paths"]}
    return _leaf_cache


def _check_pack(doc: dict, pack_dir: Path | None) -> list[str]:
    errs = _forbidden_keys(doc)
    fam_ids = [f["family_id"] for f in doc["families"]]
    if len(set(fam_ids)) != len(fam_ids):
        errs.append("families: duplicate family_id")
    anchor_ids = {a["anchor_id"] for a in doc["anchors"]}
    pinned_uids = {c["uid"] for c in doc["ocsf"]["pinned_classes"]}
    if PINNED_INDEX.exists():
        idx = {c["uid"]: c["table_hash"] for c in json.loads(PINNED_INDEX.read_text())["classes"]}
        for c in doc["ocsf"]["pinned_classes"]:
            if c["uid"] not in idx:
                errs.append(f"ocsf.pinned_classes: class {c['uid']} is not in ocsf/pinned/index.json")
            elif idx[c["uid"]] != c["table_hash"]:
                errs.append(f"ocsf.pinned_classes: table_hash for class {c['uid']} does not match the pinned (complete) table — subset guard")
    dsl_hashes, mapping_hashes = [], []
    all_paths: set[str] = set()
    leaf_paths = _pinned_leaf_paths()
    for fi, fam in enumerate(doc["families"]):
        p = f"families[{fi}]"
        if fam["event_class_uid"] not in pinned_uids:
            errs.append(f"{p}: event_class_uid not among ocsf.pinned_classes")
        for aid in fam["routing_signature"]["l3_anchor_ids"]:
            if aid not in anchor_ids:
                errs.append(f"{p}: l3_anchor_id {aid!r} not declared in anchors")
        spec_fields_set: set[str] | None = None
        if pack_dir is not None:
            spec_path = pack_dir / fam["parser"]["spec_ref"]
            if not spec_path.exists():
                errs.append(f"{p}: spec_ref {fam['parser']['spec_ref']} not found")
            else:
                raw = spec_path.read_bytes()
                if sha256_bytes(raw) != fam["parser"]["dsl_hash"]:
                    errs.append(f"{p}: dsl_hash does not match sha256 of {fam['parser']['spec_ref']}")
                spec = json.loads(raw)
                sub = validate_document("parser-spec", spec)
                errs.extend(f"{p}: spec: {e}" for e in sub)
                if spec.get("spec_id") != fam["parser"]["spec_id"]:
                    errs.append(f"{p}: spec_id does not match the referenced spec")
                if not sub:
                    spec_fields_set = spec_fields(spec)
            for cid in fam["certificates"]:
                cpath = pack_dir / "certificates" / f"{cid}.json"
                if not cpath.exists():
                    errs.append(f"{p}: certificate {cid} not found under certificates/")
        dsl_hashes.append(fam["parser"]["dsl_hash"])
        m = fam["mapping"]
        if sha256_bytes(canonical(m["fields"])) != m["mapping_hash"]:
            errs.append(f"{p}: mapping_hash != sha256 of canonical mapping.fields")
        mapping_hashes.append(m["mapping_hash"])
        mapped_attrs = {f["ocsf_attribute"] for f in m["fields"]}
        paths = [f["path"] for f in m["fields"]]
        attrs_list = [f["ocsf_attribute"] for f in m["fields"]]
        if len(set(attrs_list)) != len(attrs_list):
            errs.append(f"{p}: mapping.fields: an OCSF attribute is mapped more than once")
        all_paths |= set(paths)
        class_leaves = leaf_paths.get(fam["event_class_uid"])
        for i, f in enumerate(m["fields"]):
            prov = f["provenance"]
            if class_leaves is not None and f["ocsf_attribute"] not in class_leaves:
                errs.append(f"{p}.mapping.fields[{i}]: {f['ocsf_attribute']!r} is not an attribute of the pinned class table")
            if f["mandatory"] and prov["category"] == "model_proposal":
                errs.append(f"{p}.mapping.fields[{i}]: mandatory field with model_proposal provenance (invariant 4)")
            if prov["category"] == "structural_determination" and prov.get("enumerated_survivors") != [f["ocsf_attribute"]]:
                errs.append(f"{p}.mapping.fields[{i}]: structural_determination requires enumerated_survivors == [ocsf_attribute]")
            if f["ocsf_attribute"] in m["acceptance_snapshot"]["mandatory_attributes"] and not f["mandatory"]:
                errs.append(f"{p}.mapping.fields[{i}]: attribute is in mandatory_attributes but mandatory is false")
            if spec_fields_set is not None and f["path"] not in spec_fields_set:
                errs.append(f"{p}.mapping.fields[{i}]: path {f['path']!r} is not a field of the spec")
        missing = set(m["acceptance_snapshot"]["mandatory_attributes"]) - mapped_attrs
        if missing:
            errs.append(f"{p}: mandatory attributes not mapped (critical coverage < 100%): {sorted(missing)}")
        known_paths = set(paths) | {u["path"] for u in m["unmapped"]}
        for i, r in enumerate(fam["resolutions"]):
            for fp in r["fields"]:
                if fp not in known_paths:
                    errs.append(f"{p}.resolutions[{i}]: field {fp!r} is neither a mapped nor an unmapped path")
            if r["propagation_scope"]["source_id"] != doc["source"]["source_id"]:
                errs.append(f"{p}.resolutions[{i}]: propagation_scope.source_id != source.source_id")
        if fam["validation"]["held_out"]["passed"] > fam["validation"]["held_out"]["samples"]:
            errs.append(f"{p}: held_out.passed > samples")
    if doc["tiebreaker_field"] is not None and doc["tiebreaker_field"] not in all_paths:
        errs.append("tiebreaker_field is not a mapped path in any family")
    if sha256_bytes("".join(dsl_hashes).encode()) != doc["hashes"]["dsl_hash"]:
        errs.append("hashes.dsl_hash != sha256 of concatenated family dsl_hash values")
    if sha256_bytes("".join(mapping_hashes).encode()) != doc["hashes"]["mapping_hash"]:
        errs.append("hashes.mapping_hash != sha256 of concatenated family mapping_hash values")
    return errs


# ----------------------------------------------------------------------------- entry points

def validate_document(kind: str, doc, pack_dir: Path | None = None) -> list[str]:
    if kind not in KINDS:
        raise ValidationError(f"unknown contract kind {kind!r}")
    if not isinstance(doc, dict):
        return ["document is not a JSON object"]
    ver = doc.get("schema_version")
    if ver not in SUPPORTED_VERSIONS[kind]:
        return [f"unsupported schema_version {ver!r} for {kind} (supported: {sorted(SUPPORTED_VERSIONS[kind])}) — refused"]
    errs = _schema_errors(kind, doc)
    if errs:
        return errs
    if kind == "parser-spec":
        return _check_parser_spec(doc)
    if kind == "span-map":
        return _check_span_map(doc)
    if kind == "ambiguity-certificate":
        return _check_certificate(doc)
    return _check_pack(doc, pack_dir)


def validate_file(kind: str, path: Path) -> list[str]:
    path = Path(path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as ex:
        return [f"invalid JSON: {ex}"]
    return validate_document(kind, doc, pack_dir=path.parent if kind == "parser-pack" else None)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--golden":
        index = json.loads((CONTRACTS / "golden" / "index.json").read_text())
        bad = 0
        for v in index["vectors"]:
            errs = validate_file(v["kind"], CONTRACTS / "golden" / v["path"])
            outcome = "valid" if not errs else "invalid"
            matches = v.get("reason_match", [])
            matches = [matches] if isinstance(matches, str) else matches
            ok = outcome == v["expect"] and (v["expect"] == "valid" or any(m in e for m in matches for e in errs))
            bad += 0 if ok else 1
            print(f"{'PASS' if ok else 'FAIL'}  {v['kind']:22s} {v['path']:60s} expect={v['expect']:7s} got={outcome}")
            if not ok:
                for e in errs[:5]:
                    print(f"        {e}")
        print(f"{len(index['vectors']) - bad}/{len(index['vectors'])} vectors behaved as expected")
        return 1 if bad else 0
    if len(argv) != 3:
        print("usage: python -m ulpf_contracts.validate <kind> <file> | --golden", file=sys.stderr)
        return 2
    errs = validate_file(argv[1], Path(argv[2]))
    for e in errs:
        print(e)
    print("VALID" if not errs else f"INVALID ({len(errs)} errors)")
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
