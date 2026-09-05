"""Predict the runtime's normalized output from a span map and a pack mapping — the Python side of the
cross-stack differential test. Mirrors runtime/internal/normalize exactly (minus _lineage, which is
runtime state)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _set_path(out: dict, path: str, v):
    parts = path.split(".")
    cur = out
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = v


def _norm_number(v):
    return int(v) if isinstance(v, float) and v.is_integer() else v


def _transform(t: dict | None, v, strs: dict):
    if not t or t["kind"] == "none":
        return v, True
    k = t["kind"]
    if k in ("int", "epoch_ms"):
        try:
            return int(v), True
        except (TypeError, ValueError):
            return None, False
    if k == "float":
        try:
            return float(v), True
        except (TypeError, ValueError):
            return None, False
    if k == "lowercase":
        return str(v).lower(), True
    if k == "lookup":
        key = str(v)
        if key in t["lookup"]:
            return _norm_number(t["lookup"][key]), True
        if "default" in t:
            return _norm_number(t["default"]), True
        return None, False
    return None, False


def predict(span_map: dict, pack: dict, family: dict) -> dict:
    vals, strs, opaque, nulls = {}, {}, set(), set()
    for s in span_map["spans"]:
        if s.get("declared_null"):
            nulls.add(s["path"])
            continue
        if s["kind"] == "opaque":
            opaque.add(s["path"])
            continue
        if s["kind"] != "semantic" or "value" not in s:
            if s["kind"] == "semantic":
                opaque.add(s["path"])
            continue
        strs[s["path"]] = s["value"]
        vals[s["path"]] = s["coerced"]["value"] if "coerced" in s else s["value"]
    out = {"class_uid": family["event_class_uid"]}
    present, mapped = set(), {}
    for f in family["mapping"]["fields"]:
        mapped[f["ocsf_attribute"]] = f.get("path", "")
        if "constant" in f:
            _set_path(out, f["ocsf_attribute"], _norm_number(f["constant"]))
            present.add(f["ocsf_attribute"])
            continue
        if f["path"] not in vals:
            continue
        v, ok = _transform(f.get("transform"), vals[f["path"]], strs)
        if not ok:
            continue
        _set_path(out, f["ocsf_attribute"], v)
        present.add(f["ocsf_attribute"])
    absent = []
    for a in family["mapping"]["acceptance_snapshot"]["mandatory_attributes"]:
        if a in present:
            continue
        path = mapped.get(a)
        if a not in mapped:
            continue
        cause = "declared_null" if path in nulls else "uncoercible" if path in opaque else "structural"
        absent.append({"attribute": a, "cause": cause})
    unmapped = {u["name"]: vals[u["path"]] for u in family["mapping"]["unmapped"] if u["path"] in vals}
    if unmapped:
        out["unmapped"] = unmapped
    idx = {c["uid"]: c for c in json.loads((ROOT / "ocsf" / "pinned" / "index.json").read_text())["classes"]}
    out["category_uid"] = idx[family["event_class_uid"]]["category_uid"]
    out["type_uid"] = family["event_class_uid"] * 100 + int(out.get("activity_id", 0))
    out["metadata"] = {"version": pack["ocsf"]["version"], "product": {"vendor_name": pack["source"]["vendor"], "name": pack["source"]["product"]}}
    out["_absent"] = absent
    return out
