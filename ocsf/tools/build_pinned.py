#!/usr/bin/env python3
"""Generate the pinned OCSF class tables from the schema server's compiled 1.3.0 export.

Subset guard (architecture v0.7 §3.3): pinning selects event CLASSES, never attributes within a
class. Each table is the class's complete top-level attribute set exactly as the export defines it
(own + inherited + every applied profile), with objects expanded to leaf paths to a bounded depth so
the P3 candidate enumerator has typed leaf paths to enumerate over. Nothing is hand-typed.

Outputs: ocsf/pinned/<class>.json and ocsf/pinned/index.json (with per-table sha256).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "ocsf" / "cache"
PINNED = ROOT / "ocsf" / "pinned"

PINNED_CLASSES = ["network_activity", "http_activity", "authentication", "detection_finding"]
MAX_DEPTH = 4  # leaf-path expansion depth; recursion (e.g. process.parent_process) is cut and flagged

SCALAR_FAMILY = {
    "integer_t": "integer", "long_t": "integer", "port_t": "integer", "timestamp_t": "integer",
    "float_t": "float", "boolean_t": "boolean",
    "string_t": "string", "datetime_t": "string", "email_t": "string", "file_hash_t": "string",
    "file_name_t": "string", "hostname_t": "string", "process_name_t": "string", "resource_uid_t": "string",
    "subnet_t": "string", "json_t": "json", "bytestring_t": "string",
    "ip_t": "ip", "mac_t": "mac", "url_t": "url",
}


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def leaf_paths(objects: dict, attrs: dict, prefix: str, depth: int, seen: tuple) -> list[dict]:
    out = []
    for name in sorted(attrs):
        a = attrs[name]
        path = f"{prefix}{name}"
        t = a.get("type")
        if t == "object_t":
            obj = a.get("object_type")
            if obj in seen or depth >= MAX_DEPTH:
                out.append({"path": path, "type": "object", "object_type": obj, "is_array": bool(a.get("is_array")),
                            "requirement": a.get("requirement", "optional"), "truncated": "recursion" if obj in seen else "depth"})
                continue
            out.append({"path": path, "type": "object", "object_type": obj, "is_array": bool(a.get("is_array")),
                        "requirement": a.get("requirement", "optional")})
            out.extend(leaf_paths(objects, objects[obj]["attributes"], path + ".", depth + 1, seen + (obj,)))
        else:
            entry = {"path": path, "type": t, "family": SCALAR_FAMILY.get(t, "string"), "is_array": bool(a.get("is_array")),
                     "requirement": a.get("requirement", "optional")}
            if "enum" in a:
                entry["enum"] = sorted(a["enum"].keys(), key=lambda k: (len(k), k))
            out.append(entry)
    return out


def main() -> int:
    exp = json.loads((CACHE / "ocsf-1.3.0-export.json").read_text(encoding="utf-8"))
    manifest = json.loads((PINNED / "manifest.json").read_text())
    assert exp["version"] == manifest["ocsf_version"]
    export_sha = hashlib.sha256((CACHE / "ocsf-1.3.0-export.json").read_bytes()).hexdigest()
    assert export_sha == manifest["export"]["sha256"], "export cache does not match manifest"

    objects = exp["objects"]
    index = {"ocsf_version": exp["version"], "export_sha256": export_sha, "generator": "ocsf/tools/build_pinned.py",
             "rule": "classes are pinned complete; no attribute within a class is omitted", "classes": []}
    for cname in PINNED_CLASSES:
        cls = exp["classes"][cname]
        attrs = cls["attributes"]
        top = []
        for name in sorted(attrs):
            a = attrs[name]
            row = {"name": name, "type": a.get("type"), "requirement": a.get("requirement", "optional"),
                   "group": a.get("group"), "is_array": bool(a.get("is_array"))}
            if a.get("object_type"):
                row["object_type"] = a["object_type"]
            if a.get("profile"):
                row["profile"] = a["profile"]
            if "enum" in a:
                row["enum"] = sorted(a["enum"].keys(), key=lambda k: (len(k), k))
            top.append(row)
        table = {
            "ocsf_version": exp["version"],
            "class_name": cname,
            "class_uid": cls["uid"],
            "caption": cls.get("caption"),
            "category": cls.get("category"),
            "category_uid": cls.get("category_uid"),
            "extends": cls.get("extends"),
            "profiles_applied": cls.get("profiles", []),
            "top_level_attribute_count": len(top),
            "attributes": top,
            "leaf_paths": leaf_paths(objects, attrs, "", 0, ()),
        }
        table_sha = sha256(canonical(table))
        table["table_hash"] = table_sha
        (PINNED / f"{cname}.json").write_text(json.dumps(table, indent=1) + "\n", encoding="utf-8")
        index["classes"].append({"name": cname, "uid": cls["uid"], "category_uid": cls.get("category_uid"), "top_level_attribute_count": len(top),
                                 "leaf_path_count": len(table["leaf_paths"]), "table_hash": table_sha,
                                 "file": f"ocsf/pinned/{cname}.json"})
        print(f"{cname:20s} uid={cls['uid']:5d} top-level={len(top):3d} leaves={len(table['leaf_paths']):5d} {table_sha[:23]}")
    (PINNED / "index.json").write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
