"""The lake's Parquet schema, per OCSF class, built from the PINNED class tables (ocsf/pinned/*.json) — never inferred.

DuckDB can infer nested structure from JSON, but it infers per batch: a field that is null in one batch and a number in
the next gets a different type in each file, and a lake's files stop agreeing. So every column of every file of a class
comes from the pinned table, and every file of that class has the identical schema (tested: test_lakewriter.py).

  object attribute with children  -> STRUCT(...)            the pinned tables cut recursion at a fixed depth; an object
  object cut at that depth        -> JSON                   they cut (or OCSF's free-form `unmapped`) is kept as JSON text
  is_array                        -> LIST(...)              (or JSON, for an array of cut objects)
  integer_t / port_t              -> INTEGER
  long_t / timestamp_t            -> BIGINT                 timestamps stay epoch milliseconds, as OCSF defines them
  float_t -> DOUBLE, boolean_t -> BOOLEAN, json_t -> JSON, every other type (string, ip, mac, url, uuid, hash, …) -> VARCHAR

Lineage columns come first and are flat — `event_id`, `raw_hash`, `segment_id`, `offset`, `length` plus the pack that
produced the event — so traceability survives into the lake; the whole `_lineage` block is also kept as JSON.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

SCALARS = {"integer_t": "INTEGER", "port_t": "INTEGER", "long_t": "BIGINT", "timestamp_t": "BIGINT", "float_t": "DOUBLE",
           "boolean_t": "BOOLEAN", "json_t": "JSON"}
LINEAGE = [("event_id", "VARCHAR", "event_id"), ("raw_hash", "VARCHAR", "raw_hash"), ("segment_id", "VARCHAR", "segment_id"),
           ("offset", "BIGINT", "offset"), ("length", "INTEGER", "length"), ("source_id", "VARCHAR", "source_id"),
           ("parser_id", "VARCHAR", "parser_id"), ("parser_version", "VARCHAR", "parser_version"), ("family_id", "VARCHAR", "family_id"),
           ("ingest_time", "BIGINT", "ingest_time")]


def q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


@lru_cache(maxsize=None)
def pinned_classes(pinned_dir: str) -> dict[int, dict]:
    idx = json.loads((Path(pinned_dir) / "index.json").read_text(encoding="utf-8"))
    out = {}
    for c in idx["classes"]:
        t = json.loads((Path(pinned_dir) / Path(c["file"]).name).read_text(encoding="utf-8"))   # the index names files from the repository root
        out[int(c["uid"])] = {"name": c["name"], "table": t, "table_hash": c["table_hash"]}
    return out


def _type(path: str, by_path: dict, children: dict) -> str:
    e = by_path[path]
    kids = children.get(path, [])
    if e["type"] == "object" or e["type"] == "object_t":
        if not kids:
            return "JSON"
        t = "STRUCT(" + ", ".join(f"{q(k.rsplit('.', 1)[1])} {_type(k, by_path, children)}" for k in kids) + ")"
    else:
        t = SCALARS.get(e["type"], "VARCHAR")
    return t + "[]" if e.get("is_array") and t != "JSON" else t


@lru_cache(maxsize=None)
def class_columns(pinned_dir: str, class_uid: int) -> tuple[tuple[str, str], ...]:
    """(top-level attribute, DuckDB type) for every attribute of the class, in the pinned table's order."""
    t = pinned_classes(pinned_dir)[class_uid]["table"]
    by_path = {e["path"]: e for e in t["leaf_paths"]}
    children: dict[str, list[str]] = {}
    for p in by_path:
        if "." in p:
            children.setdefault(p.rsplit(".", 1)[0], []).append(p)
    cols = []
    for a in t["attributes"]:
        n = a["name"]
        cols.append((n, _type(n, by_path, children) if n in by_path else SCALARS.get(a["type"], "VARCHAR")))
    return tuple(cols)


def read_columns(pinned_dir: str, class_uid: int | None) -> str:
    """The `columns={...}` argument of read_json: the class's attributes plus `_lineage` as JSON. A class with no pinned
    table (not one of the pinned classes) is read as one JSON column, `event`, so nothing is dropped and nothing is guessed."""
    if class_uid is None or class_uid not in pinned_classes(pinned_dir):
        return "{'json': 'JSON'}"
    cols = list(class_columns(pinned_dir, class_uid)) + [("_lineage", "JSON")]
    return "{" + ", ".join(f"'{n}': '{t}'" for n, t in cols) + "}"


def select_list(pinned_dir: str, class_uid: int | None) -> str:
    """Lineage columns first, flat; then the whole lineage as JSON; then every class attribute."""
    lin_src = "_lineage" if class_uid in pinned_classes(pinned_dir) else "(json->'$._lineage')"
    parts = [f"CAST(json_extract_string({lin_src}, '$.{src}') AS {t}) AS {q(n)}" for n, t, src in LINEAGE]
    parts.append(f"({lin_src})::JSON AS lineage")
    if class_uid in pinned_classes(pinned_dir):
        parts += [q(n) for n, _ in class_columns(pinned_dir, class_uid)]
    else:
        parts.append("json AS event")
    return ", ".join(parts)
