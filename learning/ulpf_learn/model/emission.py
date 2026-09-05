"""Emission schemas — what the grammar lets the model say.

Three schemas, all deliberately inside the subset of JSON Schema that llama.cpp's converter can turn
into a grammar (types, enum/const, properties + required + additionalProperties:false, arrays with
min/maxItems, anyOf of simple alternatives, bounded integers). No `if/then`, `not`, `propertyNames`,
`uniqueItems`, no `$ref`:

  class_schema()                 one of the pinned event classes
  proposal_schema(class_uid, n)  whole-proposal: N slots, each labelled with one attribute of the class
                                 (or `unmapped` / `compound`) and up to two ranked alternatives
  slot_schema(survivors)         per-slot: one label drawn from the validator's survivors (or `unmapped`)

`project_for_grammar(schema)` is the mechanical projection of an arbitrary contract schema onto that
subset: it drops the unsupported keywords and keeps everything else. It exists to measure what the
parser-spec contract loses under projection (docs/p4-report.md) — structure by construction, the
dropped conditionals by check — not because the provider emits parser specs: the provider emits labels
over the structure induction already fixed.
"""
from __future__ import annotations

import copy
import hashlib
import json

from ..enumerate_ import load_table

PINNED_CLASSES = {4001: "network_activity", 4002: "http_activity", 3002: "authentication", 2004: "detection_finding"}
UNMAPPED, COMPOUND = "unmapped", "compound"
UNSUPPORTED = {"if", "then", "else", "not", "propertyNames", "uniqueItems", "contains", "minContains", "maxContains",
               "patternProperties", "dependentRequired", "dependentSchemas", "unevaluatedProperties", "unevaluatedItems", "format", "$comment", "description", "default", "examples"}


def class_attributes(class_uid: int, max_depth: int = 2) -> list[str]:
    """Scalar leaf attributes of the pinned class at depth <= max_depth — the same admission the
    enumerator uses, so anything the model can name is something the validator can judge."""
    table = load_table(class_uid)
    out = []
    for leaf in table["leaf_paths"]:
        if leaf.get("is_array") or leaf["path"].count(".") > max_depth:
            continue
        if leaf.get("type") in (None, "object_t", "json_t"):
            continue
        out.append(leaf["path"])
    return out


def class_schema() -> dict:
    return {"type": "object", "additionalProperties": False, "required": ["event_class"],
            "properties": {"event_class": {"type": "string", "enum": sorted(PINNED_CLASSES.values())}}}


def proposal_schema(class_uid: int, n_slots: int) -> dict:
    attrs = class_attributes(class_uid)
    return {
        "type": "object", "additionalProperties": False, "required": ["slots"],
        "properties": {
            "slots": {
                "type": "array", "minItems": n_slots, "maxItems": n_slots,
                "items": {
                    "type": "object", "additionalProperties": False, "required": ["slot", "label"],
                    "properties": {
                        "slot": {"type": "integer", "minimum": 1, "maximum": n_slots},
                        "label": {"type": "string", "enum": attrs + [UNMAPPED, COMPOUND]},
                        "alternatives": {"type": "array", "maxItems": 2, "items": {"type": "string", "enum": attrs}},
                    },
                },
            },
        },
    }


def slot_schema(survivors: list[str]) -> dict:
    return {"type": "object", "additionalProperties": False, "required": ["label"],
            "properties": {"label": {"type": "string", "enum": list(survivors) + [UNMAPPED]},
                           "alternatives": {"type": "array", "maxItems": 2, "items": {"type": "string", "enum": list(survivors)}}}}


def project_for_grammar(schema: dict) -> tuple[dict, dict]:
    """Drop every keyword the grammar converter cannot express; report what was dropped, by keyword,
    with the JSON pointer of each occurrence. Purely mechanical — no judgement is applied."""
    dropped: dict[str, list[str]] = {}

    def note_nested(node, ptr):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in UNSUPPORTED:
                    dropped.setdefault(k, []).append(ptr)
                note_nested(v, f"{ptr}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                note_nested(v, f"{ptr}/{i}")

    def walk(node, ptr):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k in UNSUPPORTED:
                    dropped.setdefault(k, []).append(ptr)
                    note_nested(v, f"{ptr}/{k}")   # keywords lost inside a dropped subtree count too
                    continue
                out[k] = walk(v, f"{ptr}/{k}")
            return out
        if isinstance(node, list):
            return [walk(v, f"{ptr}/{i}") for i, v in enumerate(node)]
        return node

    return walk(copy.deepcopy(schema), ""), dropped


def schema_hash(schema: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
