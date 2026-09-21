"""Spec drafting for SELF-DESCRIBING formats (laptop branch, 2026-09-22): JSON, XML, key=value (LEEF's attribute
list included) and CSV. Deterministic, no model: the STRUCTURE of such a line is written in the line itself — its
keys, its element paths, its cell count — so the parser spec is read off the samples the way `induce` reads a
whitespace template off positional text. The P4 boundary is unchanged: the model labels fields, it never builds a spec.

What a drafted spec is:
  * one cell per key / path / column seen in the samples, the cell's class the class every sample agrees on;
  * UNKNOWN KEYS ARE REJECTED, deliberately. JSON and XML have no L4 sketch in the router (nothing cheap to count), so
    a key nobody has seen would otherwise be carried opaque and SILENTLY: a format change that no monitor notices.
    With `reject`, a changed format fails its parse, the drift monitor sees routed-then-refused events, and the
    spec is drafted again from the new lines. The cost, stated: a rare optional key that the samples did not happen
    to contain quarantines its events until then (bytes kept, as always).
  * no semantics. Names in a line are the vendor's names — a hint the model reads, never evidence.

`surface()` is the Python twin of the router's detectL2 (runtime/internal/route/router.go), so that a drafted
family is one the router will actually route to. The draft is verified before it is returned: every sample must parse
under it in the reference executor (and the promoted pack is verified by the Go engine like any other).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .induce import Structure

_KVTOK = re.compile(rb"^[A-Za-z_][A-Za-z0-9_.\-]*=")
_LEEF = re.compile(rb"^LEEF:(\d+)(?:\.\d+)?\|")
BOUNDS = {"max_event_bytes": 16384, "max_fields": 128, "max_nesting": 4, "max_repeat": 16}


def leef_split(raw: bytes) -> tuple[int, str] | None:
    """Twin of frame.UnwrapLEEF: (payload offset, declared delimiter or '') — None when the line is not LEEF."""
    m = _LEEF.match(raw)
    if not m:
        return None
    pos = m.end()
    for _ in range(4):
        e = raw.find(b"|", pos)
        if e < 0:
            return None
        pos = e + 1
    delim = ""
    if int(m.group(1)) >= 2:
        e = raw.find(b"|", pos)
        if 0 < e - pos <= 4:
            d = raw[pos:e].decode("latin-1")
            h = d[2:] if d.startswith("0x") else d[1:] if d.startswith("x") else None
            if len(d) == 1 or (h is not None and len(h) == 2 and all(c in "0123456789abcdefABCDEF" for c in h)):
                delim, pos = d, e + 1
    return (pos, delim) if pos < len(raw) else None


def leef_payload(raw: bytes) -> bytes:
    s = leef_split(raw)
    return raw[s[0]:] if s else raw


def _csv_cells(b: bytes) -> int:
    n, inq, i = 1, False, 0
    while i < len(b):
        c = b[i:i + 1]
        if c == b'"':
            if inq and b[i + 1:i + 2] == b'"':
                i += 1
            else:
                inq = not inq
        elif c == b"," and not inq:
            n += 1
        i += 1
    return n


def surface(payload: bytes) -> str:
    t = payload.lstrip(b" \t")
    if t[:1] in (b"{", b"["):
        return "json"
    if len(t) > 1 and t[:1] == b"<" and (t[1:2] in (b"?", b"!", b"_") or t[1:2].isalpha()):
        return "xml"
    if sum(1 for tok in payload.split()[:6] if _KVTOK.match(tok)) >= 3:
        return "kv"
    if _csv_cells(payload) >= 9:
        return "csv"
    return "tokens"


def _kv_pairs(payload: bytes) -> list[str]:
    """Keys in order, exactly as the router's kvPairs counts them (whitespace separated, double-quoted values)."""
    keys, i, b = [], 0, payload
    while i < len(b):
        while i < len(b) and b[i:i + 1] in (b" ", b"\t"):
            i += 1
        s = i
        while i < len(b) and b[i:i + 1] not in (b"=", b" ", b"\t"):
            i += 1
        if i >= len(b) or b[i:i + 1] != b"=":
            while i < len(b) and b[i:i + 1] not in (b" ", b"\t"):
                i += 1
            continue
        keys.append(b[s:i].decode("utf-8", "replace"))
        i += 1
        if b[i:i + 1] == b'"':
            i += 1
            while i < len(b) and b[i:i + 1] != b'"':
                i += 2 if b[i:i + 1] == b"\\" else 1
            i += 1
        else:
            while i < len(b) and b[i:i + 1] not in (b" ", b"\t"):
                i += 1
    return keys


def _json_leaves(v, path: str, out: list[str]):
    if isinstance(v, dict):
        for k, x in v.items():
            _json_leaves(x, f"{path}.{k}" if path else k, out)
    elif path and path not in out:
        out.append(path)   # scalars, and an array as ONE verbatim value (the json op's rule)


def _xml_leaves(el, path: str, out: list[str]):
    for a in el.attrib:
        if f"{path}@{a}" not in out:
            out.append(f"{path}@{a}")
    kids = list(el)
    if not kids:
        if (el.text or "").strip() and path not in out:
            out.append(path)
    for k in kids:
        _xml_leaves(k, f"{path}/{k.tag}", out)


def _field_names(paths: list[str]) -> dict[str, str]:
    clean = lambda s: re.sub(r"[^A-Za-z0-9_]", "_", s)
    short = {p: clean(re.split(r"[./@]", p)[-1]) for p in paths}
    out = {}
    for p in paths:
        f = short[p] if list(short.values()).count(short[p]) == 1 else clean(p)
        out[p] = f if re.match(r"[A-Za-z_]", f) else "f_" + f
    return out


@dataclass
class Draft:
    l1: str                 # raw | leef
    l2: str                 # json | xml | kv | csv
    spec: dict
    structure: Structure
    routing: dict
    named: bool             # the line names its own fields (json/xml/kv): resolutions propagate by NAME, not by position


def draft(lines: list[bytes], spec_id: str) -> Draft | None:
    """None when the samples are whitespace tokens (positional/template text): that is `induce`'s job."""
    from .model.structure_from_spec import structure_from_spec
    leef = [leef_split(l) for l in lines]
    l1 = "leef" if lines and all(leef) else "raw"
    payloads = [l[s[0]:] for l, s in zip(lines, leef)] if l1 == "leef" else list(lines)
    kinds = {surface(p) for p in payloads}
    if kinds == {"tokens"} or not payloads:
        return None
    if len(kinds) != 1:
        raise ValueError(f"the samples are not one format ({sorted(kinds)}): nothing is drafted from a mixed capture")
    l2 = kinds.pop()
    cell = lambda f: {"field": f, "kind": "semantic", "class": "text"}
    lo = hi = 0
    if l2 == "json":
        paths: list[str] = []
        for p in payloads:
            _json_leaves(json.loads(p), "", paths)
        names = _field_names(paths)
        root = {"op": "json", "unknown_keys": "reject", "keys": {p: cell(names[p]) for p in paths}}
    elif l2 == "xml":
        import xml.etree.ElementTree as ET
        paths = []
        for p in payloads:
            el = ET.fromstring(p.decode("utf-8"))
            _xml_leaves(el, el.tag, paths)
        names = _field_names(paths)
        root = {"op": "xml", "unknown": "reject", "paths": {p: cell(names[p]) for p in paths}}
    elif l2 == "kv":
        paths, counts = [], []
        for p in payloads:
            ks = _kv_pairs(p); counts.append(len(ks))
            paths += [k for k in ks if k not in paths]
        lo, hi = min(counts), max(counts)
        names = _field_names(paths)
        delims = {s[1] for s in leef} if l1 == "leef" else set()
        sep = {"char": "\t"} if l1 == "leef" and delims == {""} else {"whitespace_run": True}
        if l1 == "leef" and delims != {""}:
            raise ValueError("LEEF 2.0 with a declared delimiter: the router counts whitespace-separated pairs only; not drafted")
        root = {"op": "kv", "pair_separator": sep, "key_value_separator": "=", "quote": '"', "escape": "backslash", "key_pattern": "[A-Za-z_][A-Za-z0-9_.\\-]*",
                "keys": {p: cell(names[p]) for p in paths}, "unknown_keys": "reject", "order": "any"}
    else:
        n = {_csv_cells(p) for p in payloads}
        if len(n) != 1:
            raise ValueError(f"csv samples of {sorted(n)} cells: one family has one cell count")
        lo = hi = n.pop()
        root = {"op": "csv", "delimiter": ",", "quote": '"', "escape": "doubled", "fields": [cell(f"pos_{i + 1}") for i in range(lo)], "extra_fields": "reject", "missing_fields": "reject"}
    spec = {"schema_version": "1.2.0" if l2 in ("json", "xml") else "1.1.0", "spec_id": spec_id,
            "description": f"Drafted from {len(lines)} samples: the {l2} structure the lines themselves carry; unknown keys rejected; no semantics.",
            "regex_dialect": "re2", "bounds": dict(BOUNDS), "root": root}
    structure, kept = structure_from_spec(json.dumps(spec).encode(), payloads)
    if len(kept) != len(payloads):
        raise ValueError(f"{len(payloads) - len(kept)} sample(s) do not parse under the drafted {l2} spec: not drafted")
    if l2 == "csv":
        for s in structure.slots:
            s.name = None   # a csv column has a position, not a name
    arity = str(lo) if lo == hi else f"{lo}-{hi}"
    routing = {"l1_envelope": l1, "l2_structure": l2, "l3_anchor_ids": [], "l3_structural_literals": [],
               "l4_sketch": {"arity_bucket": arity if l2 in ("kv", "csv") else str(structure.arity), "token_class_sequence": [s.token_class for s in structure.slots]}}
    return Draft(l1, l2, spec, structure, routing, l2 != "csv")
