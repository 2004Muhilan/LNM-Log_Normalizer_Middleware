"""Deterministic candidate enumerator over the pinned OCSF class tables.

Runs over the COMPLETE pinned table (subset guard: classes, never attributes), never over a model's
proposals. Candidates = leaf attributes whose type family accepts the slot's token class; survivors =
candidates that also pass the value-domain constraints checkable from the samples. The enumerated
set is stored in the acceptance record so every structural determination is auditable.

Policy knobs (recorded in acceptance/policy-v1.json): scalars only, leaf depth <= 2.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PINNED = ROOT / "ocsf" / "pinned"

# token class -> OCSF type families that accept it
ACCEPTS = {
    "integer": {"integer_t", "long_t", "port_t", "timestamp_t"},
    "float": {"float_t", "timestamp_t"},  # an epoch with a fractional part is float-shaped
    "ipv4": {"ip_t"},
    "ipv6": {"ip_t"},
    "ip": {"ip_t"},
    "mac": {"mac_t"},
    "url": {"url_t"},
    "hostname": {"hostname_t", "string_t"},
    "uuid": {"string_t", "resource_uid_t"},
    "hex": {"string_t"},
    "word": {"string_t"},
    "text": {"string_t"},
}


@dataclass
class Enumeration:
    table_hash: str
    depth: int
    candidates: list[dict]
    survivors: list[str]

    def record(self) -> dict:
        return {"method": "validator-enumeration", "table_hash": self.table_hash, "candidates": self.candidates, "survivors": self.survivors}


_tables: dict[int, dict] = {}


def load_table(class_uid: int) -> dict:
    if class_uid not in _tables:
        idx = json.loads((PINNED / "index.json").read_text(encoding="utf-8"))
        entry = next(c for c in idx["classes"] if c["uid"] == class_uid)
        _tables[class_uid] = json.loads((ROOT / entry["file"]).read_text(encoding="utf-8"))
    return _tables[class_uid]


# epoch_auto's disjoint plausible-date windows (contracts/README.md): 2000-01-01..2100-01-01 per unit
_EPOCH_WINDOWS = [(946684800 * 10 ** k, 4102444800 * 10 ** k) for k in (0, 3, 6, 9)]


def _epoch_window(samples: list[str]) -> bool:
    """True when every numeric sample falls in the SAME epoch_auto window — the same rule the runtime's
    `epoch_auto` coercion applies, so a timestamp_t survivor is one the coercion could actually accept.
    (P3 as shipped checked milliseconds only, and only integer-shaped samples; an epoch in seconds had
    no timestamp_t survivor and a fractional epoch skipped the check. Fixed at the P3->P4 boundary.)"""
    values = []
    for s in samples:
        try:
            values.append(float(s))
        except ValueError:
            return False
    if not values:
        return True
    return any(all(lo <= v < hi for v in values) for lo, hi in _EPOCH_WINDOWS)


def enumerate_candidates(class_uid: int, token_class: str, samples: list[str], max_depth: int = 2) -> Enumeration:
    table = load_table(class_uid)
    accepts = ACCEPTS.get(token_class, set())
    candidates, survivors = [], []
    for leaf in table["leaf_paths"]:
        t = leaf.get("type")
        # depth = number of dots; max_depth 2 admits src_endpoint.ip and http_request.url.url_string
        if t not in accepts or leaf["path"].count(".") > max_depth:
            continue
        basis = f"{t} accepts a {token_class} value"
        excluded = None
        if leaf.get("is_array"):
            excluded = "array attribute; the slot holds a scalar"
        elif t == "port_t" and any(not (0 <= int(s) <= 65535) for s in samples if s.lstrip("-").isdigit()):
            excluded = "values exceed the 0-65535 port range"
        elif t == "timestamp_t" and not _epoch_window(samples):
            excluded = "values fall in no single epoch_auto precision window (s/ms/us/ns, 2000-2100)"
        elif leaf.get("enum") and any(s not in leaf["enum"] for s in samples):
            # integer enums (action_id) and string enums (http_request.http_method) alike: the sample
            # values must all be members. (P3 excluded every enumerated attribute for non-integer slots,
            # which wrongly refuted http_method for a GET/CONNECT slot — found by the P4 provider tests.)
            excluded = "values are outside the attribute's enum"
        candidates.append({"attribute": leaf["path"], "type": t, "basis": basis if not excluded else f"excluded: {excluded}"})
        if not excluded:
            survivors.append(leaf["path"])
    return Enumeration(table["table_hash"], max_depth, candidates, survivors)
