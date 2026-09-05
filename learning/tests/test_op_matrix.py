"""Executor alignment: every contract enum value has a micro-vector, every vector validates, and the
reference executor and the Go engine produce identical span maps for every input of every vector."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from ulpf_contracts import validate_document
from ulpf_learn import dslexec

import op_matrix  # tests/ is not a package; pytest prepends this directory

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get("ULPF_RUNTIME_BIN", ROOT / "runtime" / "bin" / "ulpf-runtime"))
SCHEMA = json.loads((ROOT / "contracts" / "parser-spec.schema.json").read_text(encoding="utf-8"))

# property name -> where its enum lives in the schema (JSON pointer segments)
ENUMS = {
    "schema_version": ["properties", "schema_version", "enum"],
    "class": ["$defs", "token_class", "enum"],
    "coerce.to": ["$defs", "coerce", "properties", "to", "enum"],
    "timestamp.kind": ["$defs", "timestamp_format", "properties", "kind", "enum"],
    "timestamp.timezone": ["$defs", "timestamp_format", "properties", "timezone", "enum"],
    "coerce.on_failure": ["$defs", "coerce", "properties", "on_failure", "enum"],
    "decode.encoding": ["$defs", "decode", "properties", "encoding", "enum"],
    "decode.on_failure": ["$defs", "decode", "properties", "on_failure", "enum"],
    "csv.escape": ["$defs", "op_csv", "properties", "escape", "enum"],
    "csv.extra_fields": ["$defs", "op_csv", "properties", "extra_fields", "enum"],
    "csv.missing_fields": ["$defs", "op_csv", "properties", "missing_fields", "enum"],
    "kv.escape": ["$defs", "op_kv", "properties", "escape", "enum"],
    "kv.unknown_keys": ["$defs", "op_kv", "properties", "unknown_keys", "enum"],
    "kv.order": ["$defs", "op_kv", "properties", "order", "enum"],
    "positional.leading_delimiter": ["$defs", "op_positional", "properties", "leading_delimiter", "enum"],
    "positional.trailing_delimiter": ["$defs", "op_positional", "properties", "trailing_delimiter", "enum"],
    "quoted.escape": ["$defs", "op_quoted", "properties", "escape", "enum"],
    "kind": ["$defs", "kind", "enum"],
}
OPS = [d[3:] for d in SCHEMA["$defs"] if d.startswith("op_")] + ["coerce", "decode"]


def _get(ptr):
    node = SCHEMA
    for p in ptr:
        node = node[p]
    return node


def _observe(node, ctx, seen):
    """Collect (enum-key, value) pairs actually used by a spec."""
    if isinstance(node, dict):
        op = node.get("op")
        if op:
            seen.setdefault("op", set()).add(op)
        for k, v in node.items():
            key = None
            if k == "schema_version":
                key = "schema_version"
            elif k == "class" and isinstance(v, str):
                key = "class"
            elif k == "kind" and isinstance(v, str) and ctx == "cell":
                key = "kind"
            elif k == "kind" and isinstance(v, str) and ctx == "ts":
                key = "timestamp.kind"
            elif k == "timezone":
                key = "timestamp.timezone"
            elif k == "to":
                key = "coerce.to"
            elif k == "on_failure":
                key = "coerce.on_failure" if op == "coerce" else "decode.on_failure"
            elif k == "encoding":
                key = "decode.encoding"
            elif k in ("escape", "extra_fields", "missing_fields", "unknown_keys", "order", "leading_delimiter", "trailing_delimiter") and op:
                key = f"{op}.{k}"
            if key and isinstance(v, str):
                seen.setdefault(key, set()).add(v)
            if k in ("format",) or (k == "formats"):
                _observe(v, "ts", seen)
            elif k in ("captures", "keys"):
                for c in v.values():
                    _observe(c, "cell", seen)
            elif k in ("fields", "slots"):
                for c in v:
                    _observe(c, "cell", seen)
            elif k in ("content", "tail") and isinstance(v, dict):
                _observe(v, "cell", seen)
            else:
                _observe(v, "cell" if k in ("token", "parse") else ctx, seen)
    elif isinstance(node, list):
        for v in node:
            _observe(v, ctx, seen)


def test_every_vector_is_a_valid_spec():
    for v in op_matrix.V:
        errs = validate_document("parser-spec", v["spec"])
        assert errs == [], (v["name"], errs)
    assert len({v["name"] for v in op_matrix.V}) == len(op_matrix.V)


def test_every_contract_enum_value_has_a_vector():
    seen: dict[str, set] = {}
    for v in op_matrix.V:
        _observe(v["spec"], "spec", seen)
    missing = {}
    for key, ptr in ENUMS.items():
        want = set(_get(ptr))
        got = seen.get(key, set())
        if want - got:
            missing[key] = sorted(want - got)
    if set(OPS) - seen.get("op", set()):
        missing["op"] = sorted(set(OPS) - seen.get("op", set()))
    assert missing == {}, f"contract enum values with no micro-vector: {missing}"


def test_every_vector_parses_as_expected_in_the_reference_executor():
    for v in op_matrix.V:
        prog = dslexec.compile_spec(json.dumps(v["spec"]).encode())
        for raw, ok in zip(v["inputs"], v["expect_ok"]):
            m = prog.parse(raw)
            assert (m["status"] == "ok") == ok, (v["name"], raw, m.get("failure"))


@pytest.mark.skipif(not RUNTIME.exists(), reason="runtime binary not built; the differential needs it")
def test_reference_executor_and_engine_agree_on_every_vector(tmp_path):
    env = dict(os.environ, ULPF_ROOT=str(ROOT))
    diffs = []
    for v in op_matrix.V:
        spec_path = tmp_path / f"{v['name']}.json"
        spec_bytes = json.dumps(v["spec"], indent=1).encode()
        spec_path.write_bytes(spec_bytes)
        inp = tmp_path / f"{v['name']}.log"
        inp.write_bytes(b"\n".join(v["inputs"]) + b"\n")
        prog = dslexec.compile_spec(spec_bytes)
        go = subprocess.run([str(RUNTIME), "parse", "--spec", str(spec_path), "--input", str(inp)], capture_output=True, text=True, env=env)
        if go.returncode != 0:
            diffs.append((v["name"], "engine error", go.stderr[:500]))
            continue
        go_maps = [json.loads(l) for l in go.stdout.splitlines() if l.strip()]
        assert len(go_maps) == len(v["inputs"]), v["name"]
        for raw, gm in zip(v["inputs"], go_maps):
            pm = prog.parse(raw)
            if _comparable(pm) != _comparable(gm):
                diffs.append((v["name"], raw, json.dumps({"python": pm, "go": gm}, indent=1)[:1800]))
    assert diffs == [], "\n\n".join(f"{n}: {r}\n{d}" for n, r, d in diffs)


def _comparable(m: dict) -> dict:
    """Everything in the span map is contract except the failure's free-text `reason`: offset and step
    must agree, the wording need not (Python quotes 'B', Go quotes \"B\")."""
    m = json.loads(json.dumps(m))
    if m.get("failure"):
        m["failure"].pop("reason", None)
    return m
