"""Spec drafting for self-describing formats (laptop branch): the structure is read off the samples with no model, the
draft is a valid parser spec that parses every sample, a drafted pack loads and runs in the Go engine, and an operator's
answers propagate to a drifted format BY NAME — never by position — for formats that name their fields."""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

from ulpf_contracts import validate_document
from ulpf_learn import dslexec
from ulpf_learn.draft import draft, leef_split, surface
from ulpf_learn.provider import FixtureProvider
from ulpf_learn.session import Session

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get("ULPF_RUNTIME_BIN", ROOT / "runtime" / "bin" / "ulpf-runtime"))
FIXTURE = ROOT / "demo" / "live" / "flowtap-proposals.json"
_spec = importlib.util.spec_from_file_location("flowgen", ROOT / "demo" / "live" / "flowgen.py")
flowgen = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(flowgen)
SHEET = ["time", "action_id", "connection_info.protocol_name", "src_endpoint.ip", "src_endpoint.port", "dst_endpoint.ip", "dst_endpoint.port", "traffic.bytes_out", "traffic.bytes_in"]


def lines(shape, fmt=1, n=20, seed=7):
    g = flowgen.Flowtap(seed)
    return [g.line(fmt, 1758350000 + i * 0.37, shape).encode() for i in range(n)]


def test_surface_is_the_routers_detection_and_tokens_are_left_to_induction():
    assert [surface(lines(s)[0]) for s in ("positional", "csv", "kv", "json", "xml")] == ["tokens", "csv", "kv", "json", "xml"]
    assert surface(b"a,b,c") == "tokens"                       # the router sees CSV from nine cells on; fewer is a token line
    assert draft(lines("positional"), "t") is None
    with pytest.raises(ValueError):
        draft(lines("json", n=3) + lines("kv", n=3), "t")      # a mixed capture is not one format


def test_leef_header_twin():
    raw = lines("leef")[0]
    off, delim = leef_split(raw)
    assert raw[:off].count(b"|") == 5 and raw[off:].startswith(b"devTime=") and delim == ""
    assert leef_split(b"LEEF:2.0|V|P|1|id|^|a=1^b=2") == (20, "^") and leef_split(b"LEEF:2.0|V|P|1|id|x09|a=1") == (22, "x09")
    assert leef_split(b"LEEF:1.0|V|P|1|id|") is None and leef_split(b"CEF:0|a|b") is None


@pytest.mark.parametrize("shape,l1,l2,named", [("csv", "raw", "csv", False), ("kv", "raw", "kv", True), ("json", "raw", "json", True), ("xml", "raw", "xml", True), ("leef", "leef", "kv", True)])
def test_a_draft_is_a_valid_spec_that_parses_every_sample_and_rejects_what_it_has_not_seen(shape, l1, l2, named):
    d = draft(lines(shape), f"t-{shape}")
    assert (d.l1, d.l2, d.named) == (l1, l2, named) and d.structure.arity == 9
    assert validate_document("parser-spec", d.spec) == []
    assert [s.token_class for s in d.structure.slots] == ["float", "integer", "word", "ipv4", "integer", "ipv4", "integer", "integer", "integer"]
    prog = dslexec.compile_spec(json.dumps(d.spec).encode())
    strip = (lambda l: l[leef_split(l)[0]:]) if l1 == "leef" else (lambda l: l)
    assert all(prog.parse(strip(l))["status"] == "ok" for l in lines(shape, seed=99))
    assert all(prog.parse(strip(l))["status"] == "failed" for l in lines(shape, fmt=2))     # firmware 2.0 adds a field: never carried silently
    if l2 in ("kv", "csv"):
        assert d.routing["l4_sketch"]["arity_bucket"] == "9"


def onboard(tmp_path, shape, fmt, store, name):
    p = tmp_path / f"{name}.log"; p.write_bytes(b"".join(l + b"\n" for l in lines(shape, fmt)))
    s = Session(tmp_path / name)
    s.onboard(p, "flowtap-01", "op-014", FixtureProvider(FIXTURE), vendor="flowtap", product="flowtap sensor", propagation_store=store)
    return s


@pytest.mark.parametrize("shape", ["json", "xml", "kv", "leef", "csv"])
def test_a_drafted_family_promotes_loads_in_the_go_engine_and_its_answers_propagate_to_the_drifted_format(tmp_path, shape):
    store = tmp_path / "prop.json"
    s = onboard(tmp_path, shape, 1, store, "v1")
    fields = [p.field for _, p in s.plan.parts()]
    assert len(s.state["verdict"]["blockers"]) == 4                              # a name in a line is a hint, never evidence
    for f, a in zip(fields, SHEET):
        s.respond("operator_assertion", f"op-014 asserts {f} is {a}", field=f, attribute=a)
    s.promote(tmp_path / "pack-v1", f"flowtap-01-{shape}", withhold_unevidenced=True)
    spec = json.loads(next((tmp_path / "pack-v1" / "specs").iterdir()).read_text())
    cells = spec["root"].get("keys") or spec["root"].get("paths") or {c["field"]: c for c in spec["root"]["fields"]}
    assert [c for c in cells.values() if c.get("coerce", {}).get("to") == "timestamp"], "the asserted time field carries its coercion in the rebuilt spec"
    if RUNTIME.exists():
        r = subprocess.run([str(RUNTIME), "verify-pack", "--pack", str(tmp_path / "pack-v1")], capture_output=True, text=True, cwd=ROOT)
        assert r.returncode == 0, r.stdout + r.stderr
    s2 = onboard(tmp_path, shape, 2, store, "v2")
    carried = {h["fields"][0] for h in s2.state["propagated"]}
    assert carried == set(fields) - {fields[2]} and not s2.state["verdict"]["blockers"]           # the protocol changed class, the zone is new: neither inherits anything
    unresolved = [p.field for _, p in s2.plan.parts() if not p.mappings or p.mappings[0].provenance["category"] in ("model_proposal", "fixture_proposal")]
    assert len(unresolved) == 2


def test_named_fields_propagate_by_name_not_by_position(tmp_path):
    """A key inserted BEFORE the known ones shifts every position; nothing may inherit its neighbour's answer."""
    store = tmp_path / "prop.json"
    s = onboard(tmp_path, "kv", 1, store, "v1")
    for f, a in zip([p.field for _, p in s.plan.parts()], SHEET):
        s.respond("operator_assertion", f"op-014 asserts {f} is {a}", field=f, attribute=a)
    s.promote(tmp_path / "pack-v1", "flowtap-01-kv", withhold_unevidenced=True)
    shifted = tmp_path / "shifted.log"
    shifted.write_bytes(b"".join(b"site=7 " + l + b"\n" for l in lines("kv")))
    s2 = Session(tmp_path / "shifted"); s2.onboard(shifted, "flowtap-01", "op-014", FixtureProvider(FIXTURE), vendor="flowtap", product="x", propagation_store=store)
    got = {h["fields"][0]: h["attributes"][0] for h in s2.state["propagated"]}
    assert got["src"] == "src_endpoint.ip" and got["dst"] == "dst_endpoint.ip" and got["ts"] == "time" and "site" not in got and len(got) == 9
