"""parser-spec 1.2.0 / normalized-event 1.4.0 on the learning-plane side: the reference executor's json and xml ops
(their agreement with the engine, span for span, is the op matrix's job), and the syslog twin not mistaking an
application header for a tag."""
import json

from ulpf_contracts import validate_document
from ulpf_learn import dslexec
from ulpf_learn.envelope import unwrap

BOUNDS = {"max_event_bytes": 8192, "max_fields": 64, "max_nesting": 4, "max_repeat": 16}


def prog(root):
    spec = {"schema_version": "1.2.0", "spec_id": "t-fmt", "description": "t", "regex_dialect": "re2", "bounds": BOUNDS, "root": root}
    assert validate_document("parser-spec", spec) == []
    return dslexec.compile_spec(json.dumps(spec).encode())


def values(m, raw):
    assert m["status"] == "ok", m.get("failure")
    at = 0
    for s in m["spans"]:                       # the tiling rule: every byte, exactly once, in order
        assert s["start"] == at and s["end"] > s["start"]
        at = s["end"]
    assert at == len(raw)
    return {s["path"]: s.get("value") for s in m["spans"] if s["kind"] == "semantic"}


def test_json_op_values_and_tiling():
    p = prog({"op": "json", "unknown_keys": "opaque", "keys": {"src.ip": {"field": "src", "kind": "semantic", "class": "ipv4"}, "msg": {"field": "msg", "kind": "semantic"}}})
    raw = b'{"src": {"ip": "10.4.2.17", "port": 1}, "msg": "tab\\there \\u00e9", "n": [1, 2]}'
    assert values(p.parse(raw), raw) == {"src": "10.4.2.17", "msg": "tab\there é"}
    assert p.parse(b'{"src": {"ip": "x"}}')["status"] == "failed"


def test_xml_op_values_and_tiling():
    p = prog({"op": "xml", "unknown": "opaque", "paths": {"e/id": {"field": "id", "kind": "semantic", "class": "integer"}, "e@t": {"field": "t", "kind": "semantic"}}})
    raw = b"<e t='2026-09-20T06:33:20Z'><id> 4625 </id><other>x</other></e>"
    assert values(p.parse(raw), raw) == {"id": "4625", "t": "2026-09-20T06:33:20Z"}
    assert p.parse(b"<e><id>1</id>")["status"] == "failed"


def test_a_spec_below_1_2_0_cannot_use_the_new_ops_silently():
    spec = {"schema_version": "1.2.0", "spec_id": "t", "description": "t", "regex_dialect": "re2", "bounds": BOUNDS, "root": {"op": "json", "keys": {}, "unknown_keys": "opaque"}}
    assert validate_document("parser-spec", spec) != []      # keys must declare at least one path


def test_syslog_twin_does_not_take_an_application_header_for_a_tag():
    e = unwrap(b"<134>Dec 19 00:00:00 gw01 LEEF:1.0|Acme|Gate|4.2|login_fail|src=10.0.0.5\tdst=10.0.0.6")
    assert e["kind"] == "rfc3164" and not e.get("app_name")
    raw = b"<134>Dec 19 00:00:00 gw01 LEEF:1.0|Acme|Gate|4.2|login_fail|src=10.0.0.5"
    assert raw[e["payload_offset"]:e["payload_offset"] + 5] == b"LEEF:"
    assert unwrap(b"<134>Dec 19 00:00:00 proxy01 squid[1234]: x")["app_name"] == "squid"
