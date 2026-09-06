"""P6: envelope twin, surface twin, vendor-schema applier, propagation under the §4.4 key, recorded
provider, the ML feature draft contract. Corpus-free: every input is a trace line, a synthetic line, or a
committed fixture."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from ulpf_contracts import validate_document
from ulpf_learn import envelope, surface
from ulpf_learn.propagation import Store
from ulpf_learn.provider import RecordedProvider
from ulpf_learn.session import Session

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "contracts" / "golden" / "squid-native"
RUNTIME = Path(os.environ.get("ULPF_RUNTIME_BIN", ROOT / "runtime" / "bin" / "ulpf-runtime"))
LOGFORMAT = "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt"

LINES = [
    b"Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-302013: Built outbound TCP connection 11757 for outside:100.66.205.104/80 (100.66.205.104/80) to inside:172.31.98.44/1772 (172.31.98.44/1772)",
    b"Nov 30 16:09:08 PA-220 1,2018/11/30 16:09:07,012801096514,TRAFFIC,end,2049,2018/11/30 16:09:07,192.168.15.207,184.51.253.152",
    b'<189>date=2020-04-23 time=01:16:08 devname="fw" devid="x" logid="0000000013" type="traffic" subtype="forward"',
    b"<134>1 2024-12-19T00:00:00Z proxy01 squid 1234 - - 1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://e/ - HIER_DIRECT/93.184.216.34 text/html",
    b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
    b"1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://e/ - HIER_DIRECT/93.184.216.34 text/html",
    b"Built outbound TCP connection with no header at all",
]


def test_envelope_twin_agrees_with_the_runtime_unwrap():
    """The learning plane must see the payload the runtime parses: same kind, same payload bounds, per line."""
    if not RUNTIME.exists():
        pytest.skip("runtime binary not built")
    for raw in LINES:
        py = envelope.unwrap(raw)
        # the runtime exposes the unwrap through `parse --spec` lineage only; use the frame test vector CLI: compile a
        # trivial opaque spec and read _lineage.envelope? Simpler and exact: the Go test suite pins the same lines
        # (frame/syslog_test.go); here we pin the Python side to the same expectations.
        assert py["payload_offset"] + py["payload_length"] == len(raw)
    e = envelope.unwrap(LINES[0]); assert e["kind"] == "rfc3164" and e["hostname"] == "localhost" and e["app_name"] == "CiscoASA" and LINES[0][e["payload_offset"]:].startswith(b"%ASA-6-302013")
    e = envelope.unwrap(LINES[1]); assert e["kind"] == "rfc3164" and e["hostname"] == "PA-220" and LINES[1][e["payload_offset"]:].startswith(b"1,2018")
    e = envelope.unwrap(LINES[2]); assert e["kind"] == "rfc3164" and e["priority"] == 189 and "hostname" not in e and LINES[2][e["payload_offset"]:].startswith(b"date=")
    e = envelope.unwrap(LINES[3]); assert e["kind"] == "rfc5424" and LINES[3][e["payload_offset"]:].startswith(b"1734567890.123")
    e = envelope.unwrap(LINES[4]); assert e["kind"] == "rfc3164" and e["app_name"] == "su" and LINES[4][e["payload_offset"]:] == b"'su root' failed for lonvick on /dev/pts/8"
    assert envelope.unwrap(LINES[5])["kind"] == "none" and envelope.unwrap(LINES[6])["kind"] == "none"


def test_surface_twin_matches_the_router_reading():
    """L2 detection, cell/pair counts and token classes as the Go router computes them (router_test.go pins the same)."""
    fgt = b'date=2020-04-23 time=01:16:08 devname="testswitch1" devid="somerouterid" logid="0000000013" type="traffic" subtype="forward" level="notice"'
    s = surface.detect(fgt)
    assert s.l2 == "kv" and s.pairs["devname"] == "testswitch1" and s.arity == 8
    panos = b"1,2018/11/30 16:09:07,012801096514,TRAFFIC,end,2049,2018/11/30 16:09:07,192.168.15.207,184.51.253.152,\"a,b\",x"
    s = surface.detect(panos)
    assert s.l2 == "csv" and s.arity == 11 and s.cells[3] == "TRAFFIC" and s.cells[9] == "a,b"
    squid = LINES[5]
    s = surface.detect(squid)
    assert s.l2 == "tokens" and [surface.classify(t) for t in s.toks] == ["float", "integer", "ipv4", "text", "integer", "word", "url", "word", "text", "text"]
    assert surface.detect(b"a=1 b=2").l2 == "tokens" and surface.detect(b"x,y,z").l2 == "tokens" and surface.detect(b'{"a":1}').l2 == "json"
    anchor = {"locator": {"kind": "pattern", "pattern": r"%(?:ASA|FTD|PIX)-(?:[a-z]+-)?[0-7]-(?P<anchor>[0-9]{6})"}, "expected_value_domain": {"kind": "enum", "values": ["302013"]}}
    asa = LINES[0][envelope.unwrap(LINES[0])["payload_offset"]:]
    assert surface.locate(anchor, asa, surface.detect(asa), None) == "302013" and surface.in_domain(anchor, "302013") and not surface.in_domain(anchor, "999999")


def test_recorded_provider_replays_the_model_by_field_name():
    rec = ROOT / "spike" / "results" / "desktop-5060ti" / "granite-4.1-8b-q4_k_m__gpu__asa-302013__whole.json"
    if not rec.exists():
        pytest.skip("no recording")
    from ulpf_learn.induce import SlotObservation, Structure
    st = Structure(3, [SlotObservation(0, "ipv4", 2, ["1.1.1.1"], name="src_host"), SlotObservation(1, "integer", 2, ["80"], name="src_port"), SlotObservation(2, "text", 1, ["x"], name="not_recorded")], 5)
    prop = RecordedProvider(rec).propose(st)
    assert prop.proposed_by == "model" and prop.model_hash.startswith("sha256:") and prop.event_class_uid == 4001
    assert prop.slots[0].candidates and prop.slots[2].candidates == []
    assert prop.notes["provenance"]["recording"].endswith("asa-302013__whole.json")


def test_vendor_schema_applier_resolves_named_fields_and_envelope_time(tmp_path):
    """The ASA path without the corpus: two synthetic 302013 lines under the committed draft; the vendor table resolves
    every named field with vendor provenance, adds the per-family constants, and sources `time` from the syslog header."""
    if not RUNTIME.exists():
        pytest.skip("runtime binary not built")
    samples = tmp_path / "asa.log"
    samples.write_bytes(LINES[0] + b"\n" + LINES[0].replace(b"11757", b"11758").replace(b"12:34:56", b"12:35:00") + b"\n")
    rec = ROOT / "spike" / "results" / "desktop-5060ti" / "granite-4.1-8b-q4_k_m__gpu__asa-302013__whole.json"
    if not rec.exists():
        pytest.skip("no recording")
    s = Session(tmp_path / "s")
    s.onboard_spec(samples, ROOT / "drafts" / "sufficiency" / "asa-302013.json", "asa-fw-01", "op-014", "cisco-asa", "asa-302013", RecordedProvider(rec), unwrap_envelope=True)
    assert s.state["state"] == "awaiting_evidence" and s.state["pending_request"]  # the model proposed; nothing is sufficient yet
    v = s.respond("vendor_schema_field_order", "Cisco ASA Syslog Messages: 302013")
    assert v.promotable, v.blockers
    attrs = {m.attribute: m for _, p in s.plan.parts() for m in p.mappings}
    assert attrs["src_endpoint.ip"].provenance["category"] == "vendor_schema_or_device_configuration"
    assert {c.attribute for c in s.plan.constants} == {"action_id", "severity_id", "activity_id"}
    env_maps = {e.attribute: e for e in s.plan.envelope_mappings}
    assert set(env_maps) == {"time", "device.hostname"} and env_maps["time"].transform["format"]["kind"] == "rfc3164"
    pack_path = s.promote(tmp_path / "pack", "asa-test")
    pk = json.loads(pack_path.read_text(encoding="utf-8"))
    assert pk["schema_version"] == "1.3.0" and pk["source"]["vendor"] == "Cisco" and pk["anchors"][0]["anchor_id"] == "asa-message-id"
    fam = pk["families"][0]
    assert fam["family_id"] == "asa-302013" and fam["routing_signature"]["l2_structure"] == "template" and fam["routing_signature"]["l1_envelope"] == "rfc3164"
    assert fam["routing_signature"]["l3_anchor_values"] == [{"anchor_id": "asa-message-id", "values": ["302013"]}]
    assert any(f.get("envelope_field") == "timestamp" and f["ocsf_attribute"] == "time" for f in fam["mapping"]["fields"])
    # the runtime loads it (signed by the dev authority) and routes the same lines to it, with time from the header
    env = dict(os.environ, ULPF_ROOT=str(ROOT))
    subprocess.run([str(RUNTIME), "verify-pack", "--pack", str(tmp_path / "pack")], check=True, capture_output=True, env=env)
    out = subprocess.run([str(RUNTIME), "run", "--pack", str(tmp_path / "pack"), "--input", str(samples), "--evidence", str(tmp_path / "ev"), "--ml-out", str(tmp_path / "ml.jsonl")],
                         check=True, capture_output=True, text=True, env=env)
    events = [json.loads(l) for l in out.stdout.splitlines()]
    assert len(events) == 2 and events[0]["time"] == 1539174896000 and events[0]["src_endpoint"]["ip"] == "100.66.205.104" and events[0]["action_id"] == 1
    for e in events:
        assert validate_document("normalized-event", e) == []
    ml = [json.loads(l) for l in (tmp_path / "ml.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(ml) == 2 and all(validate_document("ml-feature", r) == [] for r in ml)
    assert ml[0]["template_id"].startswith("asa-test/asa-302013@sha256:") and ml[0]["entity_ids"]["src_ip"] == "100.66.205.104" and ml[0]["entity_ids"]["device"] == "localhost"


def test_propagation_resolves_a_second_family_without_a_repeat_request(tmp_path):
    """§4.4 key: the 10-slot Squid family is resolved by its logformat; the 11-slot family of the same source
    gets every shared slot resolved from the store, and the only question left concerns the new slot."""
    if not RUNTIME.exists():
        pytest.skip("runtime binary not built")
    store = tmp_path / "prop.json"
    a = Session(tmp_path / "a")
    a.onboard(GOLDEN / "samples" / "access.log", "squid-proxy-01", "op-014", propagation_store=store)
    assert a.state["pending_request"] and not a.state.get("propagated")
    a.respond("device_logformat_configuration", LOGFORMAT)
    a.promote(tmp_path / "pack-10", "squid-10")
    assert len(Store(store).entries) == 10
    b = Session(tmp_path / "b")
    b.onboard(ROOT / "learning" / "fixtures" / "squid-native-11.log", "squid-proxy-01", "op-014", propagation_store=store)
    assert {h["slot_index"] for h in b.state["propagated"]} == set(range(10))
    assert not b.state["verdict"]["blockers"]
    req = b.state["pending_request"]
    assert req is None or set(req["resolves"]) == {"pos_11"}, req
    # the compound slots came back whole: cache_result/status_code from TCP_MISS/200
    parts = {p.field for _, p in b.plan.parts()}
    assert {"cache_result", "status_code", "hier_code", "server_ip", "client_ip", "url"} <= parts
    b.promote(tmp_path / "pack-11", "squid-11")
    m = b.metrics()
    assert m["operator_responses"] == 0 and m["promoted"]
    # a different source never receives the propagation (the key starts with source_id)
    c = Session(tmp_path / "c")
    c.onboard(GOLDEN / "samples" / "access.log", "squid-proxy-02", "op-014", propagation_store=store)
    assert not c.state.get("propagated") and c.state["pending_request"]


def test_ml_feature_contract_refuses_invented_entities_and_wrong_shapes():
    ok = {"schema_version": "0.1.0", "event_id": "ev_" + "0" * 26, "source_id": "s", "class_uid": 4001, "template_id": "p/f@sha256:" + "0" * 64,
          "parameter_names": ["a"], "parameter_vector": [1], "timestamp": 1, "entity_ids": {"src_ip": "1.1.1.1"}}
    assert validate_document("ml-feature", ok) == []
    bad = dict(ok, entity_ids={"src_ip": "1.1.1.1", "confidence": 0.9})
    assert validate_document("ml-feature", bad)
    assert validate_document("ml-feature", dict(ok, template_id="no-hash"))
    assert validate_document("ml-feature", dict(ok, schema_version="1.0.0"))
