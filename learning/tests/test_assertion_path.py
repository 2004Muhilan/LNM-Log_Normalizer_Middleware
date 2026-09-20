"""The operator-assertion path for a source WITHOUT a vendor table (live demo, second pass): the request is answerable
and counted once, an assertion derives its value coercion from the pinned OCSF type, a pack never claims to be Squid,
nothing resting on a proposal alone is mapped when it is withheld — and automatic healing refuses traffic that is not
bound to the onboarded source. Vendor-table sessions (Squid) must not move at all."""
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "learning" / "tools"))
from ulpf_learn.discriminators import coercion_for  # noqa: E402
from ulpf_learn.provider import FixtureProvider  # noqa: E402
from ulpf_learn.session import Session  # noqa: E402

RUNTIME = Path(os.environ.get("ULPF_RUNTIME_BIN", ROOT / "runtime" / "bin" / "ulpf-runtime"))
FIXTURE = ROOT / "demo" / "live" / "flowtap-proposals.json"
spec = importlib.util.spec_from_file_location("flowgen", ROOT / "demo" / "live" / "flowgen.py")
flowgen = importlib.util.module_from_spec(spec); spec.loader.exec_module(flowgen)


def samples(tmp_path, fmt=1, n=24):
    g = flowgen.Flowtap(7)
    p = tmp_path / f"v{fmt}.log"
    p.write_text("".join(g.line(fmt, 1758350000 + i * 0.37) + "\n" for i in range(n)), encoding="utf-8", newline="\n")
    return p


def test_coercion_comes_from_the_pinned_type_and_the_token_class_never_from_a_proposal():
    assert coercion_for(4001, "time", "float", ["1758350000.324"])["format"]["kind"] == "epoch_s_frac"
    assert coercion_for(4001, "time", "integer", ["1758350000"])["format"]["kind"] == "epoch_auto"
    assert coercion_for(4001, "time", "word", ["2026-09-20T06:33:20.042Z"])["format"]["kind"] == "rfc3339"
    assert coercion_for(4001, "time", "text", ["Sep 20 06:33:20"]) is None            # not derivable: stays a string, as before
    assert coercion_for(4001, "dst_endpoint.port", "integer", ["443"])["to"] == "int"
    assert coercion_for(4001, "action_id", "integer", ["1", "2"])["to"] == "int"
    assert coercion_for(4001, "src_endpoint.ip", "ipv4", ["10.4.2.17"])["to"] == "ip"
    assert coercion_for(4001, "connection_info.protocol_name", "word", ["tcp"]) is None
    assert coercion_for(4001, "no.such.attribute", "integer", ["1"]) is None


def test_a_source_without_a_vendor_table_gets_one_answerable_request_counted_once(tmp_path):
    s = Session(tmp_path / "s"); s.onboard(samples(tmp_path), "flowtap-01", "op-014", FixtureProvider(FIXTURE), vendor="flowtap", product="flowtap sensor")
    req = s.state["pending_request"]
    assert req["discriminator_id"] == "operator_assertion" and "No vendor documentation" in req["text"] and len(s.state["verdict"]["blockers"]) == 4
    cert = s.state["certificates"]["cert_flowtap-01_pos4"]
    assert cert["request"]["selected"]["discriminator_id"] == "operator_assertion"
    assert "operator_labelled_session" in [a["discriminator_id"] for a in cert["request"]["alternatives"]]      # the library's own discriminators stay listed
    assert not {"device_logformat_configuration", "vendor_schema_field_order"} & {a["discriminator_id"] for a in cert["request"]["alternatives"]}
    for f, a in (("pos_4", "src_endpoint.ip"), ("pos_6", "dst_endpoint.ip"), ("pos_1", "time"), ("pos_2", "action_id")):
        s.respond("operator_assertion", f"op-014 asserts {f} is {a}", field=f, attribute=a)
    m = s.metrics()
    assert m["evidence_requests"] == 1 and m["operator_responses"] == 4 and not s.state["verdict"]["blockers"]   # a shrinking request is the same request
    parts = {p.field: p for _, p in s.plan.parts()}
    assert parts["pos_1"].coerce["to"] == "timestamp" and parts["pos_2"].coerce["to"] == "int" and parts["pos_2"].unmapped_name is None


def test_a_squid_session_is_asked_what_it_was_always_asked():
    s = Session(Path(os.environ.get("TMPDIR", "/tmp")) / f"ulpf-squid-{os.getpid()}")
    s.onboard(ROOT / "contracts/golden/squid-native/samples/access.log", "squid-proxy-01", "op-014")
    assert s.state["pending_request"]["discriminator_id"] == "device_logformat_configuration"


def test_withheld_promotion_maps_only_what_has_evidence_and_the_pack_does_not_say_squid(tmp_path):
    if not RUNTIME.exists():
        pytest.skip("runtime binary not built; promotion needs parser_hash")
    s = Session(tmp_path / "s"); s.onboard(samples(tmp_path), "flowtap-01", "op-014", FixtureProvider(FIXTURE), vendor="flowtap", product="flowtap sensor", transport_hint="syslog-tcp")
    for f, a in (("pos_4", "src_endpoint.ip"), ("pos_6", "dst_endpoint.ip"), ("pos_1", "time"), ("pos_2", "action_id")):
        s.respond("operator_assertion", f"op-014 asserts {f} is {a}", field=f, attribute=a)
    pack = json.loads(s.promote(tmp_path / "pack", "flowtap-01", withhold_unevidenced=True).read_text(encoding="utf-8"))
    assert pack["source"]["vendor"] == "flowtap" and pack["source"]["product"] == "flowtap sensor" and "Squid" not in json.dumps(pack["source"])
    fam = pack["families"][0]
    assert "operator_assertion" in fam["description"] and "device configuration" not in fam["description"]
    assert {f["provenance"]["category"] for f in fam["mapping"]["fields"]} == {"operator_assertion"}       # five proposals were NOT mapped
    assert sorted(w["field"] for w in s.state["withheld"]) == ["pos_3", "pos_5", "pos_7", "pos_8", "pos_9"]
    assert {u["path"] for u in fam["mapping"]["unmapped"]} >= {"pos_5", "pos_8"}                           # carried, not lost


def test_autoheal_refuses_traffic_that_is_not_bound_to_the_onboarded_source(tmp_path):
    import autoheal
    ev, run = tmp_path / "ev", tmp_path / "run-1"; ev.mkdir(); run.mkdir()
    idx = [{"event_id": "ev_1", "ingest_channel": "tcp:127.0.0.1:6515", "peer": "10.0.0.5:40000"}, {"event_id": "ev_2", "ingest_channel": "tcp:127.0.0.1:6515", "peer": "10.0.0.5:40001"},
           {"event_id": "ev_3", "ingest_channel": "tcp:127.0.0.1:6515", "peer": "192.0.2.66:5555"}]
    (ev / "seg_00000.idx.jsonl").write_text("".join(json.dumps(r) + "\n" for r in idx))
    (run / "out.jsonl").write_text(json.dumps({"_lineage": {"event_id": "ev_1", "parser_id": "flowtap-01"}}) + "\n")
    assert autoheal.source_binding([run], ev, "flowtap-01", ["ev_2"])["bound"]            # same channel, same host, another connection
    b = autoheal.source_binding([run], ev, "flowtap-01", ["ev_2", "ev_3"])
    assert not b["bound"] and ["tcp:127.0.0.1:6515", "192.0.2.66"] in b["drifted_from"]   # one stranger among the samples: refused
    assert not autoheal.source_binding([run], ev, "some-other-source", ["ev_2"])["bound"]  # a source that never emitted anything has no binding
