"""P3 exit tests: the trace scenario end to end, invariants 4 and 5, the cross-stack differential test."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from ulpf_contracts import validate_file
from ulpf_learn import dslexec
from ulpf_learn.predict import predict
from ulpf_learn.session import Session

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "contracts" / "golden" / "squid-native"
RUNTIME = Path(os.environ.get("ULPF_RUNTIME_BIN", ROOT / "runtime" / "bin" / "ulpf-runtime"))
LOGFORMAT = "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt"


@pytest.fixture()
def session(tmp_path):
    s = Session(tmp_path / "session")
    s.onboard(GOLDEN / "samples" / "access.log", "squid-proxy-01", "op-014")
    return s


def certs_by_slot(s):
    return {c["context"]["slot_index"] + 1: c for c in s.state["certificates"].values()}


def test_trace_stage8_certificates_and_stage9_request(session):
    s = session
    assert s.state["structure"]["arity"] == 10
    c = certs_by_slot(s)
    assert c[3]["status"] == "ambiguous" and c[3]["evidence"]["discriminator"]["ambiguity_class"] == "endpoint_orientation"
    assert [r["attribute"] for r in c[3]["ranked_candidates"]] == ["src_endpoint.ip", "dst_endpoint.ip"]
    assert c[5]["status"] == "ambiguous" and c[5]["evidence"]["discriminator"]["ambiguity_class"] == "volume_direction"
    assert [r["attribute"] for r in c[5]["ranked_candidates"]] == ["traffic.bytes_out", "traffic.bytes_in", "traffic.bytes"]
    # both are resolved by ONE evidence item: same sufficiency group, rank-1 discriminator is the logformat
    assert c[3]["request"]["sufficiency_group"] == c[5]["request"]["sufficiency_group"]
    assert c[3]["request"]["selected"]["discriminator_id"] == "device_logformat_configuration"
    assert c[3]["request"]["selected"]["rank"] == 1
    assert "operator_labelled_session" in [a["discriminator_id"] for a in c[3]["request"]["alternatives"]]
    assert s.state["pending_request"]["discriminator_id"] == "device_logformat_configuration"
    # exactly the trace's certificates: two ambiguous (3, 5) and one out-of-library (2); single
    # proposals are unevidenced fields covered by the request, never fabricated ambiguities
    assert sorted(c) == [2, 3, 5]
    assert set(s.state["pending_request"]["resolves"]) == {f"pos_{i}" for i in range(1, 11)}
    assert {u["field"] for u in s.state["unevidenced"]} == {"pos_1", "pos_6", "pos_7", "pos_10"}
    # enumeration is over the pinned table, not over the proposal: survivors exceed the ranked set
    assert len(c[3]["enumeration"]["survivors"]) > 2 and set(r["attribute"] for r in c[3]["ranked_candidates"]) <= set(c[3]["enumeration"]["survivors"])
    for cert in c.values():
        assert validate_file("ambiguity-certificate", _dump(cert)) == []


def test_invariant5_out_of_library_ambiguity_is_unresolved_not_guessed(session):
    c = certs_by_slot(session)
    assert c[2]["status"] == "unresolved"
    assert c[2]["unresolved_reason"] == "no_library_discriminator"
    assert c[2]["evidence"]["discriminator"]["status"] == "none"
    assert "request" not in c[2]
    assert [r["attribute"] for r in c[2]["ranked_candidates"]] == ["duration", "http_response.latency"]


def test_invariant4_fixture_only_mandatory_blocks_promotion(session, tmp_path):
    v = session.state["verdict"]
    assert v["promotable"] is False
    assert any("invariant 4" in b for b in v["blockers"])
    with pytest.raises(RuntimeError):
        session.promote(tmp_path / "pack", "squid-native-emitted")


def test_structural_determination_never_rests_on_the_proposal(session):
    # 6 IP survivors, 15+ integer survivors, 21 url leaves: nothing in this class is structurally determined
    assert session.state["verdict"]["determinations"] == []


def test_trace_stage10_to_13_resolution_promotion_and_differential(session, tmp_path):
    s = session
    v = s.respond("device_logformat_configuration", LOGFORMAT)
    assert v.promotable, v.blockers
    c = certs_by_slot(s)
    assert c[3]["status"] == "resolved" and c[3]["resolution"]["resolved_to"] == "src_endpoint.ip"
    assert c[5]["status"] == "resolved" and c[5]["resolution"]["resolved_to"] == "traffic.bytes_out"
    assert c[2]["status"] == "resolved" and c[2]["resolution"]["resolved_to"] == "duration"  # the same evidence settled it
    assert c[3]["resolution"]["provenance"] == "vendor_schema_or_device_configuration"
    pack_dir = tmp_path / "pack"
    pack_path = s.promote(pack_dir, "squid-native-emitted")
    # contract: Python
    assert validate_file("parser-pack", pack_path) == []
    pack = json.loads(pack_path.read_text())
    fam = pack["families"][0]
    mapped = {f["ocsf_attribute"]: f for f in fam["mapping"]["fields"]}
    for a in ("time", "src_endpoint.ip", "dst_endpoint.ip", "http_request.url.url_string", "http_request.http_method", "activity_id", "action_id"):
        assert mapped[a]["provenance"]["category"] == "vendor_schema_or_device_configuration", a
    assert mapped["severity_id"]["constant"] == 1 and mapped["severity_id"]["provenance"]["category"] == "operator_assertion"
    spec = json.loads((pack_dir / fam["parser"]["spec_ref"]).read_text())
    assert spec["null_values"] == ["-"]
    # effort instrumentation recorded from the first step
    m = s.metrics()
    assert m["evidence_requests"] == 1 and m["operator_responses"] == 1 and m["promoted"] and m["steps"] >= 6
    if not RUNTIME.exists():
        pytest.skip("runtime binary not built; differential test needs it")
    # contract: Go, fail-closed load
    env = dict(os.environ, ULPF_ROOT=str(ROOT))
    out = subprocess.run([str(RUNTIME), "verify-pack", "--pack", str(pack_dir)], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    # differential 1: span maps — Python reference executor vs Go engine on the same lines
    samples = pack_dir / "samples" / "access.log"
    lines = [l for l in samples.read_bytes().split(b"\n") if l.strip()]
    prog = dslexec.compile_spec((pack_dir / fam["parser"]["spec_ref"]).read_bytes())
    go = subprocess.run([str(RUNTIME), "parse", "--spec", str(pack_dir / fam["parser"]["spec_ref"]), "--input", str(samples)], capture_output=True, text=True, check=True, env=env).stdout
    go_maps = [json.loads(l) for l in go.splitlines() if l.strip()]
    assert len(go_maps) == len(lines)
    for line, gm in zip(lines, go_maps):
        pm = prog.parse(line)
        assert pm == gm, json.dumps({"python": pm, "go": gm}, indent=1)[:4000]
    # differential 2: normalized output — Python prediction vs Go pipeline (OCSF part, unmapped, absence)
    ev_dir = tmp_path / "ev"
    run = subprocess.run([str(RUNTIME), "run", "--pack", str(pack_dir), "--input", str(samples), "--evidence", str(ev_dir), "--out", "-"], capture_output=True, text=True, check=True, env=env)
    go_events = [json.loads(l) for l in run.stdout.splitlines() if l.strip()]
    assert len(go_events) == len(lines)
    for line, ge in zip(lines, go_events):
        lin = ge.pop("_lineage")
        pe = predict(prog.parse(line), pack, fam)
        absent = pe.pop("_absent")
        assert pe == ge, json.dumps({"python": pe, "go": ge}, indent=1)[:4000]
        assert lin.get("absent", []) == absent
    # differential 3 (corpus, optional): the real Beats Squid native lines
    corpus = ROOT / "corpus" / "cache" / "beats-squid-log" / "access1.log"
    if corpus.exists():
        go = subprocess.run([str(RUNTIME), "parse", "--spec", str(pack_dir / fam["parser"]["spec_ref"]), "--input", str(corpus)], capture_output=True, text=True, check=True, env=env).stdout
        clines = [l.rstrip(b"\r") for l in corpus.read_bytes().split(b"\n") if l.strip()]
        for line, gl in zip(clines, go.splitlines()):
            assert prog.parse(line) == json.loads(gl)


def test_cooperative_operator_absent_labelled_session_resolves_only_pos3(session):
    s = session
    line = "1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://example.com/index.html - HIER_DIRECT/93.184.216.34 text/html"
    v = s.respond("operator_labelled_session", "", sample_line=line, initiator_ip="10.20.14.62", field="pos_3")
    c = certs_by_slot(s)
    assert c[3]["status"] == "resolved" and c[3]["resolution"]["provenance"] == "validated_discriminator"
    assert c[5]["status"] == "ambiguous"  # bytes direction still unknown: the certificate is retained
    assert not v.promotable


def _dump(doc) -> Path:
    p = Path(tempfile.mkdtemp()) / "doc.json"
    p.write_text(json.dumps(doc))
    return p
