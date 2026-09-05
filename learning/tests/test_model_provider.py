"""P4 unit tests with a fake llama-server: the builder/verifier loop, the emission schemas, the
projection report, and the fixture path running unchanged beside the model path."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from ulpf_learn import dslexec
from ulpf_learn.induce import induce
from ulpf_learn.model import emission, prompt
from ulpf_learn.model.client import Completion
from ulpf_learn.model.provider import ModelProvider
from ulpf_learn.model.structure_from_spec import structure_from_spec
from ulpf_learn.session import Session

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "contracts" / "golden" / "squid-native"
LOGFORMAT = "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt"


class FakeClient:
    """Answers from a script keyed by the schema's shape; records what it was asked."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.asked = []

    def props(self):
        return {"build_info": "fake", "model_path": "/fake.gguf", "n_ctx": 8192}

    def chat(self, system, user, schema, max_tokens=2048, enable_thinking=False):
        self.asked.append((system, user, schema))
        text = self.answers.pop(0)
        return Completion(text if isinstance(text, str) else json.dumps(text), 100, 20, 1.0)


def _labels(pairs):
    return {"slots": [{"slot": i, **({"label": lab} if isinstance(lab, str) else {"label": lab[0], "alternatives": lab[1:]})} for i, lab in pairs]}


TRUTH = [(1, "time"), (2, "duration"), (3, ["src_endpoint.ip", "dst_endpoint.ip"]), (4, "compound"), (5, "traffic.bytes_out"),
         (6, "http_request.http_method"), (7, "http_request.url.url_string"), (8, "unmapped"), (9, "compound"), (10, "http_response.content_type")]


def test_emission_schemas_are_grammar_subset():
    for s in (emission.class_schema(), emission.proposal_schema(4002, 10), emission.slot_schema(["time", "start_time"])):
        _, dropped = emission.project_for_grammar(s)
        assert dropped == {}, dropped
        jsonschema.Draft202012Validator.check_schema(s)
    attrs = emission.class_attributes(4002)
    assert "src_endpoint.ip" in attrs and "http_request.url.url_string" in attrs and len(attrs) < 1500
    assert not any(a.count(".") > 2 for a in attrs)


def test_projection_reports_what_the_contract_loses():
    schema = json.loads((ROOT / "contracts" / "parser-spec.schema.json").read_text())
    projected, dropped = emission.project_for_grammar(schema)
    assert {"if", "then", "not", "propertyNames", "uniqueItems"} <= set(dropped)  # `not` lives inside the conditionals
    assert "$ref" in json.dumps(projected)  # structure kept
    jsonschema.Draft202012Validator.check_schema(projected)


def test_whole_mode_refutes_type_incompatible_labels_then_abandons(tmp_path):
    # iteration 1: slot 2 labelled with an IP attribute (integer token) -> refuted; slot 5 with a timestamp -> refuted
    bad = _labels([(1, "time"), (2, "src_endpoint.ip"), (3, "src_endpoint.ip"), (4, "compound"), (5, "time"),
                   (6, "http_request.http_method"), (7, "http_request.url.url_string"), (8, "unmapped"), (9, "compound"), (10, "http_response.content_type")])
    # iteration 2: slot 2 fixed, slot 5 still wrong; iteration 3: still wrong -> abandoned
    fix2 = _labels([(1, "time"), (2, "duration"), (3, "src_endpoint.ip"), (4, "compound"), (5, "time"), (6, "http_request.http_method"),
                    (7, "http_request.url.url_string"), (8, "unmapped"), (9, "compound"), (10, "http_response.content_type")])
    fc = FakeClient([{"event_class": "http_activity"}, bad, fix2, fix2])
    prov = ModelProvider(fc, "fake", "sha256:" + "0" * 64, mode="whole", max_iterations=3, backend="test")
    lines = [l for l in (GOLDEN / "samples" / "access.log").read_bytes().split(b"\n") if l.strip()]
    prov.set_samples(lines)
    prop = prov.propose(induce(lines))
    tr = prov.last_trace
    assert tr.iterations == 3 and tr.refuted_by_iteration == [[1, 4], [4], [4]] and tr.abandoned == [4]
    by = {s.slot_index: s for s in prop.slots}
    assert by[1].candidates == ["duration"] and by[4].candidates == []  # abandoned to review, never guessed
    assert by[7].unmapped_name == "slot_8" and by[3].sub_split == "/" and by[8].sub_split == "/"
    assert prop.proposed_by == "model" and prop.model_hash.startswith("sha256:")
    assert "rejected by the validator" in fc.asked[2][1] and "slot 2" in fc.asked[2][1]
    prov_rec = prop.notes["provenance"]
    assert prov_rec["decoding"]["temperature"] == 0.0 and prov_rec["decoding"]["top_k"] == 1 and prov_rec["prompt_template_hash"].startswith("sha256:")
    assert set(prov_rec["grammar_hashes"]) == {"class", "labels"}


def test_model_proposal_yields_the_same_certificates_as_the_fixture(tmp_path):
    fc = FakeClient([{"event_class": "http_activity"}, _labels(TRUTH)])
    prov = ModelProvider(fc, "fake", "sha256:" + "1" * 64, mode="whole")
    s = Session(tmp_path / "s")
    s.onboard(GOLDEN / "samples" / "access.log", "squid-proxy-01", "op-014", provider=prov)
    c = {c["context"]["slot_index"] + 1: c for c in s.state["certificates"].values()}
    assert sorted(c) == [1, 3, 5]
    assert c[3]["evidence"]["discriminator"]["ambiguity_class"] == "endpoint_orientation"
    assert [r["proposed_by"] for r in c[3]["ranked_candidates"]] == ["model", "model"]  # the model ranked both
    assert c[5]["evidence"]["discriminator"]["ambiguity_class"] == "volume_direction"
    assert s.state["proposal_provenance"]["model_hash"] == "sha256:" + "1" * 64
    assert s.state["verdict"]["promotable"] is False  # invariant 4: model alone never promotes
    v = s.respond("device_logformat_configuration", LOGFORMAT)
    assert v.promotable
    pack = s.promote(tmp_path / "pack", "squid-model-emitted")
    assert json.loads(pack.read_text())["provenance"]["model_hash"] == "sha256:" + "1" * 64


def test_per_slot_mode_is_type_compatible_by_construction(tmp_path):
    lines = [l for l in (GOLDEN / "samples" / "access.log").read_bytes().split(b"\n") if l.strip()]
    st = induce(lines)
    answers = [{"event_class": "http_activity"}] + [{"label": "unmapped"}] * 10
    fc = FakeClient(answers)
    prov = ModelProvider(fc, "fake", "sha256:" + "2" * 64, mode="per-slot")
    prov.set_samples(lines)
    prop = prov.propose(st)
    assert len(fc.asked) == 11
    for (_, _, schema) in fc.asked[1:]:
        assert schema["properties"]["label"]["enum"][-1] == "unmapped"
    ipv4_schema = fc.asked[3][2]
    assert set(ipv4_schema["properties"]["label"]["enum"]) - {"unmapped"} <= set(emission.class_attributes(4002))
    assert all(sp.candidates == [] and sp.unmapped_name for sp in prop.slots)


def test_request_without_certificate_when_nothing_is_ambiguous(tmp_path):
    """P3 boundary item decided in P4: a session whose mandatory fields rest on the provider alone, with
    no library class naming a rival, still gets a request (free-tier configuration evidence) — it must
    not sit blocked with nothing to ask. No certificate is fabricated for it."""
    # a provider that labels the IP as device.ip (no class), the timestamp unmapped, everything else unevidenced
    lab = _labels([(1, "unmapped"), (2, "duration"), (3, "device.ip"), (4, "compound"), (5, "unmapped"), (6, "http_request.http_method"),
                   (7, "http_request.url.url_string"), (8, "unmapped"), (9, "compound"), (10, "http_response.content_type")])
    fc = FakeClient([{"event_class": "http_activity"}, lab])
    s = Session(tmp_path / "s")
    s.onboard(GOLDEN / "samples" / "access.log", "squid-proxy-01", "op-014", provider=ModelProvider(fc, "fake", "sha256:" + "3" * 64))
    assert s.state["certificates"] == {}
    req = s.state["pending_request"]
    assert req and req["kind"] == "unevidenced_mandatory" and req["certificates"] == [] and req["discriminator_id"] == "device_logformat_configuration"
    assert s.state["state"] == "awaiting_evidence" and s.state["verdict"]["promotable"] is False
    v = s.respond("device_logformat_configuration", LOGFORMAT)   # the same evidence resolves it
    assert v.promotable


def test_fixture_path_runs_unchanged(tmp_path):
    s = Session(tmp_path / "s")
    s.onboard(GOLDEN / "samples" / "access.log", "squid-proxy-01", "op-014")   # no provider argument: the P3 default
    assert s.state["proposal"]["provider"] == "fixture" and s.state["proposal_provenance"] is None
    assert sorted(c["context"]["slot_index"] + 1 for c in s.state["certificates"].values()) == [1, 2, 3, 5]


def test_structure_from_spec_names_slots(tmp_path):
    spec = (ROOT / "drafts" / "sufficiency" / "asa-302013.json").read_bytes()
    line = b"%ASA-6-302013: Built outbound TCP connection 11757 for outside:100.66.205.104/80 (100.66.205.104/80) to inside:172.31.98.44/1772 (172.31.98.44/1772)"
    st, kept = structure_from_spec(spec, [line])
    names = [s.name for s in st.slots]
    assert "src_host" in names and "dst_port" in names and kept == [line]
    assert st.slots[names.index("dst_port")].token_class == "integer"
    assert "name=src_host" in prompt.describe_structure(st, kept)
