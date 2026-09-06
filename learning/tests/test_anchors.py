"""Anchor admission (P6 exit criterion): cardinality alone never admits; declared domains and measured
partitions do; a declaration contradicted by observation is a drift signal, not an admission."""
from ulpf_learn.anchors import Candidate, admit


def test_low_cardinality_without_domain_is_refused():
    # a constant hostname in a 12-line sample: the implementer's first instinct, and wrong
    c = Candidate({"kind": "slot", "slot_index": 3}, ["PA-220"], {"panos-traffic": {"PA-220"}})
    d = admit("device-name", c)
    assert not d.admitted and d.basis is None and "cardinality alone" in d.reason
    # two values, still one family, still no domain
    c = Candidate({"kind": "key", "key": "vd"}, ["root", "OPERATIONAL"], {"fortigate-traffic": {"root", "OPERATIONAL"}})
    assert not admit("vd", c).admitted


def test_declared_domain_admits_and_records_the_domain():
    c = Candidate({"kind": "pattern", "pattern": "%ASA-[0-7]-(?P<anchor>[0-9]{6})"}, ["302013", "106023"],
                  {"asa-302013": {"302013"}, "asa-106023": {"106023"}},
                  declared_domain={"kind": "enum", "values": ["302013", "302014", "106023"]})
    d = admit("asa-message-id", c)
    assert d.admitted and d.basis == "declared_domain" and d.anchor["admission_basis"] == "declared_domain" and d.anchor["observed_cardinality"] == 2


def test_declared_domain_contradicted_by_observation_is_a_drift_signal_not_an_admission():
    c = Candidate({"kind": "slot", "slot_index": 3}, ["TRAFFIC", "WEIRD"], {"panos-traffic": {"TRAFFIC", "WEIRD"}},
                  declared_domain={"kind": "enum", "values": ["TRAFFIC", "THREAT"]})
    d = admit("panos-log-type", c)
    assert not d.admitted and "drift signal" in d.reason


def test_measured_utility_needs_a_perfect_partition_over_two_families():
    ok = Candidate({"kind": "key", "key": "type"}, ["traffic", "utm"], {"fgt-traffic": {"traffic"}, "fgt-utm": {"utm"}})
    d = admit("fortigate-type", ok)
    assert d.admitted and d.basis == "measured_utility" and d.anchor["anchor_status"] == "probation"
    shared = Candidate({"kind": "key", "key": "level"}, ["notice"], {"fgt-traffic": {"notice"}, "fgt-utm": {"notice"}})
    assert not admit("level", shared).admitted
