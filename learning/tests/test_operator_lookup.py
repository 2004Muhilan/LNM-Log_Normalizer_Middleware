"""An operator's assertion may carry the value map onto an enum attribute (2026-09-30): FortiGate system events say
status="success"/"failed", OCSF Authentication needs status_id — a mandatory attribute no plain field mapping can meet.
The map is the operator's statement (provenance operator_assertion, the map in the evidence reference) and becomes the
pack mapping's lookup transform, the form the vendor tables already use (parser-pack 1.3.0)."""
from ulpf_learn.discriminators import apply_operator_assertion
from ulpf_learn.plan import Part, Plan, Slot


def plan():
    part = Part("status", "word", "semantic", None, [], [], "status", ["status_id"], "model")
    return Plan("fortigate-lab-01", 3002, "authentication", [Slot(0, "word", [part], None, ["success", "failed"])])


def test_a_value_map_becomes_a_lookup_transform_and_is_recorded_in_the_evidence():
    p = apply_operator_assertion(plan(), "status", "status_id", "op-014", "FortiOS login status", {"status_id"}, lookup={"success": 1, "failed": 2})
    m = p.slots[0].parts[0].mappings[0]
    assert m.attribute == "status_id" and m.mandatory
    assert m.transform == {"kind": "lookup", "lookup": {"success": 1, "failed": 2}, "default": 99}
    assert m.provenance["category"] == "operator_assertion" and "success=1, failed=2" in m.provenance["evidence_ref"]
    assert p.slots[0].parts[0].coerce is None   # the looked-up value stays text; the lookup makes the enum


def test_without_a_map_the_assertion_is_what_it_was():
    p = apply_operator_assertion(plan(), "status", "status_detail", "op-014", "the status word", set())
    m = p.slots[0].parts[0].mappings[0]
    assert m.transform is None and m.attribute == "status_detail" and not m.mandatory
