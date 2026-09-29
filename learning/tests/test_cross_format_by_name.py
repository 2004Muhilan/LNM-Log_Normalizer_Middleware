"""The user's decision after the real FortiGate (laptop branch, 2026-09-30): on a SELF-DESCRIBING format (JSON,
key=value) an answer carries across formats by NAME — same source, same family, same field name, same value class —
because the name is the evidence. Structure-based formats keep the structure-based §4.4 key. Tested on the captured
FortiGate lines: the vendor pack's documented answers for its traffic family, seeded for the lab source, carry to the
same device's JSON format; not to another source, not to another family, not into another OCSF class, and not to CSV."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ulpf_learn.propagation import Store
from ulpf_learn.provider import Proposal, Provider, SlotProposal
from ulpf_learn.session import Session, family_values

ROOT = Path(__file__).resolve().parents[2]
FGT = Path(__file__).parent / "fixtures" / "fortigate"
SRC = "fortigate-lab-01"
REC = ROOT / "spike" / "results" / "desktop-5060ti" / "granite-4.1-8b-q4_k_m__gpu__fortigate-traffic__whole.json"


@pytest.fixture(scope="module")
def pack(tmp_path_factory):
    """The FortiGate vendor pack exactly as scripts/p6-build-packs.sh builds it (recorded proposals, the vendor's field
    documentation resolves, merged into a source pack) — built here, so the test depends on no demo state."""
    w = tmp_path_factory.mktemp("fgt")
    learn = lambda *a: subprocess.run([sys.executable, "-m", "ulpf_learn", *map(str, a)], cwd=ROOT / "learning", capture_output=True, text=True, check=True)
    learn("onboard-spec", "--samples", ROOT / "corpus" / "cache" / "beats-fortinet-firewall" / "traffic.log", "--spec", ROOT / "drafts" / "sufficiency" / "fortigate-traffic.json",
          "--source-id", "fortigate-fw-01", "--operator", "op-014", "--session", w / "s", "--vendor", "fortinet-fortigate", "--family-id", "fortigate-traffic",
          "--unwrap-envelope", "--provider", "recorded", "--recording", REC)
    learn("respond", "--session", w / "s", "--discriminator", "vendor_schema_field_order", "--input", "FortiOS 6.2 Log Reference: traffic/forward log fields")
    learn("promote", "--session", w / "s", "--out", w / "packs" / "fortigate-traffic", "--pack-id", "fortigate-traffic")
    learn("merge", w / "packs" / "fortigate-traffic", "--out", w / "fortigate", "--pack-id", "fortigate-fw-01", "--vendor", "fortinet-fortigate")
    return w / "fortigate"


class ClassOnly(Provider):
    """Stands where the model stands: proposes a class and nothing else (every field would be asked)."""
    name = "fixture"

    def __init__(self, uid, name):
        self.uid, self.cname = uid, name

    def propose(self, structure):
        return Proposal(self.uid, self.cname, [SlotProposal(i, []) for i in range(structure.arity)], "fixture")


def lines(name):
    return [l for l in (FGT / name).read_bytes().split(b"\n") if l.strip()]


def seeded(tmp_path, pack, source=SRC):
    store = tmp_path / "prop.json"
    st = Store(store)
    n = st.seed_from_pack(pack, source, lines("default-traffic.log"))
    st.save()
    return store, n


def onboard(tmp_path, name, store, fixture, uid=4001, cname="network_activity", source=SRC, keys=("type",), extra=b""):
    p = tmp_path / f"{name}.log"
    p.write_bytes(b"".join(l + b"\n" for l in lines(fixture)) + extra)
    s = Session(tmp_path / name)
    s.onboard(p, source, "op-014", ClassOnly(uid, cname), vendor="Fortinet", product="FortiGate", propagation_store=store, family_keys=list(keys))
    return s


def test_family_values_read_json_and_kv():
    assert family_values(b'{"type":"traffic","subtype":"forward"}', ["type"]) == "type=traffic"
    assert family_values(b'date=2026-09-29 type="event" subtype="system"', ["type"]) == "type=event"
    assert family_values(b'{"alert":{"x":1},"event_type":"alert"}', ["event_type"]) == "event_type=alert"
    assert family_values(b'a=1 b=2', ["type"]) == ""


def test_the_json_format_heals_by_name_from_the_vendor_packs_answers(tmp_path, pack):
    store, n = seeded(tmp_path, pack)
    assert n > 30
    s = onboard(tmp_path, "json", store, "json-traffic.log")
    hits = s.state["propagated"]
    assert len(hits) == s.state["structure"]["arity"] == 44 and all(h["by"] == "name" for h in hits)
    assert not s.state["verdict"]["blockers"]
    got = {h["fields"][0]: h["attributes"] for h in hits}
    assert got["srcip"] == ["src_endpoint.ip"] and got["action"] == ["action", "action_id"] and got["eventtime"] == ["time"]
    unresolved = [p.field for _, p in s.plan.parts() if p.mappings and p.mappings[0].provenance["category"] in ("model_proposal", "fixture_proposal")]
    assert unresolved == []


def test_nothing_carries_to_another_source_family_or_a_structure_based_format(tmp_path, pack):
    store, _ = seeded(tmp_path, pack)
    assert not onboard(tmp_path, "other-source", store, "json-traffic.log", source="fortigate-lab-02").state.get("propagated")
    wrong = onboard(tmp_path, "model-said-3002", store, "json-traffic.log", uid=3002, cname="authentication")   # a proposal; the family's class is evidence
    assert wrong.plan.event_class_uid == 4001 and len(wrong.state["propagated"]) == 44
    assert [e for e in wrong.state["timeline"] if e["step"] == "class_from_earlier_answers"][0]["proposed"] == 3002
    ev = onboard(tmp_path, "events", store, "json-event.log", uid=4001)
    assert ev.state["family"] == "type=event" and not ev.state.get("propagated")        # traffic's `action` is not an event's `action`
    csv = onboard(tmp_path, "csv", store, "csv-traffic.log")
    assert csv.state["drafted"]["l2"] == "csv" and not csv.state.get("propagated")         # csv: positions, the structure key


def test_one_onboarding_learns_one_family(tmp_path, pack):
    store, _ = seeded(tmp_path, pack)
    extra = b"".join(l + b"\n" for l in lines("json-event.log")[:3])
    s = onboard(tmp_path, "mixed", store, "json-traffic.log", extra=extra)
    split = [e for e in s.state["timeline"] if e["step"] == "family_split"]
    assert s.state["family"] == "type=traffic" and split and split[0]["left"] == {"type=event": 3}
    assert s.state["sample_count"] == 12 and len(s.state["propagated"]) == 44


def test_the_seeded_json_family_promotes_and_loads_in_the_go_engine(tmp_path, pack):
    store, _ = seeded(tmp_path, pack)
    s = onboard(tmp_path, "json", store, "json-traffic.log")
    s.promote(tmp_path / "pack", f"{SRC}-json", withhold_unevidenced=True)
    rt = Path(os.environ.get("ULPF_RUNTIME_BIN", ROOT / "runtime" / "bin" / "ulpf-runtime"))
    if rt.exists():
        r = subprocess.run([str(rt), "verify-pack", "--pack", str(tmp_path / "pack")], capture_output=True, text=True, cwd=ROOT)
        assert r.returncode == 0, r.stdout + r.stderr
