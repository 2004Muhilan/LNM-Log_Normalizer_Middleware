"""2026-09-30, after the live Suricata test: (1) an ISO 8601 time with a BASIC offset (+0000, as Suricata's EVE writes
it) is coerced to a timestamp, like RFC 3339 is; (2) the acceptance engine refuses a pack whose mandatory `time` is not
coerced to a real timestamp on every sample — such a pack produced documents the SIEM rejected, and must never go live."""
import json

import pytest

from ulpf_learn import dslexec
from ulpf_learn.discriminators import coercion_for
from ulpf_learn.provider import Proposal, Provider, SlotProposal
from ulpf_learn.session import Session


class ClassOnly(Provider):
    name = "fixture"

    def propose(self, st):
        return Proposal(4001, "network_activity", [SlotProposal(i, []) for i in range(st.arity)], "fixture")


def test_basic_offsets_get_the_pattern_coercion_and_read_the_same_instant_as_the_runtime():
    c = coercion_for(4001, "time", "text", ["2026-09-29T17:01:40.291297+0000", "2026-09-29T22:31:40.291297+0530"])
    assert c["format"] == {"kind": "pattern", "pattern": "%Y-%m-%dT%H:%M:%S.%f%z", "timezone": "in_value"}
    both = coercion_for(4001, "time", "text", ["2026-09-29T17:01:40+0000", "2026-09-29T17:01:40.5+0000"])
    assert [f["pattern"] for f in both["formats"]] == ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"]
    assert coercion_for(4001, "time", "text", ["2026-09-29T17:01:40.291297+00:00"])["format"]["kind"] == "rfc3339"   # unchanged
    assert coercion_for(4001, "time", "text", ["29/Sep/2026:17:01:40 +0000"]) is None                           # still not derivable
    env = dslexec.Env()
    # the same values as runtime/internal/dsl/iso_basic_offset_test.go
    for v in ("2026-09-29T17:01:40.291297+0000", "2026-09-29T22:31:40.291297+0530", "2026-09-29T12:01:40.291297-0500"):
        assert dslexec.parse_timestamp(c["format"], v, env)[0] == 1790701300291


def eve(tmp_path, ts):
    lines = []
    for i in range(6):
        ev = {"timestamp": ts(i), "event_type": "alert", "src_ip": "10.10.1.10", "src_port": 40000 + i, "dest_ip": "172.20.20.10", "dest_port": 23,
              "proto": "TCP", "alert": {"action": "allowed", "signature_id": 9000001, "signature": "ULPF LAB Telnet connection attempt", "severity": 1}}
        lines.append(b"<174>Sep 29 17:05:55 suricata-ids suricata[1]: " + json.dumps(ev).encode())
    p = tmp_path / "eve.log"
    p.write_bytes(b"\n".join(lines) + b"\n")
    s = Session(tmp_path / "s")
    s.onboard(p, "suricata-lab-01", "op-014", ClassOnly(), vendor="OISF", product="Suricata", family_keys=["event_type"])
    for f, a in (("timestamp", "time"), ("src_ip", "src_endpoint.ip"), ("dest_ip", "dst_endpoint.ip")):
        s.respond("operator_assertion", f"op-014 asserts {f} is {a}", field=f, attribute=a)
    s.respond("operator_assertion", "op-014 asserts action is action_id", field="action", attribute="action_id", lookup={"allowed": 1, "blocked": 2})
    return s


def test_suricatas_eve_time_is_coerced_and_the_pack_promotes(tmp_path):
    s = eve(tmp_path, lambda i: f"2026-09-29T17:01:4{i}.29129{i}+0000")
    assert s.state["verdict"]["blockers"] == []
    s.promote(tmp_path / "pack", "suricata-test", withhold_unevidenced=True)


def test_a_pack_whose_mandatory_time_stays_text_is_refused(tmp_path):
    s = eve(tmp_path, lambda i: f"29/Sep/2026:17:01:4{i} +0000")   # a form nothing derives a coercion for
    blockers = s.state["verdict"]["blockers"]
    assert len(blockers) == 1 and "time (timestamp) is not coerced to a timestamp on 6 of 6 samples" in blockers[0]
    with pytest.raises(Exception):
        s.promote(tmp_path / "pack", "suricata-test", withhold_unevidenced=True)
