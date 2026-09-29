"""The learning plane sees the payload routing sees (2026-09-30). A real FortiGate showed the gap: its JSON arrives as
`<189>{…}` and its CEF as `<189>Sep 29 … fgt CEF:0|…|extension`; the drafter unwrapped LEEF only, so it drafted the
JSON as CSV (it counted commas) and the CEF as positional text. `envelope.chain` is the twin of frame.UnwrapChain, held
to the same vectors file as the Go test (runtime/internal/frame/chain_vectors_test.go), and the drafter uses it.

The fixtures are this lab's own FortiGate 7.4.12 (demo/devices/fortigate), captured over syslog/TCP."""
import json
from pathlib import Path

import pytest

from ulpf_learn import envelope
from ulpf_learn.draft import draft

HERE = Path(__file__).parent
FG = HERE / "fixtures" / "fortigate"


def lines(name):
    return [l for l in (FG / name).read_bytes().split(b"\n") if l.strip()]


def test_the_chain_twin_agrees_with_the_runtime_on_every_shared_vector():
    vs = json.loads((HERE / "envelope_vectors.json").read_text(encoding="utf-8"))
    assert len(vs) >= 16
    for v in vs:
        c = envelope.chain(v["raw"].encode("utf-8"))
        assert (c["kinds"], c["payload_offset"], c["payload_length"]) == (v["kinds"], v["payload_offset"], v["payload_length"]), v["name"]


def test_fortigate_json_is_drafted_as_json_behind_its_syslog_pri():
    d = draft(lines("json-traffic.log"), "fg-json")
    assert (d.l1, d.l2) == ("rfc3164", "json")   # not csv: the payload after <189> is a JSON object
    assert d.routing["l1_envelope"] == "rfc3164" and d.named
    assert {"srcip", "dstip", "action", "policyname", "eventtime", "tz"} <= set(d.spec["root"]["keys"])


def test_fortigate_cef_is_drafted_from_its_extension_and_refused_honestly_when_values_hold_spaces():
    ls = lines("cef-traffic.log")
    assert any(b"United States" in l for l in ls)   # the DNS denies to 8.8.8.8: dstcountry=United States, unquoted
    with pytest.raises(ValueError, match="CEF extension value runs to the next key="):
        draft(ls, "fg-cef")
    d = draft([l for l in ls if b"United States" not in l], "fg-cef")
    assert (d.l1, d.l2) == ("cef", "kv")   # the extension, after the syslog header AND the CEF header — never positional text
    assert {"src", "dst", "spt", "dpt", "act"} <= set(d.spec["root"]["keys"])


def test_fortigate_system_events_are_key_value_behind_the_pri():
    d = draft(lines("default-event.log"), "fg-event")
    assert (d.l1, d.l2) == ("rfc3164", "kv")
    assert {"logdesc", "user", "ui", "action", "eventtime", "tz"} & set(d.spec["root"]["keys"])


def test_a_mixed_envelope_capture_is_not_drafted():
    with pytest.raises(ValueError, match="do not share one envelope"):
        draft(lines("json-traffic.log")[:3] + [b'{"ts": 1, "src": "10.0.0.1"}'] * 3, "mixed")
