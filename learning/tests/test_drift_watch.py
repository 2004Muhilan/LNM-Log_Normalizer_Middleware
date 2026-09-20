"""The live half of the drift monitor (tools/drift.py --watch, --extract-signature) and the generator's format
(demo/live/flowgen.py): the properties the live demo sequence stands on, without a runtime."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "learning" / "tools"))
import drift  # noqa: E402

spec = importlib.util.spec_from_file_location("flowgen", ROOT / "demo" / "live" / "flowgen.py")
flowgen = importlib.util.module_from_spec(spec); spec.loader.exec_module(flowgen)

SIG9, SIG10 = "raw|tokens||9|a", "raw|tokens||10|b"


def ev(i): return {"_lineage": {"event_id": f"ev_{i:06d}", "family_id": "positional-9"}}
def qr(i, sig, stage="routing", reason="unknown signature: no onboarded family matches (quarantined, not guessed)"):
    return {"event_id": f"ev_{i:06d}", "stage": stage, "reason": reason, "routing_signature": sig}


def write_run(d: Path, out, q):
    d.mkdir(parents=True)
    (d / "out.jsonl").write_text("".join(json.dumps(x) + "\n" for x in out))
    (d / "q.jsonl").write_text("".join(json.dumps(x) + "\n" for x in q) + '{"event_id": "ev_9')   # a half-written last line is skipped


def test_watch_is_quiet_on_a_healthy_stream_and_fires_when_the_format_changes(tmp_path):
    write_run(tmp_path / "run-1", [ev(i) for i in range(100)], [])
    w = drift.watch_once([tmp_path / "run-1"], 40, 0.8, 20)
    assert not w["fired"] and w["parse_success"] == 1.0 and w["frames_total"] == 100
    # the same source changes format: a second run directory (a restarted runtime) over the same evidence log
    write_run(tmp_path / "run-2", [ev(i) for i in range(100, 110)], [qr(i, SIG10) for i in range(110, 140)])
    w = drift.watch_once([tmp_path / "run-1", tmp_path / "run-2"], 40, 0.8, 20)
    assert w["fired"] and w["parse_success"] == 0.25 and w["dominant_signal"] == "unknown_signatures"
    assert w["signals"]["unknown_signatures"][0]["key"] == SIG10 and w["signals"]["unknown_signatures"][0]["events"] == 30


def test_watch_names_routed_then_refused_as_parse_success_drop_and_does_not_fire_before_min_frames(tmp_path):
    write_run(tmp_path / "run-1", [], [qr(i, SIG9, stage="parse", reason="at 3: no match") for i in range(10)])
    assert not drift.watch_once([tmp_path / "run-1"], 40, 0.8, 20)["fired"]          # 10 frames: still warming up
    write_run(tmp_path / "run-2", [], [qr(i, SIG9, stage="parse", reason="at 3: no match") for i in range(10, 40)])
    w = drift.watch_once([tmp_path / "run-1", tmp_path / "run-2"], 40, 0.8, 20)
    assert w["fired"] and w["dominant_signal"] == "parse_success_drop"


def test_extract_signature_returns_the_evidence_bytes_and_refuses_bytes_that_do_not_hash(tmp_path):
    lines = [b"2026-09-20T06:33:20.042Z 1 udp 203.0.113.167 36567 10.4.5.137 8443 8578504 75239571 mgmt", b"another line of another signature"]
    raw = b"\n".join(lines) + b"\n"
    (tmp_path / "seg_00000.raw").write_bytes(raw)
    q = [{"event_id": "ev_1", "stage": "routing", "reason": "unknown signature: …", "routing_signature": SIG10, "segment_id": "seg_00000", "offset": 0, "length": len(lines[0]),
          "raw_hash": "sha256:" + hashlib.sha256(lines[0]).hexdigest()},
         {"event_id": "ev_2", "stage": "routing", "reason": "unknown signature: …", "routing_signature": SIG9, "segment_id": "seg_00000", "offset": len(lines[0]) + 1, "length": len(lines[1]),
          "raw_hash": "sha256:" + hashlib.sha256(lines[1]).hexdigest()}]
    assert drift.extract_signature(q, SIG10, tmp_path, 0) == [lines[0]]
    q[0]["raw_hash"] = "sha256:" + "00" * 32
    with pytest.raises(SystemExit):
        drift.extract_signature(q, SIG10, tmp_path, 0)


def test_the_generated_format_says_nothing_about_which_address_is_the_initiator():
    g = flowgen.Flowtap(26156)
    v1 = [g.line(1, 1758350000 + i).split() for i in range(60)]
    assert {len(r) for r in v1} == {9}
    private_first = sum(r[3].startswith("10.") for r in v1)
    assert 0 < private_first < 60                       # both directions: neither address column is "the private one"
    assert all(not any(ch.isalpha() for ch in r[0]) and r[1] in ("1", "2") for r in v1)   # bare epoch, bare verdict code: no label anywhere
    v2 = [g.line(2, 1758350000 + i).split() for i in range(20)]
    assert {len(r) for r in v2} == {10} and all(r[2] in ("6", "17") and r[9] in flowgen.ZONES for r in v2)
    assert all(a == b for x, y in zip(v1[:1], v2[:1]) for a, b in [(len(x[0]), len(y[0]))])   # the timestamp column did not change: what is mandatory still propagates
