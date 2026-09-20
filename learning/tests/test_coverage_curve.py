"""The arithmetic of the declared replay mix (tools/coverage_curve.py). Needs no corpus: pool sizes are given, not read."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import coverage_curve as coverage  # noqa: E402

CFG = json.loads((Path(__file__).resolve().parents[2] / "metrics/replay-mix.json").read_text(encoding="utf-8"))
COUNTS = {s["id"]: 10 * (i + 1) for i, s in enumerate(CFG["strata"])}
MIX = {m["id"]: m for m in CFG["mixes"]}


def test_every_mix_states_its_assumption_and_names_known_strata():
    ids = {s["id"] for s in CFG["strata"]}
    for m in CFG["mixes"]:
        assert len(m["assumption"]) > 80, m["id"]
        assert set(coverage.stratum_weights(CFG, m, COUNTS)) <= ids


def test_corpus_mixes_never_weight_our_own_samples():
    ours = {s["id"] for s in CFG["strata"] if s.get("ours")}
    for mid in ("corpus-lines", "equal-sources", "connection-heavy"):
        assert not ours & set(coverage.stratum_weights(CFG, MIX[mid], COUNTS))


def test_equal_sources_gives_each_source_a_quarter():
    w = coverage.stratum_weights(CFG, MIX["equal-sources"], COUNTS)
    by_src = {}
    for s in CFG["strata"]:
        by_src[s["source"]] = by_src.get(s["source"], 0) + w.get(s["id"], 0)
    assert all(abs(v - 0.25) < 1e-9 for v in by_src.values()), by_src


def test_connection_heavy_is_80_20_inside_a_firewall_and_whole_for_a_source_with_one_class():
    w = coverage.stratum_weights(CFG, MIX["connection-heavy"], COUNTS)
    asa_conn = sum(w[s["id"]] for s in CFG["strata"] if s["source"] == "cisco-asa" and s["class"] == "connection")
    asa_other = sum(w[s["id"]] for s in CFG["strata"] if s["source"] == "cisco-asa" and s["class"] == "other")
    squid = sum(w[s["id"]] for s in CFG["strata"] if s["source"] == "squid" and not s.get("ours"))
    assert abs(asa_conn - 0.20) < 1e-9 and abs(asa_other - 0.05) < 1e-9 and abs(squid - 0.25) < 1e-9


def test_apportion_is_exact_and_deterministic():
    w = {"a": 1.0, "b": 1.0, "c": 1.0}
    assert coverage.apportion(w, 100) == {"a": 34, "b": 33, "c": 33} == coverage.apportion(dict(reversed(w.items())), 100)
    assert sum(coverage.apportion({"x": 0.3, "y": 0.7, "z": 1e-9}, 2000).values()) == 2000


def test_stream_cycles_the_pool_and_is_reproducible(tmp_path):
    pools = {"a": [b"a1", b"a2"], "b": [b"b1"], "empty": []}
    n1 = coverage.build_stream({"a": 5, "b": 3, "empty": 4}, pools, tmp_path / "s1")
    n2 = coverage.build_stream({"b": 3, "empty": 4, "a": 5}, pools, tmp_path / "s2")
    s1 = (tmp_path / "s1").read_bytes()
    assert n1 == n2 == 8 and s1 == (tmp_path / "s2").read_bytes()      # an empty pool contributes nothing, and says so in the count
    assert s1.count(b"a1") == 3 and s1.count(b"a2") == 2 and s1.count(b"b1") == 3
