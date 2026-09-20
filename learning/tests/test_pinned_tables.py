"""The subset guard's other half (audit §3.2). Both loaders compare a pack's `table_hash` with `ocsf/pinned/index.json`
and neither recomputes it, so a pinned table with leaf paths deleted passed every suite. Here the hash IS recomputed
from each table file, with the definition the generator uses (canonical JSON of the table without `table_hash`).
Python side only: the Go loader still compares two strings — reproducing Python's canonical JSON in Go is the
canonical-JSON machinery plan §1 rules out, and redefining the hash over file bytes changes every pack hash."""
import hashlib
import json
from pathlib import Path

PINNED = Path(__file__).resolve().parents[2] / "ocsf" / "pinned"


def table_hash(table: dict) -> str:
    body = {k: v for k, v in table.items() if k != "table_hash"}
    return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def test_every_pinned_table_hashes_to_what_it_and_the_index_claim():
    index = json.loads((PINNED / "index.json").read_text(encoding="utf-8"))
    assert len(index["classes"]) == 4
    for c in index["classes"]:
        table = json.loads((PINNED / f"{c['name']}.json").read_text(encoding="utf-8"))
        assert table_hash(table) == table["table_hash"] == c["table_hash"], c["name"]
        assert len(table["leaf_paths"]) == c["leaf_path_count"] and table["top_level_attribute_count"] == len(table["attributes"]) == c["top_level_attribute_count"]


def test_a_table_with_a_leaf_path_removed_no_longer_matches():
    c = json.loads((PINNED / "index.json").read_text(encoding="utf-8"))["classes"][0]
    table = json.loads((PINNED / f"{c['name']}.json").read_text(encoding="utf-8"))
    table["leaf_paths"] = table["leaf_paths"][:-1]
    assert table_hash(table) != c["table_hash"]
