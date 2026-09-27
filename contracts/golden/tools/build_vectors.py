#!/usr/bin/env python3
"""Golden-vector authoring tool. Idempotent.

1. Fills the content hashes in squid-native/pack.json from the actual files (dsl_hash, mapping_hash,
   corpus_hash, pack-level hashes). parser_hash is set equal to dsl_hash until P2 defines the compiled
   representation (recorded in contracts/README.md as a P2 obligation).
2. Produces the resolved certificates in squid-native/certificates/ from the ambiguous snapshots.
3. Generates the negative vectors under negative/ by mutating the golden documents, so they cannot
   drift from the positives.
4. Writes index.json, which both validation suites iterate.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GOLDEN = Path(__file__).resolve().parents[1]
ROOT = GOLDEN.parents[1]
# parser_hash is defined by the runtime (sha256 of the compiled representation); the Go binary is
# the only thing that can compute it. Build it with scripts/p2-check.sh or set ULPF_RUNTIME_BIN.
RUNTIME_BIN = os.environ.get("ULPF_RUNTIME_BIN", str(ROOT / "runtime" / "bin" / "ulpf-runtime"))
SQ = GOLDEN / "squid-native"
NEG = GOLDEN / "negative"
LOGFORMAT = "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt"


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def canonical(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def dump(p: Path, o):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(o, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def rehash_pack():
    pack = load(SQ / "pack.json")
    # subset guard: the pack pins classes; their table_hash comes from the generated pinned index
    pinned = {c["uid"]: c["table_hash"] for c in load(ROOT / "ocsf" / "pinned" / "index.json")["classes"]}
    for c in pack["ocsf"]["pinned_classes"]:
        c["table_hash"] = pinned[c["uid"]]
    corpus_hash = sha((SQ / "samples" / "access.log").read_bytes())
    dsl, mapping, parser = [], [], []
    for fam in pack["families"]:
        spec_path = SQ / fam["parser"]["spec_ref"]
        spec_bytes = spec_path.read_bytes()
        fam["parser"]["dsl_hash"] = sha(spec_bytes)
        fam["parser"]["parser_hash"] = runtime_parser_hash(spec_path)
        fam["mapping"]["mapping_hash"] = sha(canonical(fam["mapping"]["fields"]))
        fam["sample_provenance"]["corpus_hash"] = corpus_hash
        dsl.append(fam["parser"]["dsl_hash"]); mapping.append(fam["mapping"]["mapping_hash"]); parser.append(fam["parser"]["parser_hash"])
    pack["hashes"] = {
        "parser_hash": sha("".join(parser).encode()),
        "dsl_hash": sha("".join(dsl).encode()),
        "mapping_hash": sha("".join(mapping).encode()),
        "corpus_hash": corpus_hash,
    }
    dump(SQ / "pack.json", pack)
    return pack


def runtime_parser_hash(spec_path: Path) -> str:
    if not Path(RUNTIME_BIN).exists():
        sys.exit(f"runtime binary not found at {RUNTIME_BIN}; build it first (scripts/p2-check.sh) — parser_hash is runtime-defined")
    out = subprocess.run([RUNTIME_BIN, "compile", "--spec", str(spec_path)], check=True, capture_output=True, text=True).stdout
    info = json.loads(out)
    if info["dsl_hash"] != sha(spec_path.read_bytes()):
        sys.exit("runtime dsl_hash disagrees with the file hash")
    return info["parser_hash"]


def normalized_golden():
    """Run the golden pack over its samples with a fixed clock and sequential ids; keep line 1 as
    the normalized-event golden vector (contracts/normalized-event.schema.json)."""
    tmp = Path(tempfile.mkdtemp(prefix="ulpf-golden-"))
    try:
        env = dict(os.environ, ULPF_ROOT=str(ROOT))
        subprocess.run([RUNTIME_BIN, "run", "--dev-no-evidence-archive", "--pack", str(SQ), "--input", str(SQ / "samples" / "access.log"),
                        "--evidence", str(tmp / "evidence"), "--out", str(tmp / "out.jsonl"),
                        "--collector", "col-01", "--channel", "file:/var/log/squid/access.log",
                        "--fixed-clock-ms", "1734567890481", "--deterministic-ids"], check=True, env=env, capture_output=True)
        first = (tmp / "out.jsonl").read_text(encoding="utf-8").splitlines()[0]
        dump(SQ / "normalized" / "line1.json", json.loads(first))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def resolve_certificates():
    resolved_to = {"cert_squid_pos3": "src_endpoint.ip", "cert_squid_pos5": "traffic.bytes_out"}
    for snap in sorted((SQ / "certificate-snapshots").glob("*_ambiguous.json")):
        cert = load(snap)
        cert["status"] = "resolved"
        cert["resolution"] = {
            "discriminator_id": "device_logformat_configuration",
            "provenance": "vendor_schema_or_device_configuration",
            "resolved_to": resolved_to[cert["certificate_id"]],
            "evidence_ref": {"kind": "operator_input", "summary": LOGFORMAT, "hash": sha(LOGFORMAT.encode())},
            "operator_id": "op-014",
            "resolved_at": "2026-09-05T10:04:00Z",
            "propagation_scope": {"source_id": cert["source_id"], **cert["context"]},
        }
        dump(SQ / "certificates" / f"{cert['certificate_id']}.json", cert)


def negatives(pack):
    spec = load(SQ / "specs" / "squid-native-positional-10.json")
    smap = load(SQ / "span-maps" / "line1-promoted.json")
    cert = load(SQ / "certificate-snapshots" / "cert_squid_pos3_ambiguous.json")
    out = []

    s = copy.deepcopy(spec)
    s["root"]["slots"][3] = {"token": {"parse": {"op": "regex", "pattern": "(?P<a>[A-Z_]+)/(?P<b>[0-9]+)\\1",
                                                 "captures": {"a": {"field": "cache_result", "kind": "semantic"}, "b": {"field": "status_code", "kind": "semantic"}}}}}
    dump(NEG / "spec-non-re2-backreference.json", s)
    out.append({"kind": "parser-spec", "path": "negative/spec-non-re2-backreference.json", "expect": "invalid",
                "reason_match": ["RE2", "regex"], "note": "backreference \\1 is not RE2; both stacks must refuse it"})

    s = copy.deepcopy(spec)
    s["root"] = {"op": "exec", "command": "/bin/sh"}
    dump(NEG / "spec-unknown-op.json", s)
    out.append({"kind": "parser-spec", "path": "negative/spec-unknown-op.json", "expect": "invalid",
                "reason_match": ["schema", "oneOf", "root"], "note": "the op set is closed; invariant 1"})

    m = copy.deepcopy(smap)
    m["spans"] = [x for x in m["spans"] if not (x["start"] == 86 and x["end"] == 87)]
    dump(NEG / "span-map-gap.json", m)
    out.append({"kind": "span-map", "path": "negative/span-map-gap.json", "expect": "invalid", "reason_match": "gap"})

    m = copy.deepcopy(smap)
    m["spans"][2]["end"] = 23
    dump(NEG / "span-map-overlap.json", m)
    out.append({"kind": "span-map", "path": "negative/span-map-overlap.json", "expect": "invalid", "reason_match": "overlap"})

    c = copy.deepcopy(cert)
    c["ranked_candidates"][0]["confidence"] = 0.83
    dump(NEG / "certificate-numeric-confidence.json", c)
    out.append({"kind": "ambiguity-certificate", "path": "negative/certificate-numeric-confidence.json", "expect": "invalid",
                "reason_match": "confidence", "note": "no numeric confidence anywhere (round 3 blocking change 2)"})

    c = copy.deepcopy(cert)
    c["enumeration"]["survivors"] = ["src_endpoint.ip"]
    dump(NEG / "certificate-single-survivor-ambiguous.json", c)
    out.append({"kind": "ambiguity-certificate", "path": "negative/certificate-single-survivor-ambiguous.json", "expect": "invalid",
                "reason_match": "survivors", "note": "one survivor is structural determination, never an ambiguity"})

    p = copy.deepcopy(pack)
    p["families"][0]["mapping"]["fields"][3]["provenance"] = {"category": "model_proposal"}
    dump(NEG / "pack-mandatory-model-only.json", p)
    out.append({"kind": "parser-pack", "path": "negative/pack-mandatory-model-only.json", "expect": "invalid",
                "reason_match": ["model_proposal", "not failed", "/provenance/category"], "note": "invariant 4 at the contract level"})

    p = copy.deepcopy(pack)
    p["families"][0]["mapping"]["fields"][3]["provenance"] = {"category": "structural_determination",
                                                              "enumerated_survivors": ["http_request.url.url_string", "proxy_http_request.url.url_string"]}
    dump(NEG / "pack-structural-determination-two-survivors.json", p)
    out.append({"kind": "parser-pack", "path": "negative/pack-structural-determination-two-survivors.json", "expect": "invalid",
                "reason_match": ["enumerated_survivors", "structural_determination"],
                "note": "two survivors is an ambiguity, never a structural determination — the real 4002 table has both url leaves"})

    p = copy.deepcopy(pack)
    p["schema_version"] = "2.0.0"
    dump(NEG / "pack-version-bumped.json", p)
    out.append({"kind": "parser-pack", "path": "negative/pack-version-bumped.json", "expect": "invalid",
                "reason_match": "unsupported schema_version", "note": "fail closed on unknown contract versions"})

    p = copy.deepcopy(pack)
    p["ocsf"]["pinned_attributes"] = ["src_endpoint.ip", "dst_endpoint.ip", "http_request.url"]
    dump(NEG / "pack-attribute-pinning.json", p)
    out.append({"kind": "parser-pack", "path": "negative/pack-attribute-pinning.json", "expect": "invalid",
                "reason_match": "pinned_attributes", "note": "subset guard: the contract cannot express attribute-level pinning"})

    p = copy.deepcopy(pack)
    p["ocsf"]["pinned_classes"][0]["table_hash"] = "sha256:" + "ab" * 32
    dump(NEG / "pack-subset-guard-stale-table.json", p)
    out.append({"kind": "parser-pack", "path": "negative/pack-subset-guard-stale-table.json", "expect": "invalid",
                "reason_match": "subset guard", "note": "a pack must pin the complete class table exactly as generated"})
    return out


def sign_golden():
    """Detached ed25519 signature over the exact bytes of the golden pack.json by the dev pack authority
    (keys/dev, demo-grade). The Go loader refuses the pack without it since P5."""
    sys.path.insert(0, str(ROOT / "learning"))
    from ulpf_learn.signing import sign_pack, verify_pack  # noqa: E402
    sign_pack(SQ)
    verify_pack(SQ)


def main():
    pack = rehash_pack()
    sign_golden()
    resolve_certificates()
    normalized_golden()
    vectors = [
        {"kind": "normalized-event", "path": "squid-native/normalized/line1.json", "expect": "valid"},
        {"kind": "parser-spec", "path": "squid-native/specs/squid-native-positional-10.json", "expect": "valid"},
        {"kind": "parser-spec", "path": "squid-native/specs/squid-native-candidate.json", "expect": "valid"},
        {"kind": "span-map", "path": "squid-native/span-maps/line1-promoted.json", "expect": "valid"},
        {"kind": "span-map", "path": "squid-native/span-maps/line1-candidate.json", "expect": "valid"},
        {"kind": "ambiguity-certificate", "path": "squid-native/certificate-snapshots/cert_squid_pos3_ambiguous.json", "expect": "valid"},
        {"kind": "ambiguity-certificate", "path": "squid-native/certificate-snapshots/cert_squid_pos5_ambiguous.json", "expect": "valid"},
        {"kind": "ambiguity-certificate", "path": "squid-native/certificates/cert_squid_pos3.json", "expect": "valid"},
        {"kind": "ambiguity-certificate", "path": "squid-native/certificates/cert_squid_pos5.json", "expect": "valid"},
        {"kind": "ambiguity-certificate", "path": "unresolved/cert_out_of_library.json", "expect": "valid"},
        {"kind": "parser-pack", "path": "squid-native/pack.json", "expect": "valid"},
    ] + negatives(pack)
    dump(GOLDEN / "index.json", {"note": "Generated by contracts/golden/tools/build_vectors.py; both validation suites iterate this list.", "vectors": vectors})
    print(f"wrote {len(vectors)} vectors")


def check() -> int:
    """Regenerate into a SCRATCH COPY and compare with the committed goldens; fail on any difference.

    Until P8 every phase check began by regenerating the goldens in place — line 1's normalized event from the
    runtime's current output, every hash, the negatives, the index — and then "checked" them, so a regression
    that stayed schema-valid rewrote its own expectation and passed (audit §3.1). The checks now call this:
    the committed files are the expectation, regeneration is a deliberate `--write` whose diff gets reviewed.
    `pack.json.sig` is excluded: it is git-ignored and signed per machine by keys-bootstrap."""
    global GOLDEN, SQ, NEG
    committed = GOLDEN
    tmp = Path(tempfile.mkdtemp(prefix="ulpf-golden-check-"))
    try:
        scratch = tmp / "golden"
        shutil.copytree(committed, scratch, ignore=shutil.ignore_patterns("__pycache__"))
        GOLDEN, SQ, NEG = scratch, scratch / "squid-native", scratch / "negative"
        main()
        skip = {"pack.json.sig"}
        def files(root):
            return {str(f.relative_to(root)).replace(chr(92), "/"): f for f in root.rglob("*") if f.is_file() and f.name not in skip and "__pycache__" not in f.parts}
        old, new = files(committed), files(scratch)
        problems = [f"only in the committed tree: {k}" for k in sorted(set(old) - set(new))] + [f"regeneration produces a file that is not committed: {k}" for k in sorted(set(new) - set(old))]
        for k in sorted(set(old) & set(new)):
            if old[k].read_bytes() != new[k].read_bytes():
                problems.append(f"DIFFERS: {k}")
                if k.endswith(".json"):
                    import difflib
                    d = list(difflib.unified_diff(old[k].read_text(encoding="utf-8").splitlines(), new[k].read_text(encoding="utf-8").splitlines(), "committed/" + k, "regenerated/" + k, lineterm="", n=1))
                    problems += ["    " + l for l in d[:24]]
        if problems:
            print("GOLDEN CHECK: FAIL — the committed goldens are not what the current code produces:")
            print(chr(10).join("  " + x for x in problems))
            print("  If the change is intended: python contracts/golden/tools/build_vectors.py --write, review the diff, commit it.")
            return 1
        print(f"GOLDEN CHECK: ok — {len(old)} committed golden files are byte-identical to a fresh regeneration")
        return 0
    finally:
        GOLDEN, SQ, NEG = committed, committed / "squid-native", committed / "negative"
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        sys.exit(check())
    if sys.argv[1:] == ["--write"]:
        main()
        sys.exit(0)
    sys.exit("usage: build_vectors.py --check   (compare the committed goldens with a fresh regeneration; what every phase check runs)" + chr(10) +
             "       build_vectors.py --write   (regenerate in place: a deliberate act — review and commit the diff)")
