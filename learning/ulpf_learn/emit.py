"""Pack emission: build the pack bundle from a promotable plan, validate it against the contracts,
and fill parser_hash from the runtime compiler (the only thing that can compute it)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from ulpf_contracts import validate_document

from .acceptance import Verdict, policy_for
from .plan import Plan

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_BIN = os.environ.get("ULPF_RUNTIME_BIN", str(ROOT / "runtime" / "bin" / "ulpf-runtime"))


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def canonical(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parser_hash(spec_path: Path) -> str:
    if not Path(RUNTIME_BIN).exists():
        raise RuntimeError(f"runtime binary not found at {RUNTIME_BIN}: parser_hash is runtime-defined")
    out = subprocess.run([RUNTIME_BIN, "compile", "--spec", str(spec_path)], check=True, capture_output=True, text=True).stdout
    return json.loads(out)["parser_hash"]


def emit_pack(plan: Plan, spec: dict, verdict: Verdict, certificates: list[dict], resolutions: list[dict],
              samples: bytes, sample_count: int, operator_id: str, pack_id: str, out_dir: Path, created_at: str,
              routing_sketch: dict, library_version: str) -> Path:
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "specs").mkdir(parents=True)
    (out_dir / "certificates").mkdir()
    (out_dir / "samples").mkdir()
    spec_path = out_dir / "specs" / f"{spec['spec_id']}.json"
    spec_bytes = (json.dumps(spec, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    spec_path.write_bytes(spec_bytes)
    (out_dir / "samples" / "access.log").write_bytes(samples)
    for c in certificates:
        (out_dir / "certificates" / f"{c['certificate_id']}.json").write_text(json.dumps(c, indent=2) + "\n", encoding="utf-8")
    pinned = {c["uid"]: c for c in json.loads((ROOT / "ocsf" / "pinned" / "index.json").read_text())["classes"]}
    cls = pinned[plan.event_class_uid]
    pol = policy_for(plan.event_class_uid)
    fields = plan.mapping_fields()
    mapping_hash = sha(canonical(fields))
    dsl_hash = sha(spec_bytes)
    p_hash = parser_hash(spec_path)
    family = {
        "family_id": f"positional-{len(plan.slots)}",
        "description": f"{plan.event_class_name} family induced from {sample_count} operator-supplied samples and resolved by device configuration.",
        "event_class_uid": plan.event_class_uid,
        "routing_signature": routing_sketch,
        "parser": {"spec_ref": f"specs/{spec['spec_id']}.json", "spec_id": spec["spec_id"], "dsl_hash": dsl_hash, "parser_hash": p_hash},
        "mapping": {"mapping_version": "1.0", "mapping_hash": mapping_hash, "fields": fields, "unmapped": plan.unmapped(),
                    "acceptance_snapshot": {"mandatory_attributes": list(pol["mandatory_attributes"]), "semantic_budget": pol["semantic_budget"]}},
        "validation": {"byte_conservation": 1.0, "critical_coverage": 1.0, "weighted_semantic_coverage": round(verdict.coverage.semantic_coverage, 4),
                       "held_out": {"samples": verdict.coverage.held_out_samples, "passed": verdict.coverage.held_out_passed}},
        "certificates": [c["certificate_id"] for c in certificates],
        "resolutions": resolutions,
        "sample_provenance": {"tier": 1, "operator_id": operator_id, "sample_count": sample_count, "corpus_hash": sha(samples)},
    }
    pack = {
        "schema_version": "1.1.0", "pack_id": pack_id, "pack_version": "1.0", "created_at": created_at,
        "source": {"source_id": plan.source_id, "vendor": "Squid", "product": "Squid Cache", "declared_envelope": "raw", "transport_hint": "file"},
        "ocsf": {"version": "1.3.0", "pinned_classes": [{"uid": cls["uid"], "name": cls["name"], "table_hash": cls["table_hash"]}]},
        "acceptance": {"policy_version": "1.0.0"},
        "time": {"source_timezone": plan.source_timezone, "timezone_confidence": plan.timezone_confidence},
        "anchors": [], "tiebreaker_field": None,
        "families": [family],
        "provenance": {"generator_version": "ulpf-gen-0.3", "validator_version": "ulpf-val-0.3", "model_hash": plan.model_hash, "discriminator_library_version": library_version},
        "hashes": {"parser_hash": sha(p_hash.encode()), "dsl_hash": sha(dsl_hash.encode()), "mapping_hash": sha(mapping_hash.encode()), "corpus_hash": sha(samples)},
        "signing": {"authority_id": "ulpf-pack-authority-dev", "algorithm": "ed25519", "signature_file": "pack.json.sig"},
    }
    pack_path = out_dir / "pack.json"
    pack_path.write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    errs = validate_document("parser-pack", pack, pack_dir=out_dir)
    if errs:
        raise RuntimeError("emitted pack fails the contract: " + "; ".join(errs))
    return pack_path
