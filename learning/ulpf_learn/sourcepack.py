"""Source packs: one pack per SOURCE with per-family entries (architecture §3.9, plan P6). Each family
is onboarded and promoted on its own (one session, one signed single-family pack); this module merges
those into the source pack: families and their specs and certificates side by side, the vendor table's
anchors declared once at pack level, the pack-level hashes recomputed over the families in order, and
the result signed. Nothing is re-derived: every family entry is the promoted one, byte for byte."""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from ulpf_contracts import validate_document

from .emit import PACK_SCHEMA_VERSION
from .signing import DEFAULT_KEY, sign_pack


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def merge(pack_dirs: list[Path], out_dir: Path, pack_id: str, anchors: list[dict], key_path: Path = DEFAULT_KEY, pack_version: str | None = None) -> Path:
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "specs").mkdir(parents=True)
    (out_dir / "certificates").mkdir()
    (out_dir / "samples").mkdir()
    base = None
    families, dsl, mapping, parser, corpus = [], [], [], [], []
    seen_specs: set[str] = set()
    for d in [Path(p) for p in pack_dirs]:
        pk = json.loads((d / "pack.json").read_text(encoding="utf-8"))
        if base is None:
            base = pk
        elif pk["source"]["source_id"] != base["source"]["source_id"] or pk["ocsf"] != base["ocsf"]:
            raise ValueError(f"{d}: different source or OCSF pinning than {pack_dirs[0]}")
        for fam in pk["families"]:
            ref = fam["parser"]["spec_ref"]
            if ref in seen_specs:
                raise ValueError(f"duplicate spec {ref}")
            seen_specs.add(ref)
            shutil.copyfile(d / ref, out_dir / ref)
            for cid in fam["certificates"]:
                shutil.copyfile(d / "certificates" / f"{cid}.json", out_dir / "certificates" / f"{cid}.json")
            families.append(fam)
            dsl.append(fam["parser"]["dsl_hash"]); mapping.append(fam["mapping"]["mapping_hash"]); parser.append(fam["parser"]["parser_hash"])
            corpus.append(fam["sample_provenance"]["corpus_hash"])
        for s in (d / "samples").iterdir():
            shutil.copyfile(s, out_dir / "samples" / f"{fam['family_id']}-{s.name}")
    assert base is not None
    pack = dict(base)
    pack["schema_version"] = "1.4.0" if (pack.get("time") or {}).get("timezone_field") else PACK_SCHEMA_VERSION
    pack["pack_id"] = pack_id
    if pack_version:
        pack["pack_version"] = pack_version   # a corrected family inside: the source pack's version moves with it
    pack["families"] = families
    pack["anchors"] = anchors
    pack.pop("tiebreaker_field", None)   # dropped at the P6 boundary; older single-family packs may still carry it as null
    pack["hashes"] = {"parser_hash": sha("".join(parser).encode()), "dsl_hash": sha("".join(dsl).encode()),
                      "mapping_hash": sha("".join(mapping).encode()), "corpus_hash": sha("".join(corpus).encode())}
    (out_dir / "pack.json").write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    sign_pack(out_dir, key_path, produced_by="vendor-onboarded")
    errs = validate_document("parser-pack", pack, pack_dir=out_dir)
    if errs:
        raise RuntimeError("merged source pack fails the contract: " + "; ".join(errs))
    return out_dir / "pack.json"
