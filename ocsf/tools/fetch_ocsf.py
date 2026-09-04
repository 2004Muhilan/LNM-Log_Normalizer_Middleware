#!/usr/bin/env python3
"""Fetch the OCSF 1.3.0 definitions from two independent sources into ocsf/cache (git-ignored).

1. The schema server's compiled export:   https://schema.ocsf.io/1.3.0/export/schema
2. The schema source repository at tag 1.3.0: https://github.com/ocsf/ocsf-schema (Apache-2.0)

Both hashes are pinned in ocsf/pinned/manifest.json so the derived tables are reproducible.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "ocsf" / "cache"
PINNED = ROOT / "ocsf" / "pinned"
VERSION = "1.3.0"


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ulpf-ocsf"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    PINNED.mkdir(parents=True, exist_ok=True)

    export_path = CACHE / f"ocsf-{VERSION}-export.json"
    if not export_path.exists():
        export_path.write_bytes(get(f"https://schema.ocsf.io/{VERSION}/export/schema"))
    export_sha = hashlib.sha256(export_path.read_bytes()).hexdigest()

    src_dir = CACHE / f"ocsf-schema-{VERSION}"
    tar_path = CACHE / f"ocsf-schema-{VERSION}.tar.gz"
    if not tar_path.exists():
        tar_path.write_bytes(get(f"https://github.com/ocsf/ocsf-schema/archive/refs/tags/{VERSION}.tar.gz"))
    src_sha = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    if not src_dir.exists():
        with tarfile.open(fileobj=io.BytesIO(tar_path.read_bytes()), mode="r:gz") as tf:
            top = tf.getmembers()[0].name.split("/", 1)[0]
            tf.extractall(CACHE, filter="data")
        if top != src_dir.name:
            (CACHE / top).rename(src_dir)

    manifest = {
        "ocsf_version": VERSION,
        "export": {"url": f"https://schema.ocsf.io/{VERSION}/export/schema", "sha256": export_sha,
                   "cache_path": str(export_path.relative_to(ROOT)).replace("\\", "/")},
        "source": {"url": f"https://github.com/ocsf/ocsf-schema/archive/refs/tags/{VERSION}.tar.gz", "sha256": src_sha,
                   "licence": "Apache-2.0", "cache_path": str(src_dir.relative_to(ROOT)).replace("\\", "/")},
    }
    (PINNED / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
