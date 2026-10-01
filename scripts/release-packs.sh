#!/usr/bin/env bash
# The SHIPPED parser packs of the container deployment (2026-10-01, the user's decision: "release key for shipped packs"):
# the hand-written Squid golden pack and the three vendor packs (Cisco ASA, PAN-OS, FortiGate), signed by the RELEASE
# authority `ulpf-pack-release` — the team's key, never a clone's dev key. An installation trusts it through
# keys/trust/ulpf-pack-release.pub.json (public, committed) and logs each shipped pack in ITS OWN transparency log on first
# start (deploy/init.sh), so "only what is in the log loads" holds on every install without exception.
#
#   bash scripts/release-packs.sh          -> packs/release/<name>/{pack.json, pack.json.sig, specs/, certificates/}   (git-ignored)
#
# What ships, and what never does:
#   - pack.json (its signing block names ulpf-pack-release; the hashes do not cover that block, so the parser is the same),
#     the specs it references, and the certificates its families reference (the contract requires them) WITHOUT
#     `field.sample_values` — the only place a certificate carries corpus values (174 values over 37 certificates, measured
#     2026-10-01); the schema makes it optional. NOT samples/: corpus lines (Elastic License 2.0 fixtures,
#     corpus/README.md: used locally, never redistributed).
#   - the release PRIVATE key: keys/release/ulpf-pack-release.json, git-ignored, never copied into an image or a bundle.
#     Lose it and no new release can be signed; leak it and anyone can sign packs every installation trusts.
#   - the signatures: produced here, they travel inside the images (deploy/ulpf.sh build | export), not in git.
# The vendor packs are built from the corpus cache (demo/reset.sh -> $STATE/p6/source-packs): a release is cut on a
# machine that has it.
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/../demo/lib.sh"
cd "$ROOT"
KEY=keys/release/ulpf-pack-release.json PUB=keys/trust/ulpf-pack-release.pub.json
[ -x runtime/bin/ulpf-committer ] || { echo "binaries missing: bash scripts/keys-bootstrap.sh"; exit 1; }
if [ ! -f "$KEY" ]; then
  mkdir -p keys/release && chmod 700 keys/release
  if [ -f "$PUB" ]; then echo "$PUB exists but its private key $KEY does not: restore the release key, never regenerate it silently"; exit 1; fi
  runtime/bin/ulpf-committer keygen --authority ulpf-pack-release --out "$KEY" --pub "$PUB"
  chmod 600 "$KEY"
fi
SRC="$STATE/p6/source-packs"
for v in cisco-asa panos fortigate; do [ -f "$SRC/$v/pack.json" ] || { echo "vendor pack $v missing in $SRC: bash demo/reset.sh"; exit 1; }; done
rm -rf packs/release; mkdir -p packs/release
python - "$KEY" "$ROOT/contracts/golden/squid-native" "$SRC/cisco-asa" "$SRC/panos" "$SRC/fortigate" <<'EOF'
import json, shutil, sys
from pathlib import Path
sys.path.insert(0, "learning")
from ulpf_learn.signing import sign_pack
key = Path(sys.argv[1])
for src in map(Path, sys.argv[2:]):
    doc = json.loads((src / "pack.json").read_text(encoding="utf-8"))
    dst = Path("packs/release") / src.name
    (dst / "specs").mkdir(parents=True)
    for fam in doc["families"]:
        shutil.copy2(src / fam["parser"]["spec_ref"], dst / fam["parser"]["spec_ref"])
        for cid in fam.get("certificates", []):
            cert = json.loads((src / "certificates" / f"{cid}.json").read_text(encoding="utf-8"))
            cert.get("field", {}).pop("sample_values", None)   # corpus values: not redistributed
            (dst / "certificates").mkdir(exist_ok=True)
            (dst / "certificates" / f"{cid}.json").write_text(json.dumps(cert, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    doc["signing"]["authority_id"] = "ulpf-pack-release"
    (dst / "pack.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    sign_pack(dst, key_path=key, log=False)   # logged by each installation's own log, on first start
    print(f"  {dst}: {doc['pack_id']} v{doc['pack_version']}, {len(doc['families'])} families, signed by ulpf-pack-release")
EOF
echo "release packs: packs/release (git-ignored; shipped inside the images). Public key: $PUB"
