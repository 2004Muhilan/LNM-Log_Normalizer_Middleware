"""Pack signing on the learning plane: ed25519 detached signature over the EXACT bytes of pack.json,
written to pack.json.sig as hex. Key files are the runtime's format (runtime/internal/keys): JSON with
authority_id, algorithm "ed25519", public_key (hex, 32 bytes), private_key (hex seed, 32 bytes). The
runtime verifies against keys/trust/<authority_id>.pub.json and refuses the pack on any mismatch.
Demo-grade file-based keys by decision (plan §1)."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KEY = ROOT / "keys" / "dev" / "ulpf-pack-authority-dev.json"


def load_key(path: Path = DEFAULT_KEY) -> dict:
    k = json.loads(Path(path).read_text(encoding="utf-8"))
    if k.get("algorithm") != "ed25519" or "private_key" not in k:
        raise ValueError(f"{path}: not an ed25519 private key file")
    return k


def sign_bytes(data: bytes, key: dict) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["private_key"]))
    pub_hex = priv.public_key().public_bytes_raw().hex()
    if pub_hex != key["public_key"]:
        raise ValueError("key file's public key does not match its private key")
    return priv.sign(data).hex()


def sign_pack(pack_dir: Path, key_path: Path = DEFAULT_KEY, produced_by: str | None = None, log: bool = True) -> Path:
    """Sign <pack_dir>/pack.json; the authority named in the file's signing block must be the key's. Then APPEND the pack
    to the Parser Transparency Log (runtime/bin/ulpf-tlog; 2026-09-27): the runtime refuses any pack without a valid
    inclusion proof, so signing and logging are one act — every pack, hand-written, onboarded or auto-healed, is logged
    before anything can load it. `produced_by` is recorded in the log entry (default: ULPF_PACK_PRODUCED_BY, else
    "onboarded"). `log=False` exists for one purpose: the demo's deliberately UNLOGGED pack, which the runtime refuses."""
    pack_dir = Path(pack_dir)
    data = (pack_dir / "pack.json").read_bytes()
    doc = json.loads(data)
    key = load_key(key_path)
    if doc["signing"]["authority_id"] != key["authority_id"]:
        raise ValueError(f"pack names authority {doc['signing']['authority_id']!r}, key is {key['authority_id']!r}")
    sig = sign_bytes(data, key)
    out = pack_dir / doc["signing"]["signature_file"]
    # `<authority_id> <hex signature>`: the verifier reads the authority from the .sig, looks up the key
    # and verifies the exact bytes BEFORE parsing pack.json (signature before contract, P5 boundary)
    out.write_text(f"{key['authority_id']} {sig}\n", encoding="utf-8")
    if log:
        log_pack(pack_dir, produced_by or os.environ.get("ULPF_PACK_PRODUCED_BY") or "onboarded")
    else:
        (pack_dir / "pack.json.tlog-proof").unlink(missing_ok=True)
    return out


def log_pack(pack_dir: Path, produced_by: str) -> str:
    """Append the pack to the parser transparency log (idempotent) and write its proof beside it."""
    tool = ROOT / "runtime" / "bin" / "ulpf-tlog"
    if not tool.exists():
        raise RuntimeError(f"{tool} is missing: build the runtime binaries (scripts/keys-bootstrap.sh) — a pack cannot be logged, so it could never load")
    r = subprocess.run([str(tool), "append", "--pack", str(pack_dir), "--produced-by", produced_by], capture_output=True, text=True,
                       env={**os.environ, "ULPF_ROOT": str(ROOT)})
    if r.returncode != 0:
        raise RuntimeError("the parser transparency log refused the append: " + (r.stdout + r.stderr).strip()[-400:])
    return r.stdout.strip()


def verify_pack(pack_dir: Path, trust_dir: Path = ROOT / "keys" / "trust") -> None:
    """The learning plane's own check of what it emitted (the runtime does its own, independently)."""
    pack_dir = Path(pack_dir)
    data = (pack_dir / "pack.json").read_bytes()
    doc = json.loads(data)
    authority, sig_hex = (pack_dir / doc["signing"]["signature_file"]).read_text(encoding="utf-8").split()
    if authority != doc["signing"]["authority_id"]:
        raise ValueError(f"signature by {authority!r} but pack names {doc['signing']['authority_id']!r}")
    pub = json.loads((Path(trust_dir) / f"{authority}.pub.json").read_text(encoding="utf-8"))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub["public_key"])).verify(bytes.fromhex(sig_hex), data)  # raises InvalidSignature
