"""Pack signing on the learning plane: ed25519 detached signature over the EXACT bytes of pack.json,
written to pack.json.sig as hex. Key files are the runtime's format (runtime/internal/keys): JSON with
authority_id, algorithm "ed25519", public_key (hex, 32 bytes), private_key (hex seed, 32 bytes). The
runtime verifies against keys/trust/<authority_id>.pub.json and refuses the pack on any mismatch.
Demo-grade file-based keys by decision (plan §1)."""
from __future__ import annotations

import json
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


def sign_pack(pack_dir: Path, key_path: Path = DEFAULT_KEY) -> Path:
    """Sign <pack_dir>/pack.json; the authority named in the file's signing block must be the key's."""
    pack_dir = Path(pack_dir)
    data = (pack_dir / "pack.json").read_bytes()
    doc = json.loads(data)
    key = load_key(key_path)
    if doc["signing"]["authority_id"] != key["authority_id"]:
        raise ValueError(f"pack names authority {doc['signing']['authority_id']!r}, key is {key['authority_id']!r}")
    sig = sign_bytes(data, key)
    out = pack_dir / doc["signing"]["signature_file"]
    out.write_text(sig + "\n", encoding="utf-8")
    return out


def verify_pack(pack_dir: Path, trust_dir: Path = ROOT / "keys" / "trust") -> None:
    """The learning plane's own check of what it emitted (the runtime does its own, independently)."""
    pack_dir = Path(pack_dir)
    data = (pack_dir / "pack.json").read_bytes()
    doc = json.loads(data)
    pub = json.loads((Path(trust_dir) / f"{doc['signing']['authority_id']}.pub.json").read_text(encoding="utf-8"))
    sig = bytes.fromhex((pack_dir / doc["signing"]["signature_file"]).read_text(encoding="utf-8").strip())
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub["public_key"])).verify(sig, data)  # raises InvalidSignature
