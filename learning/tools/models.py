"""Model weights lifecycle: the only path weights take. Weights never enter git or the build context.

  list                  manifest entries and their cache state
  fetch   --id X|--all  download from the manifest's pinned source into the cache, verify sha256 (resumable)
  verify  --id X        verify a cached file against the manifest (exit 1 on mismatch)
  install --id X --dest D   copy a verified cached file into the image (build time), verify the copy
  serve   [--id X] [-- llama-server args]
                        verify at start, then exec llama-server; id from --id or $ULPF_MODEL_ID; refuses
                        to start on a digest mismatch (fail closed). $ULPF_NGL sets --n-gpu-layers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import urllib.request
from pathlib import Path

CHUNK = 1 << 22
ROOT = Path(__file__).resolve().parents[2]


def load(manifest: Path) -> dict:
    return json.loads(Path(manifest).read_text(encoding="utf-8"))


def entry(man: dict, mid: str) -> dict:
    for m in man["models"]:
        if m["id"] == mid:
            return m
    raise SystemExit(f"model id {mid!r} not in manifest; known: {[m['id'] for m in man['models']]}")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def verify(p: Path, m: dict) -> str:
    if not p.exists():
        raise SystemExit(f"missing: {p}")
    d = sha256_file(p)
    if d != m["sha256"]:
        raise SystemExit(f"DIGEST MISMATCH for {m['id']}: manifest {m['sha256']} file {d} ({p}); refusing")
    return d


def fetch(cache: Path, m: dict) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / m["file"]
    url = f"https://huggingface.co/{m['repo']}/resolve/main/{m['file']}"
    if dest.exists() and sha256_file(dest) == m["sha256"]:
        print(f"{m['id']}: cached and verified", flush=True)
        return dest
    part = dest.with_suffix(dest.suffix + ".part")
    have = part.stat().st_size if part.exists() else 0
    req = urllib.request.Request(url, headers={"Range": f"bytes={have}-"} if have else {})
    print(f"{m['id']}: fetching {url} (resume from {have})", flush=True)
    with urllib.request.urlopen(req, timeout=120) as r, open(part, "ab" if have else "wb") as f:
        if have and r.status != 206:
            f.seek(0)
            f.truncate()
            have = 0
        done = have
        next_mark = done + (512 << 20)
        while True:
            b = r.read(CHUNK)
            if not b:
                break
            f.write(b)
            done += len(b)
            if done >= next_mark:
                print(f"  {m['id']}: {done / 1e9:.2f} GB", flush=True)
                next_mark += 512 << 20
    d = sha256_file(part)
    if d != m["sha256"]:
        raise SystemExit(f"DIGEST MISMATCH after download for {m['id']}: {d}; leaving .part for inspection")
    part.rename(dest)
    print(f"{m['id']}: verified sha256:{d}", flush=True)
    return dest


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["fetch", "verify", "install", "serve", "list"])
    ap.add_argument("--manifest", default=str(ROOT / "models" / "manifest.json"))
    ap.add_argument("--cache", default=str(ROOT / "models" / "cache"))
    ap.add_argument("--dest")
    ap.add_argument("--id", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    a, llama_args = ap.parse_known_args(argv)  # serve: unknown args pass through to llama-server
    man = load(Path(a.manifest))
    cache = Path(a.cache)
    env_id = os.environ.get("ULPF_MODEL_ID")
    ids = [m["id"] for m in man["models"]] if a.all else (a.id or ([env_id] if env_id else []))
    if a.cmd == "list":
        for m in man["models"]:
            p = cache / m["file"]
            state = "verified" if p.exists() and sha256_file(p) == m["sha256"] else ("present-unverified" if p.exists() else "absent")
            print(f"{m['id']:26s} {m['bytes_approx_gb']:5.2f} GB  {state:18s} {m['role']}")
        return
    if not ids:
        raise SystemExit("--id required (or ULPF_MODEL_ID)")
    if a.cmd == "fetch":
        for mid in ids:
            fetch(cache, entry(man, mid))
    elif a.cmd == "verify":
        for mid in ids:
            m = entry(man, mid)
            print(f"{mid}: sha256:{verify(cache / m['file'], m)}")
    elif a.cmd == "install":
        dest = Path(a.dest)
        dest.mkdir(parents=True, exist_ok=True)
        for mid in ids:
            m = entry(man, mid)
            verify(cache / m["file"], m)
            shutil.copyfile(cache / m["file"], dest / m["file"])
            verify(dest / m["file"], m)
            print(f"{mid}: installed and verified")
    elif a.cmd == "serve":
        m = entry(man, ids[0])
        p = cache / m["file"]
        d = verify(p, m)
        print(f"{m['id']}: model_hash sha256:{d}; starting llama-server", flush=True)
        extra = [x for x in llama_args if x != "--"]
        argv2 = ["llama-server", "-m", str(p), "--parallel", "1", "--ctx-size", os.environ.get("ULPF_CTX", "8192"),
                 "--n-gpu-layers", os.environ.get("ULPF_NGL", "0"), "--seed", "0", *extra]
        os.execvp(shutil.which("llama-server") or "/app/llama-server", argv2)


if __name__ == "__main__":
    main()
