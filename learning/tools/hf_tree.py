"""List GGUF files (name, size, LFS sha256) in Hugging Face repos via the public API — the digests feed
models/manifest.json. Usage: python learning/tools/hf_tree.py <repo>..."""
import json, sys, urllib.request

for repo in sys.argv[1:]:
    print("==", repo)
    try:
        with urllib.request.urlopen(f"https://huggingface.co/api/models/{repo}/tree/main", timeout=60) as r:
            items = json.load(r)
    except Exception as e:  # noqa: BLE001
        print("   (no listing:", e, ")")
        continue
    if isinstance(items, dict):
        print("  ", items)
        continue
    for it in items:
        n = it.get("path", "")
        if n.endswith(".gguf") or n.endswith(".jinja"):
            lfs = it.get("lfs") or {}
            print(f"   {n}  {it.get('size', 0) / 1e9:.2f} GB  sha256={lfs.get('oid', '-')}")
