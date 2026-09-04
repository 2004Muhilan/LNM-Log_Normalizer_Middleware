#!/usr/bin/env python3
"""Print the catalogue's family inventory and a few representative lines per vendor (local only)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
cat = json.loads((ROOT / "corpus" / "catalogue.json").read_text())
for f in cat["files"]:
    if f["kind"] != "samples":
        continue
    fam = f.get("families", {})
    print(f"== {f['cache_path']}  lines={f.get('lines')}  families={f.get('family_count')}")
    for k, v in list(fam.items())[:40]:
        print(f"     {v:5d}  {k}")

PEEK = {
    "beats-cisco-asa/asa.log": [0, 1, 2, 10, 40, 80],
    "beats-cisco-asa/additional_messages.log": [0, 5, 20, 40],
    "beats-fortinet-firewall/traffic.log": [0, 1],
    "beats-fortinet-firewall/utm.log": [0, 1],
    "beats-fortinet-firewall/event.log": [0, 1],
    "beats-panw-panos/traffic.log": [0, 1],
    "beats-panw-panos/threat.log": [0, 1],
    "beats-panw-panos/pan_inc_traffic_ietf.log": [0],
    "beats-panw-panos/pan_inc_other.log": [0, 1, 2],
    "beats-squid-log/access1.log": [0, 1, 2],
    "beats-squid-log/generated.log": [0, 1],
}
for rel, idxs in PEEK.items():
    p = ROOT / "corpus" / "cache" / rel
    lines = [l for l in p.read_bytes().split(b"\n") if l.strip()]
    print(f"\n#### {rel}")
    for i in idxs:
        if i < len(lines):
            print(f"[{i}] {lines[i][:400].decode('utf-8', 'replace')}")
