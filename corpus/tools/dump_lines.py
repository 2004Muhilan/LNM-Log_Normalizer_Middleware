#!/usr/bin/env python3
"""Dump specific corpus lines and edge cases needed for the DSL sufficiency drafts (local only)."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C = ROOT / "corpus" / "cache"


def lines(rel):
    return [l for l in (C / rel).read_bytes().split(b"\n") if l.strip()]


def show(title, ls, limit=6):
    print(f"\n#### {title} ({len(ls)} matches)")
    for l in ls[:limit]:
        print("  ", l.decode("utf-8", "replace"))


asa = lines("beats-cisco-asa/asa.log") + lines("beats-cisco-asa/additional_messages.log") + lines("beats-cisco-asa/sample.log") + lines("beats-cisco-asa/asa-fix.log")
for mid in [b"106023", b"302013", b"302014", b"302016", b"305011", b"305012", b"106100", b"113004", b"733100", b"302020"]:
    show(f"ASA {mid.decode()}", [l for l in asa if b"-" + mid + b":" in l], 4)
show("ASA with 'by access-group'", [l for l in asa if b"access-group" in l], 3)
show("ASA 106023 without access-group", [l for l in asa if b"106023" in l and b"access-group" not in l], 3)
show("ASA non-canonical headers", lines("beats-cisco-asa/non-canonical.log"), 6)
show("ASA hostnames", lines("beats-cisco-asa/hostnames.log"), 2)

pan = lines("beats-panw-panos/traffic.log") + lines("beats-panw-panos/threat.log") + lines("beats-panw-panos/pan_inc_threat.log")
show("PAN-OS full TRAFFIC line", lines("beats-panw-panos/traffic.log")[:1], 1)
show("PAN-OS full THREAT line", lines("beats-panw-panos/threat.log")[:1], 1)
show("PAN-OS quoted cell containing comma", [l for l in pan if re.search(rb'"[^"]*,[^"]*"', l)], 3)
show("PAN-OS doubled quotes inside cell", [l for l in pan if b'""' in l], 3)
show("PAN-OS ietf (RFC5424 + octet count)", lines("beats-panw-panos/pan_inc_traffic_ietf.log")[:1], 1)
show("PAN-OS nanos", lines("beats-panw-panos/traffic_nanos_time.log"), 1)
show("PAN-OS globalprotect", lines("beats-panw-panos/global_protect.log")[:2], 2)
t = lines("beats-panw-panos/traffic.log")[0]
payload = t.split(b" 1,", 1)[1]
print("\nPAN-OS TRAFFIC field count (naive split):", len((b"1," + payload).split(b",")))

fgt = lines("beats-fortinet-firewall/traffic.log") + lines("beats-fortinet-firewall/utm.log") + lines("beats-fortinet-firewall/event.log")
show("FortiGate full traffic line", lines("beats-fortinet-firewall/traffic.log")[:1], 1)
show("FortiGate escaped quote inside value", [l for l in fgt if b'\\"' in l], 3)
show("FortiGate value with spaces (msg=)", [l for l in fgt if b'msg="' in l], 2)
show("FortiGate unquoted key=value with '=' in value?", [l for l in fgt if re.search(rb'=[^" ]*=[^" ]*( |$)', l)], 3)
show("FortiGate event-nul raw repr", [repr(l).encode() for l in lines("beats-fortinet-firewall/event-nul.log")[:1]], 1)
keys = set()
for l in lines("beats-fortinet-firewall/traffic.log"):
    keys.update(re.findall(rb'(?:^|\s)([a-z_0-9]+)=', l))
print("\nFortiGate traffic key union:", len(keys), sorted(k.decode() for k in keys))
per_line = [len(re.findall(rb'(?:^|\s)([a-z_0-9]+)=', l)) for l in lines("beats-fortinet-firewall/traffic.log")]
print("FortiGate traffic keys per line:", per_line)

sq = lines("beats-squid-log/access1.log")
show("Squid native with '-' user and no mime", [l for l in sq if l.endswith(b" -")], 2)
show("Squid native CONNECT", [l for l in sq if b"CONNECT" in l], 2)
gen = lines("beats-squid-log/generated.log")
print("\n#### Squid generated.log full line 0:\n  ", gen[0].decode("utf-8", "replace"))
exp = json.loads((C / "beats-squid-log/generated.log-expected.json").read_text())
print("\n#### Squid generated.log-expected[0] (Beats' interpretation):")
for k, v in sorted(exp[0].items()):
    if not k.startswith(("event.dataset", "fileset", "input", "service", "tags", "log.offset", "event.module")):
        print(f"   {k}: {json.dumps(v)[:120]}")
print("\n#### Squid access1 expected[1]:")
for k, v in sorted(json.loads((C / "beats-squid-log/access1.log-expected.json").read_text())[1].items()):
    print(f"   {k}: {json.dumps(v)[:120]}")
print("\n#### ASA expected[1] (302013):")
for k, v in sorted(json.loads((C / "beats-cisco-asa/asa.log-expected.json").read_text())[1].items()):
    print(f"   {k}: {json.dumps(v)[:120]}")
