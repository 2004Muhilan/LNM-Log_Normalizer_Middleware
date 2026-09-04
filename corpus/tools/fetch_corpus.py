#!/usr/bin/env python3
"""Fetch the reference corpus into corpus/cache (git-ignored) and write corpus/catalogue.json.

Fixture files are never committed: the catalogue records provenance (repo, ref, pinned commit,
path, licence), content hashes, line counts, and a per-vendor event-family inventory.
Re-running is idempotent; a cached file whose hash matches the catalogue is not re-downloaded.
"""
from __future__ import annotations

import collections
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "corpus" / "cache"
CATALOGUE = ROOT / "corpus" / "catalogue.json"

# (source_id, owner/repo, ref, directory, [files], licence, role)
SOURCES = [
    ("beats-cisco-asa", "elastic/beats", "main", "x-pack/filebeat/module/cisco/asa/test",
     ["asa.log", "asa-fix.log", "additional_messages.log", "sample.log", "non-canonical.log",
      "asa_missing_groups.log", "not-ip.log", "hostnames.log", "filtered.log", "dap_records.log"],
     "Elastic-License-2.0", "primary"),
    ("beats-fortinet-firewall", "elastic/beats", "main", "x-pack/filebeat/module/fortinet/firewall/test",
     ["traffic.log", "utm.log", "event.log", "event-nul.log"], "Elastic-License-2.0", "primary"),
    ("beats-panw-panos", "elastic/beats", "main", "x-pack/filebeat/module/panw/panos/test",
     ["traffic.log", "threat.log", "pan_inc_traffic.log", "pan_inc_threat.log", "pan_inc_other.log",
      "pan_inc_traffic_ietf.log", "traffic_nanos_time.log", "global_protect.log", "userid.log", "hipmatch.log"],
     "Elastic-License-2.0", "primary"),
    ("beats-squid-log", "elastic/beats", "7.17", "x-pack/filebeat/module/squid/log/test",
     ["access1.log", "generated.log"], "Elastic-License-2.0", "primary"),
    ("logstash-patterns-core", "logstash-plugins/logstash-patterns-core", "main", "spec/patterns",
     ["firewalls_spec.rb", "squid_spec.rb"], "Apache-2.0", "fallback"),
]


def http_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "ulpf-corpus"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def http_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ulpf-corpus"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def resolve_commit(repo: str, ref: str) -> str:
    return http_json(f"https://api.github.com/repos/{repo}/commits/{ref}")["sha"]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


ASA_ID = re.compile(rb"%(ASA|FTD|PIX)-(?:[a-z]+-)?(\d)-(\d{6})")
PANOS_TYPE_IDX = 3  # 0-based CSV column of the log type (TRAFFIC/THREAT/SYSTEM/...)
FGT_KV = re.compile(rb'(?:^|\s)(type|subtype|logid)=("?)([^\s"]*)\2')


def panos_families(lines):
    fam = collections.Counter()
    for ln in lines:
        # strip an RFC3164/5424 header if present: payload begins at the first ",<digit>" after "1," or at "1,"
        m = re.search(rb"(?:^|\s)(\d+,\d{4}/\d\d/\d\d [\d:]+,[^,]*,)([A-Z\-]+),([^,]*),", ln)
        if not m:
            fam["<unrecognised>"] += 1
            continue
        fam[f"{m.group(2).decode()}/{m.group(3).decode()}"] += 1
    return fam


def asa_families(lines):
    fam = collections.Counter()
    for ln in lines:
        m = ASA_ID.search(ln)
        fam[f"%{m.group(1).decode()}-{m.group(2).decode()}-{m.group(3).decode()}" if m else "<no-msg-id>"] += 1
    return fam


def fortinet_families(lines):
    fam = collections.Counter()
    for ln in lines:
        kv = {k.decode(): v.decode() for k, _, v in FGT_KV.findall(ln)}
        fam[f"{kv.get('type','?')}/{kv.get('subtype','?')}"] += 1
    return fam


def squid_families(lines):
    fam = collections.Counter()
    for ln in lines:
        s = ln.strip()
        if re.match(rb"^\d{10}\.\d{3}\s+\d+\s+\S+\s+\S+/\d{3}\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+/\S+\s+\S+", s):
            fam["native"] += 1
        elif re.match(rb'^\S+ \S+ \S+ \[[^\]]+\] "', s):
            fam["combined/common"] += 1
        elif s:
            fam["<other>"] += 1
    return fam


FAMILY_FN = {
    "beats-cisco-asa": asa_families,
    "beats-fortinet-firewall": fortinet_families,
    "beats-panw-panos": panos_families,
    "beats-squid-log": squid_families,
}


def main() -> int:
    old = json.loads(CATALOGUE.read_text()) if CATALOGUE.exists() else {"files": []}
    known = {f["cache_path"]: f for f in old.get("files", [])}
    files = []
    for source_id, repo, ref, directory, names, licence, role in SOURCES:
        commit = resolve_commit(repo, ref)
        for name in names:
            wanted = [name] + ([name + "-expected.json"] if source_id.startswith("beats-") else [])
            for fname in wanted:
                rel = f"{source_id}/{fname}"
                dest = CACHE / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                url = f"https://raw.githubusercontent.com/{repo}/{commit}/{directory}/{fname}"
                if dest.exists() and rel in known and known[rel]["sha256"] == sha256(dest.read_bytes()):
                    data = dest.read_bytes()
                else:
                    data = http_bytes(url)
                    dest.write_bytes(data)
                entry = {
                    "cache_path": rel, "source_id": source_id, "repo": repo, "ref": ref, "commit": commit,
                    "path": f"{directory}/{fname}", "licence": licence, "role": role,
                    "sha256": sha256(data), "bytes": len(data),
                }
                if fname.endswith("-expected.json"):
                    try:
                        entry["expected_events"] = len(json.loads(data))
                    except Exception:
                        entry["expected_events"] = None
                    entry["kind"] = "reference-output"
                else:
                    lines = [l for l in data.split(b"\n") if l.strip()]
                    entry["lines"] = len(lines)
                    entry["kind"] = "samples"
                    fn = FAMILY_FN.get(source_id)
                    if fn:
                        fam = fn(lines)
                        entry["families"] = dict(sorted(fam.items(), key=lambda kv: (-kv[1], kv[0])))
                        entry["family_count"] = len(fam)
                files.append(entry)
                print(f"{entry['sha256'][:12]}  {entry['bytes']:>8}  {rel}", file=sys.stderr)
    CATALOGUE.write_text(json.dumps({
        "note": "Fixture content is cached locally under corpus/cache (git-ignored) and never redistributed. "
                "See corpus/README.md for the licence verdict and attribution.",
        "files": files,
    }, indent=2) + "\n")
    print(f"catalogued {len(files)} files -> {CATALOGUE}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
