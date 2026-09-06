#!/usr/bin/env bash
# One-off verification for the P1-boundary decisions (action_id, url leaves, epoch_auto window).
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
python - <<'EOF'
import json, re, glob
t = json.load(open("ocsf/pinned/http_activity.json"))
leaves = {l["path"]: l for l in t["leaf_paths"]}
top = {a["name"]: a for a in t["attributes"]}
print("== item 1: action_id in http_activity (4002)")
for k in ("action", "action_id", "disposition", "disposition_id", "status_id"):
    a = top.get(k)
    print(f"  {k:16s} present={a is not None} profile={a.get('profile') if a else None} type={a.get('type') if a else None} enum={a.get('enum') if a else None}")
print("== item 11 / golden fidelity: url_t leaves (depth<=3) and http_request.url shape")
for p, l in sorted(leaves.items()):
    if l.get("type") == "url_t" and p.count(".") <= 3:
        print(f"  url_t  {p}")
for p in ("http_request.url", "http_request.url.url_string", "http_request.http_method", "http_response.content_type", "http_response.code", "proxy_http_request.url.url_string"):
    l = leaves.get(p)
    print(f"  {p:38s} -> {None if l is None else (l.get('type'), l.get('object_type'))}")
print("== string_t leaves at depth<=1 that could take a bare method word (count only):",
      sum(1 for p, l in leaves.items() if l.get("type") == "string_t" and p.count(".") <= 1))
print("== item 3: epoch_auto window 2000-2100 over every FortiGate eventtime in the corpus")
S, E = 946684800, 4102444800
win = {"s": (S, E), "ms": (S*10**3, E*10**3), "us": (S*10**6, E*10**6), "ns": (S*10**9, E*10**9)}
vals = []
for f in glob.glob("corpus/cache/beats-fortinet-firewall/*.log"):
    vals += [int(v) for v in re.findall(rb"eventtime=(\d+)", open(f, "rb").read())]
from collections import Counter
c = Counter()
bad = []
for v in vals:
    hits = [k for k, (lo, hi) in win.items() if lo <= v < hi]
    c[tuple(hits)] += 1
    if len(hits) != 1:
        bad.append(v)
print(f"  values={len(vals)} selection histogram={dict(c)} ambiguous_or_none={bad[:5]}")
print(f"  window gaps: s..ms {E} < {S*10**3}: {E < S*10**3}; ms..us {E*10**3 < S*10**6}; us..ns {E*10**6 < S*10**9}")
EOF
echo "== item 2: where framing_method appears in the frozen contracts"
grep -rn "framing" contracts/*.schema.json || echo "  (not present in any contract schema)"
grep -n "framing" contracts/README.md | head -5
