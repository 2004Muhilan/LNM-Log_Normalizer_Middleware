#!/usr/bin/env bash
# Debug helper: show the state of a p6-build-packs work directory.
W=${1:-/tmp/ulpf-p6}
echo "--- runtime stats/stderr"; cat "$W/stats.json" 2>/dev/null | head -5
echo "--- packs"; ls "$W/packs" "$W/source-packs" 2>/dev/null
echo "--- fortigate respond tail"; tail -4 "$W/s-fortigate-traffic.respond.txt" 2>/dev/null
echo "--- squid-11 session"
python3 - "$W/s-squid-11/session.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
print("state:", s["state"])
print("blockers:", s["verdict"]["blockers"])
print("propagated:", [(h["slot_index"], h["fields"], h["attributes"]) for h in s.get("propagated", [])])
print("request:", (s.get("pending_request") or {}).get("text", "")[:300])
print("unevidenced:", s.get("unevidenced"))
print("provenance:", [(r["attribute"], r["category"], r["sufficient"]) for r in s["verdict"]["provenance"]])
PY
