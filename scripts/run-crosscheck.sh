#!/usr/bin/env bash
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
python ocsf/tools/crosscheck_source.py
echo "=== profiles/datetime.json ==="
python -c 'import json; print(json.dumps(json.load(open("ocsf/cache/ocsf-schema-1.3.0/profiles/datetime.json")), indent=1)[:900])'
echo "=== ip_t leaf paths in http_activity (depth<=2) ==="
python - <<'EOF'
import json
t = json.load(open("ocsf/pinned/http_activity.json"))
ips = [l["path"] for l in t["leaf_paths"] if l.get("type") == "ip_t" and l["path"].count(".") <= 1]
print(len(ips), ips)
ints = [l["path"] for l in t["leaf_paths"] if l.get("type") in ("integer_t", "long_t") and l["path"].count(".") <= 1 and not l.get("enum")]
print(len(ints), ints)
EOF
