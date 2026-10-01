#!/usr/bin/env bash
# One-shot: wait for OpenSearch, then set it up (templates, the custom log type, rules, detector; with Dashboards: index
# patterns, panels, dashboards, saved searches) — demo/siem/setup.py, idempotent. DEMO ONLY: the security plugin is off.
set -euo pipefail
cd /ulpf
OS="http://127.0.0.1:${ULPF_OS_PORT:-9200}"
python - "$OS" <<'EOF'
import json, sys, time, urllib.request
end = time.time() + 240
while time.time() < end:
    try:
        if json.loads(urllib.request.urlopen(sys.argv[1] + "/_cluster/health", timeout=2).read())["status"] in ("green", "yellow"):
            sys.exit(0)
    except Exception:
        pass
    time.sleep(1)
sys.exit("OpenSearch did not become ready at " + sys.argv[1])
EOF
exec python demo/siem/setup.py --os "$OS" $([ "${ULPF_DASHBOARDS:-1}" = 1 ] && echo --osd "http://127.0.0.1:${ULPF_OSD_PORT:-5601}")
