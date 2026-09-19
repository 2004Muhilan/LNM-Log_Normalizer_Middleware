#!/usr/bin/env bash
# Build demo-replay.zip from a capture (demo/replay/capture.sh) — the recording, the unchanged UI plus
# replay.js, the stdlib replay server, the notices, and (unless --no-binaries) static linux/amd64
# binaries for the optional real mode. Output: ~/demo-replay.zip (outside the repository: the capture
# holds Elastic-licensed fixture lines).
set -euo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
CAP="${ULPF_DEMO_CAPTURE:-$HOME/ulpf-demo-capture}"
OUT="${1:-$HOME/demo-replay.zip}"
[ -f "$CAP/status.json" ] || { echo "no capture at $CAP: run demo/replay/capture.sh"; exit 1; }
W=$(mktemp -d); B="$W/demo-replay"; mkdir -p "$B"
cp -r "$CAP" "$B/capture"
cp -r "$ROOT/demo/ui" "$B/ui"
cp "$HERE/replay.js" "$B/ui/replay.js"
sed -i 's|<script src="app.js"></script>|<script src="app.js"></script>\n<script src="replay.js"></script>|' "$B/ui/index.html"
grep -q replay.js "$B/ui/index.html"
cp "$HERE/serve.py" "$B/serve.py"
cp "$HERE/bundle-docs/README.md" "$HERE/bundle-docs/PRESENTER.md" "$HERE/bundle-docs/NOTICE.md" "$B/"
cp "$HERE/bundle-docs/ELASTIC-LICENSE.txt" "$B/ELASTIC-LICENSE.txt"
# the recording's own figures into PRESENTER.md
python3 - "$B/capture" "$B/PRESENTER.md" "$B/README.md" <<'EOF'
import json, os, sys
cap = sys.argv[1]
st = json.load(open(f"{cap}/status.json")); rows = []
for k in sorted(st["steps"], key=int):
    s = st["steps"][k]; rows.append(f"| {k} | {s.get('title','')} | {s.get('seconds',0):.1f} s |")
m = json.load(open(f"{cap}/machine.json")) if os.path.exists(f"{cap}/machine.json") else {}
machine = m.get("gpu") or m.get("label") or "the recording machine"
step2 = f"{st['steps'].get('2', {}).get('seconds', 0):.0f}"
for path in sys.argv[2:]:
    txt = open(path).read()
    for k, v in (("<<TIMINGS>>", "\n".join(rows)), ("<<RUN_ID>>", st.get("run_id", "?")), ("<<MACHINE>>", machine), ("<<STEP2_SECONDS>>", step2)):
        txt = txt.replace(k, v)
    assert "<<" not in txt, f"unsubstituted placeholder in {path}"
    open(path, "w").write(txt)
EOF
if [ "${2:-}" != "--no-binaries" ]; then
  mkdir -p "$B/real/bin" "$B/real/root/ocsf" "$B/real/keys/dev" "$B/real/keys/trust"
  (cd "$ROOT/runtime" && for c in ulpf-runtime ulpf-committer ulpf-verify; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$B/real/bin/$c" ./cmd/$c; done)
  cp -r "$ROOT/contracts" "$B/real/root/contracts"; rm -rf "$B/real/root/contracts/golden/squid-native/pack.json.sig"
  cp -r "$ROOT/ocsf/pinned" "$B/real/root/ocsf/pinned"
  cp "$ROOT/keys/trust/"*.pub.json "$B/real/keys/trust/"
  cp "$ROOT/keys/dev/ulpf-committer-dev.json" "$B/real/keys/dev/"
  cp "$HERE/real/run-real.sh" "$B/real/run-real.sh"
  cp "$ROOT/demo/steps/5-sender.py" "$B/real/sender.py"
fi
find "$B" -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
rm -f "$OUT"; (cd "$W" && python3 -m zipfile -c "$OUT" demo-replay)     # stdlib zip: the laptop has no zip binary
echo "built $OUT: $(du -h "$OUT" | cut -f1), $(python3 -c 'import zipfile,sys; print(len(zipfile.ZipFile(sys.argv[1]).namelist()))' "$OUT") entries"
rm -rf "$W"
