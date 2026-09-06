#!/usr/bin/env bash
# Does the model choice change what the operator sees? Run the Squid onboarding session against a live
# llama-server for one model and record: the evidence request (discriminator, fields it resolves), the
# certificates, and the session metrics after the single logformat response — so two models can be
# compared on "same request, same number of operator responses" rather than on agreement alone.
# Usage: p4-request-compare.sh <model-id> <server-url> <out-dir>   (server started separately, e.g. by
#        docker run ... ghcr.io/ggml-org/llama.cpp:server-cuda -m /models/<file> --port 8080 ...)
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
MODEL="${1:?model id}"; SERVER="${2:?server url}"; OUT="${3:?out dir}"
rm -rf "$OUT"; mkdir -p "$OUT"
S="$OUT/session"
t0=$(date +%s.%N)
(cd learning && python -m ulpf_learn onboard --provider model --model-id "$MODEL" --server "$SERVER" --mode whole --backend "cuda-laptop-1650" \
    --samples ../contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session "$S") > "$OUT/onboard.txt" 2>&1
t1=$(date +%s.%N)
(cd learning && python -m ulpf_learn certificates --session "$S") > "$OUT/certificates.txt" 2>&1
(cd learning && python -m ulpf_learn respond --session "$S" --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt") > "$OUT/respond.txt" 2>&1
(cd learning && python -m ulpf_learn promote --session "$S" --out "$OUT/pack" --pack-id squid-model-emitted) > "$OUT/promote.txt" 2>&1
runtime/bin/ulpf-runtime verify-pack --pack "$OUT/pack" > "$OUT/verify.txt" 2>&1
python - "$S/session.json" "$MODEL" "$t0" "$t1" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1])); model = sys.argv[2]; wall = float(sys.argv[4]) - float(sys.argv[3])
req = s.get("pending_request") or s.get("last_request") or {}
hist = s.get("request_history") or s.get("requests") or []
m = s.get("metrics", {})
certs = s.get("certificates") or []
if isinstance(certs, dict):
    certs = list(certs.values())
unresolved = sum(1 for c in certs if isinstance(c, dict) and c.get("status") == "unresolved")
print(json.dumps({"model": model, "onboard_wall_s": round(wall, 1), "metrics": m,
                  "request_discriminator": req.get("discriminator") if isinstance(req, dict) else None,
                  "request_resolves": req.get("resolves") if isinstance(req, dict) else None,
                  "certificates": len(certs), "unresolved": unresolved}, indent=1))
EOF
grep -E "^promotable|blocker|REQUEST|discriminator:|resolves" "$OUT/onboard.txt" | head -20
grep -E "^cert|UNRESOLVED" "$OUT/certificates.txt"
grep -E "^promotable|metrics" "$OUT/respond.txt" | tail -2
tail -1 "$OUT/verify.txt"
