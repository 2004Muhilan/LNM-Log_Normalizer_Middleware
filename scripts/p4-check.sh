#!/usr/bin/env bash
# P4 exit checks that need no model: runtime build, contract vectors, both suites (including the
# op-coverage matrix differential and the model-provider tests against a fake server), invariant 2 by
# build inspection, then the P3 scripted demo through the FIXTURE provider — proof the fallback is a
# switch, not a rewrite. The model path is exercised by scripts/p4-spike.sh (needs the image + weights)
# and, when ULPF_MODEL_SERVER points at a running llama-server, by the smoke block at the end.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }   # local dev keys + signed golden pack (never committed)
echo "=== runtime build"
(cd runtime && [ -z "$(gofmt -l ./internal ./cmd ./contracts | tee /dev/stderr)" ] && go vet ./... && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime) || status=1
echo "=== golden vectors + contract suites"
python contracts/golden/tools/build_vectors.py || status=1
(cd learning && python -m ulpf_contracts --golden | tail -1) || status=1
echo "=== runtime suite"
(cd runtime && go test -count=1 ./... 2>&1 | grep -vE "no test files") || status=1
echo "=== learning-plane suite (incl. op-coverage matrix, model provider with fake server)"
(cd learning && python -m pytest -q 2>&1 | tail -3) || status=1
echo "=== invariant 2 (build inspection)"
bash scripts/invariant2-check.sh | tail -4 || status=1
echo "=== fixture path, scripted (the P3 demo, unchanged — the fallback switch)"
S=/tmp/ulpf-p4-fixture; rm -rf "$S" /tmp/ulpf-p4-pack
(cd learning && python -m ulpf_learn onboard --provider fixture --samples ../contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session "$S" | head -3 | sed 's/^/  /') || status=1
(cd learning && python -m ulpf_learn respond --session "$S" --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt" | tail -1 | sed 's/^/  /') || status=1
(cd learning && python -m ulpf_learn promote --session "$S" --out /tmp/ulpf-p4-pack --pack-id squid-native-emitted | head -1 | sed 's/^/  /') || status=1
runtime/bin/ulpf-runtime verify-pack --pack /tmp/ulpf-p4-pack | sed 's/^/  /' || status=1
if [ -n "${ULPF_MODEL_SERVER:-}" ]; then
  echo "=== model path, scripted (llama-server at $ULPF_MODEL_SERVER, model ${ULPF_MODEL_ID:-qwen3.5-4b-q4_k_m})"
  M=/tmp/ulpf-p4-model; rm -rf "$M" /tmp/ulpf-p4-mpack
  (cd learning && python -m ulpf_learn onboard --provider model --model-id "${ULPF_MODEL_ID:-qwen3.5-4b-q4_k_m}" --server "$ULPF_MODEL_SERVER" --mode "${ULPF_MODE:-whole}" --backend "${ULPF_BACKEND:-unknown}" \
      --samples ../contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session "$M" | head -4 | sed 's/^/  /') || status=1
  (cd learning && python -m ulpf_learn certificates --session "$M" | grep -E "^cert|candidates" | sed 's/^/  /') || status=1
  (cd learning && python -m ulpf_learn respond --session "$M" --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt" | tail -1 | sed 's/^/  /') || status=1
  (cd learning && python -m ulpf_learn promote --session "$M" --out /tmp/ulpf-p4-mpack --pack-id squid-model-emitted | head -1 | sed 's/^/  /') || status=1
  runtime/bin/ulpf-runtime verify-pack --pack /tmp/ulpf-p4-mpack | sed 's/^/  /' || status=1
  python - <<'EOF'
import json; p=json.load(open("/tmp/ulpf-p4-mpack/pack.json")); print("  pack model_hash:", p["provenance"]["model_hash"])
EOF
fi
exit $status
