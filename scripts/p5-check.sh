#!/usr/bin/env bash
# P5 exit checks: build the three binaries; golden vectors (regenerated and SIGNED); both contract suites;
# runtime suite (merkle, keys, checkpoint ordering/tamper/export, signature fail-closed, envelope
# precedence, UDP); learning suite; invariant 2; the two Docker tests — the privilege boundary
# (two containers, kernel immutable flag) and the external witness (fresh container verifies a bundle) —
# and the fixture demo through a SIGNED pack.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }   # local dev keys + signed golden pack (never committed)
echo "=== build (runtime, committer, verify)"
(cd runtime && [ -z "$(gofmt -l ./internal ./cmd ./contracts | tee /dev/stderr)" ] && go vet ./... && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime && go build -o bin/ulpf-committer ./cmd/ulpf-committer && go build -o bin/ulpf-verify ./cmd/ulpf-verify) || status=1
echo "=== golden vectors (regenerated, signed by the dev pack authority) + contract suites"
python contracts/golden/tools/build_vectors.py || status=1
(cd learning && python -m ulpf_contracts --golden | tail -1) || status=1
echo "=== runtime suite"
(cd runtime && go test -count=1 ./... 2>&1 | grep -vE "no test files") || status=1
echo "=== learning-plane suite"
(cd learning && python -m pytest -q 2>&1 | tail -2) || status=1
echo "=== signed pack loads; unsigned/untrusted refused"
runtime/bin/ulpf-runtime verify-pack --pack contracts/golden/squid-native | sed 's/^/  /' || status=1
runtime/bin/ulpf-runtime verify-pack --pack contracts/golden/squid-native --trust /nonexistent >/dev/null 2>&1 && { echo "  FAIL: untrusted authority accepted"; status=1; } || echo "  ok: untrusted authority refused (fail closed)"
echo "=== invariant 2 (build inspection)"
bash scripts/invariant2-check.sh | tail -2 || status=1
[ "${ULPF_SKIP_DOCKER:-0}" = "1" ] && echo "=== DOCKER STAGES SKIPPED (ULPF_SKIP_DOCKER=1): container/boundary/witness checks did NOT run"
if [ "${ULPF_SKIP_DOCKER:-0}" != "1" ]; then
  echo "=== privilege boundary (two containers, kernel immutable flag)"
  bash scripts/p5-boundary-test.sh 2>&1 | grep -E "FAIL|BOUNDARY:|VERIFY:|tampered leaf" | sed 's/^/  /'
  bash scripts/p5-boundary-test.sh >/dev/null 2>&1 || status=1
  echo "=== external witness (fresh container verifies an exported bundle)"
  bash scripts/p5-witness-test.sh 2>&1 | grep -E "FAIL|WITNESS:|VERIFY:" | sed 's/^/  /'
  bash scripts/p5-witness-test.sh >/dev/null 2>&1 || status=1
fi
echo "=== fixture demo through a signed pack (P3 path unchanged, now signed at promotion)"
S=/tmp/ulpf-p5-fixture; rm -rf "$S" /tmp/ulpf-p5-pack
(cd learning && python -m ulpf_learn onboard --provider fixture --samples ../contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session "$S" >/dev/null) || status=1
(cd learning && python -m ulpf_learn respond --session "$S" --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt" >/dev/null) || status=1
(cd learning && python -m ulpf_learn promote --session "$S" --out /tmp/ulpf-p5-pack --pack-id squid-native-emitted | head -1 | sed 's/^/  /') || status=1
ls /tmp/ulpf-p5-pack/pack.json.sig >/dev/null && echo "  ok: emitted pack carries pack.json.sig" || { echo "  FAIL: emitted pack unsigned"; status=1; }
runtime/bin/ulpf-runtime verify-pack --pack /tmp/ulpf-p5-pack | sed 's/^/  /' || status=1
grep -qE '"schema_version": "1\.[23]\.0"' /tmp/ulpf-p5-pack/pack.json && grep -q '"proposal"' /tmp/ulpf-p5-pack/pack.json && echo "  ok: pack is >=1.2.0 with proposal provenance" || { echo "  FAIL: pack lacks proposal provenance"; status=1; }
exit $status
