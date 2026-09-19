#!/usr/bin/env bash
# P6 exit checks: build; golden vectors (regenerated, signed; the squid pack is now 1.3.0); both contract suites;
# runtime suites (route DAG: mixed stream, anchor-defeating quarantine, K cap, static no-try-all; pipeline mixed
# stream + ML; frame PRI-only; pack anchor cross-check); learning suite (anchor admission, envelope/surface twins,
# vendor-schema applier, propagation, recorded provider, ML draft contract); invariant 2; then, when the corpus
# cache is present, the four-vendor build: onboarding through the P3/P4 path, source packs, the mixed live stream
# with the candidate-set distribution, ML emission, discovery ranking, agreement.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }
echo "=== build (runtime, committer, verify)"
(cd runtime && [ -z "$(gofmt -l ./internal ./cmd ./contracts | tee /dev/stderr)" ] && go vet ./... && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime && go build -o bin/ulpf-committer ./cmd/ulpf-committer && go build -o bin/ulpf-verify ./cmd/ulpf-verify) || status=1
echo "=== golden vectors (regenerated, signed) + contract suites"
python contracts/golden/tools/build_vectors.py || status=1
(cd learning && python -m ulpf_contracts --golden | tail -1) || status=1
echo "=== runtime suite"
(cd runtime && go test -count=1 ./... 2>&1 | grep -vE "no test files") || status=1
echo "=== learning-plane suite"
(cd learning && python -m pytest -q 2>&1 | tail -2) || status=1
echo "=== invariant 2 (build inspection)"
bash scripts/invariant2-check.sh | tail -2 || status=1
echo "=== invariant 6 (static): the router never parses; the pipeline parses once, after routing"
(cd runtime && go test -count=1 ./internal/route/ -run TestStaticNoTryAllPath -v 2>&1 | grep -E "^(--- |ok|FAIL)") || status=1
if [ -f corpus/cache/beats-cisco-asa/asa.log ]; then
  echo "=== four-vendor build, mixed stream, propagation, discovery, agreement (corpus cache present)"
  bash scripts/p6-build-packs.sh 2>&1 | grep -E "PASS|FAIL|stats:|candidate-set|quarantined \[|propagated|11-slot metrics|records,|^p6-build" | sed 's/^/  /'
  bash scripts/p6-build-packs.sh >/dev/null 2>&1 || status=1
else
  echo "=== corpus cache absent: vendor build skipped (fetch per corpus/README.md)"
fi
exit $status
