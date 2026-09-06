#!/usr/bin/env bash
# P3 boundary (contracts 1.1.0): rebuild pinned tables (category_uid), build runtime, regenerate
# vectors, run both contract suites and the runtime suite.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
echo "=== pinned tables (adds category_uid) + cross-check"
python ocsf/tools/build_pinned.py | sed 's/^/  /' && python ocsf/tools/crosscheck_source.py | tail -1 || status=1
echo "=== runtime build"
(cd runtime && gofmt -w ./internal ./cmd ./contracts && go vet ./... && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime) || status=1
echo "=== golden vectors + both suites"
python contracts/golden/tools/build_vectors.py || status=1
(cd learning && python -m ulpf_contracts --golden | tail -1) || status=1
(cd learning && python -m pytest -q 2>&1 | tail -1) || status=1
echo "=== runtime suite"
(cd runtime && go test ./... 2>&1 | grep -vE "no test files") || status=1
echo "=== pipeline stats on the golden samples"
runtime/bin/ulpf-runtime run --pack contracts/golden/squid-native --input contracts/golden/squid-native/samples/access.log --evidence /tmp/ulpf-bc-ev --out /dev/null 2>&1 | tail -1
rm -rf /tmp/ulpf-bc-ev
exit $status
