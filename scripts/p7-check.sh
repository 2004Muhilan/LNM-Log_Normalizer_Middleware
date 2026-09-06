#!/usr/bin/env bash
# P7 exit checks: build; golden vectors (regenerated, signed; lineage 1.3.0); both contract suites; runtime
# suites incl. the P7 packages (frame: octet counting, TCP, HTTP, pull, multiline, de-batch, chain/CEF;
# gap; pipeline: relay chain, forwarded CEF routing, de-batch evidence, gap leaves committed/exported/verified,
# TCP partials); learning suite; invariant 2; invariant 6 static; then INVARIANT 7 UNDER LOAD sized to this
# machine (ULPF_LOAD_* below — set from the demo laptop: 12 threads, ~6 GB free under a 7.7 GB WSL cap), and
# the canned P7 demos (scripts/p7-demo.sh): octet-counted capture over TCP, a batched JSON drop, a silenced
# source producing a signed gap record the verifier displays and exports.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
bash scripts/keys-bootstrap.sh >/dev/null || { echo "key bootstrap failed"; exit 1; }
echo "=== build (runtime, committer, verify)"
(cd runtime && gofmt -l ./internal ./cmd ./contracts && go vet ./... && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime && go build -o bin/ulpf-committer ./cmd/ulpf-committer && go build -o bin/ulpf-verify ./cmd/ulpf-verify) || status=1
echo "=== golden vectors (regenerated, signed; normalized-event 1.3.0) + contract suites"
python contracts/golden/tools/build_vectors.py || status=1
(cd learning && python -m ulpf_contracts --golden | tail -1) || status=1
echo "=== runtime suite"
(cd runtime && go test ./... 2>&1 | grep -vE "no test files") || status=1
echo "=== learning-plane suite"
(cd learning && python -m pytest -q 2>&1 | tail -2) || status=1
echo "=== invariant 2 (build inspection)"
bash scripts/invariant2-check.sh | tail -2 || status=1
echo "=== invariant 6 (static): the router never parses; the pipeline parses once, after routing"
(cd runtime && go test ./internal/route/ -run TestStaticNoTryAllPath -v 2>&1 | grep -E "^(--- |ok|FAIL)") || status=1
echo "=== invariant 7 under load — sized to this machine: $(nproc) threads, $(free -m | awk '/Mem:/{print $7}') MB available of $(free -m | awk '/Mem:/{print $2}') MB"
# Sizes: a flood of 3000 connections against a 64-connection server (the laptop's ephemeral-port and fd
# limits allow it comfortably); a 32 MiB single message against a 64 KiB frame cap; 400 idle peers. The
# heap bound the tests assert is MaxConns x (64 KiB + cap) + 24 MiB = 32 MiB for the flood, and half
# the message size for the oversized case — both far below the ~6 GB this machine has free.
(cd runtime && ULPF_LOAD_CONNS="${ULPF_LOAD_CONNS:-3000}" ULPF_LOAD_MB="${ULPF_LOAD_MB:-32}" ULPF_LOAD_IDLE="${ULPF_LOAD_IDLE:-400}" \
   go test ./internal/frame/ -run 'TestTCPConnectionFloodHoldsMemoryCap|TestTCPOversizedMessageIsBoundedAndRetained|TestTCPIdleConnectionsAreClosedAndPartialsRetained' -v -count=1 2>&1 \
   | grep -E "^(--- |ok|FAIL|\s+tcp_test.go)" | sed 's/^/  /') || status=1
echo "=== envelope ambiguity, recursive unwrap, forwarded CEF, de-batching, gap leaves (named tests, verbose)"
(cd runtime && go test ./internal/frame/ ./internal/pipeline/ -run 'TestEnvelopeAmbiguityResolvesByPrecedence|TestUnwrapChainRelayed|TestUnwrapChainDepthBound|TestForwardedCEFRoutesToItsPack|TestRelayChainIsUnwrappedAndRecorded|TestDebatchProducesIndependentlyHashedRecords|TestGapRecordsAreCommittedLeaves|TestSequenceGapFromStructuredData|TestTCPPartialFrameBecomesEvidenceAndGapRecord' -v -count=1 2>&1 | grep -E "^--- " | sed 's/^/  /') || status=1
echo "=== canned P7 demos (scripts/p7-demo.sh)"
DEMO=$(mktemp); bash scripts/p7-demo.sh > "$DEMO" 2>&1; demo_rc=$?   # once: the demo binds ports and measures silence, so it is not re-run silently
grep -E "PASS|FAIL|GAP |GAPS:|VERIFY:|WITNESS|frames|stats:|reconstruct|batch" "$DEMO" | sed 's/^/  /'; rm -f "$DEMO"
[ $demo_rc -eq 0 ] || status=1
echo "p7-check: $([ $status = 0 ] && echo PASS || echo FAIL)"
exit $status
