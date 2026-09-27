#!/usr/bin/env bash
# P8 metrics: the coverage curve under the DECLARED replay mix (metrics/replay-mix.json; plan §5.3).
#   bash scripts/p8-coverage.sh            regenerate and COMPARE with docs/metrics/coverage.json (writes nothing)
#   bash scripts/p8-coverage.sh --write    regenerate docs/metrics/coverage.{json,svg} — a deliberate act; review the diff
# Onboards the nine families twice (all corpus lines; even-numbered lines only), replays a constructed stream per
# mix through the built runtime with the first k families' packs loaded, for every k. Needs the corpus cache;
# everything that contains corpus text stays outside the tree (tmpfs or /tmp).
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
[ -f corpus/cache/beats-cisco-asa/asa.log ] || { echo "p8-coverage needs the corpus cache (corpus/README.md)"; exit 1; }
(cd runtime && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime) || { echo "runtime build failed"; exit 1; }
# tmpfs: ~90 replays of 2,000 frames; with an fsync per event (invariant 3 before group commit) they took ten minutes on disk
W=${ULPF_COVERAGE_WORK:-$([ -d /dev/shm ] && echo /dev/shm/ulpf-coverage || echo /tmp/ulpf-coverage)}
if [ "${1:-}" = "--write" ]; then
  (cd learning && python tools/coverage_curve.py --work "$W" --json ../docs/metrics/coverage.json --svg ../docs/metrics/coverage.svg)
else
  (cd learning && python tools/coverage_curve.py --work "$W" --check ../docs/metrics/coverage.json) | tail -25
  exit ${PIPESTATUS[0]}
fi
