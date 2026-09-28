#!/usr/bin/env bash
# The capacity batch (docs/throughput.md, "What ULPF itself can handle"): A (one process, 10 min) then B (the scaling
# matrix, 3 min x 3 runs per cell). C runs separately: it needs OpenSearch and its layout is chosen from B.
#   ULPF_BENCH_BIN=~/ulpf-capacity/bin bash scripts/bench/capacity-batch.sh [A] [B]
set -uo pipefail
cd "$(dirname "$0")/../.."
: "${ULPF_BENCH_BIN:?a frozen copy of runtime/bin (a rebuild mid-batch must not change what is measured)}"
export ULPF_BENCH_BIN
LIMITS=(--floor-gb 100 --batch-growth-gb 20)
[ $# -gt 0 ] || set -- A B
for s in "$@"; do
  case "$s" in
    A) python3 scripts/bench/capacity.py run --suite A --procs 1 --senders 32 --duration 600 --reps 1 --budget-gb 10 "${LIMITS[@]}" || exit 1 ;;
    B) python3 scripts/bench/capacity.py run --suite B --procs 1,2,4,6 --senders 8,16,32 --duration 180 --reps 3 --budget-gb 14 "${LIMITS[@]}" || exit 1 ;;
  esac
done
echo "BATCH DONE"
