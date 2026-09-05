#!/usr/bin/env bash
# Regenerate the P4 spike tables from spike/results (all machines): aggregate per model, the per-case
# slot matrices, and the per-configuration summary. Usage: p4-spike-report.sh [case ...]
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/.."
echo "## aggregate"; python learning/tools/spike.py aggregate
for c in "${@:-squid-native}"; do
  for m in whole per-slot; do echo; echo "## slots: $c / $m (gpu)"; python learning/tools/spike.py slots --case "$c" --mode "$m" --backend gpu; done
done
echo; echo "## schema-invalid outputs:"; grep -l '"schema_invalid": [1-9]' spike/results/*/*.json || echo "  none"
echo; echo "## errors:"; grep -l '"error":' spike/results/*/*__*.json 2>/dev/null | grep -v grammar__ | grep -v wholespec__ || echo "  none"
