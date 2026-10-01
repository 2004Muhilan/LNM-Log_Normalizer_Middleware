#!/usr/bin/env bash
# ULPF CONSOLE container entrypoint (2026-10-01): the witness cosigns the log's checkpoint, the model is checked, then the
# System console starts — and through the scaler, its N runtime processes (one runtime container each, with a committer and
# a lake writer beside it).
set -euo pipefail
cd /ulpf
MODE="${ULPF_MODE:-generator}"
ADDR=$([ "$MODE" = devices ] && echo 0.0.0.0 || echo "${ULPF_INGEST_ADDR:-127.0.0.1}")
wait_http() { python - "$1" "${2:-60}" <<'EOF'
import sys, time, urllib.request
end = time.time() + float(sys.argv[2])
while time.time() < end:
    try:
        urllib.request.urlopen(sys.argv[1], timeout=2).read(); sys.exit(0)
    except Exception:
        time.sleep(0.5)
sys.exit(1)
EOF
}
export ULPF_TLOG_WITNESS="http://127.0.0.1:${ULPF_WITNESS_PORT:-8796}"
wait_http "$ULPF_TLOG_WITNESS/status" 60 || { echo "the witness did not answer at $ULPF_TLOG_WITNESS"; exit 1; }
runtime/bin/ulpf-tlog cosign > /state/app/witness-cosign.log 2>&1 || echo "the witness did not cosign the current checkpoint (packs still load: the log's signature and the inclusion proof are required)"
PROV=(--provider fixture)
if [ "${ULPF_PROVIDER:-model}" = model ]; then
  wait_http "${ULPF_MODEL_URL:-http://127.0.0.1:8081}/health" 20 || { echo "the model server does not answer at ${ULPF_MODEL_URL:-http://127.0.0.1:8081} (start it, or ULPF_PROVIDER=fixture)"; exit 1; }
  PROV=(--provider model --model-id "${ULPF_MODEL_ID:-qwen3.5-4b-q4_k_m}" --server "${ULPF_MODEL_URL:-http://127.0.0.1:8081}" --backend "${ULPF_MODEL_BACKEND:-llama.cpp}")
fi
export ULPF_OS_URL="http://127.0.0.1:${ULPF_OS_PORT:-9200}" ULPF_OSD_URL="http://127.0.0.1:${ULPF_OSD_PORT:-5601}"
exec python demo/apps/system.py --state /state/app --rt /ulpf/runtime/bin/ulpf-runtime --golden /ulpf/packs/squid-native --vendor-packs /ulpf/packs \
  --lake /state/app/lake --archive /state/app/evidence-archive --commit-dir /state/app/commit --evidence-grace "${ULPF_EVIDENCE_GRACE:-60s}" \
  --evidence-buffer-cap "${ULPF_EVIDENCE_BUFFER_CAP:-64MiB}" --processes "${ULPF_PROCESSES:-2}" --mode "$MODE" \
  --in-tcp "$ADDR:${ULPF_TCP_PORT:-6515}" --in-http "127.0.0.1:${ULPF_HTTP_PORT:-8516}" --listen "127.0.0.1:${ULPF_CONSOLE_PORT:-8765}" \
  --lake-port "${ULPF_LAKE_PORT:-8792}" --destinations deploy/destinations.json --python python \
  --scaler "http://127.0.0.1:${ULPF_SCALER_PORT:-8797}" "${PROV[@]}"
