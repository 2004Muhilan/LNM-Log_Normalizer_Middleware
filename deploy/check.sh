#!/usr/bin/env bash
# The container deployment, checked end to end (2026-10-01) — the gate's lane C. On a Linux host with Docker Engine.
# Its own installation (project ulpf-check, its own volumes and ports), so it runs beside a demo or the other gate lanes:
# generator mode, fixture proposals, no Dashboards. Then deploy/check.py drives it (see there), and everything is purged.
#
#   bash deploy/check.sh            (build first: bash deploy/ulpf.sh build)
set -uo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
export ULPF_PROJECT=ulpf-check ULPF_PROVIDER=fixture ULPF_DASHBOARDS=0 ULPF_PROCESSES=2 ULPF_EVIDENCE_GRACE=30s
export ULPF_TCP_PORT=16515 ULPF_HTTP_PORT=18516 ULPF_CONSOLE_PORT=18765 ULPF_LAKE_PORT=18792 ULPF_WITNESS_PORT=18796 ULPF_SCALER_PORT=18797 \
       ULPF_OS_PORT=19200 ULPF_GENERATOR_PORT=18780
T0=$(date +%s)
fail=0
echo "== images: no private key in any layer"
for img in ulpf-app ulpf-runtime ulpf-committer ulpf-witness ulpf-scaler; do
  docker image inspect "$img:latest" > /dev/null || { echo "image $img missing: bash deploy/ulpf.sh build"; exit 1; }
done
leak=$(docker run --rm --entrypoint sh ulpf-app:latest -c 'find / -xdev \( -name "*-dev.json" -o -name "ulpf-pack-release.json" \) -path "*key*" 2>/dev/null; grep -rl "private_key" /ulpf --include=*.json 2>/dev/null | head -3')
[ -z "$leak" ] && echo "  none (app image searched for key files and private_key fields)" || { echo "  PRIVATE KEY MATERIAL IN THE IMAGE: $leak"; fail=1; }
echo "== up"
bash "$HERE/ulpf.sh" up generator || { echo "up failed"; docker compose -f "$HERE/compose.yaml" -p ulpf-check logs --tail 40; bash "$HERE/ulpf.sh" purge > /dev/null 2>&1; exit 1; }
echo "== the containers of one runtime process (the scaler's template)"
for part in runtime committer lake; do
  docker inspect -f "  $part: {{.Name}} user={{.Config.User}} caps={{.HostConfig.CapAdd}} network={{.HostConfig.NetworkMode}} image={{.Config.Image}}" "ulpf-check-$part-1" || fail=1
done
echo "== check"
docker run --rm --network host -v ulpf-check-state:/state:ro ulpf-app:latest python deploy/check.py \
  --console "http://127.0.0.1:$ULPF_CONSOLE_PORT" --generator "http://127.0.0.1:$ULPF_GENERATOR_PORT" --os "http://127.0.0.1:$ULPF_OS_PORT" || fail=1
if [ $fail = 1 ]; then
  echo "== console and generator logs (tail)"; docker compose -f "$HERE/compose.yaml" -p ulpf-check --profile generator logs --tail 60 console generator
fi
echo "== down and purge"
bash "$HERE/ulpf.sh" purge > /dev/null 2>&1
left=$(docker ps -aq --filter label=ulpf.scaler=ulpf-check; docker volume ls -q --filter name=ulpf-check-)
[ -z "$left" ] || { echo "left behind: $left"; fail=1; }
echo "CONTAINER LANE: $([ $fail = 0 ] && echo PASS || echo FAIL) in $(( $(date +%s) - T0 )) s"
exit $fail
