#!/usr/bin/env bash
# ULPF — one command for the container deployment (2026-10-01). On a Linux host with Docker Engine and Compose v2.
#
#   bash deploy/ulpf.sh build                 build every image from this repository (needs packs/release: scripts/release-packs.sh)
#   bash deploy/ulpf.sh up [generator|devices] start, from a FRESH state (the demo); KEEP=1 keeps the state (a deployment)
#   bash deploy/ulpf.sh scale add|remove      one runtime process more or less (the System page has the same two buttons)
#   bash deploy/ulpf.sh status                the containers, the runtime processes, the console's view of them
#   bash deploy/ulpf.sh down                  stop everything (state, keys and the transparency log are kept, in volumes)
#   bash deploy/ulpf.sh purge                 down, then delete every volume — keys and the transparency log included
#   bash deploy/ulpf.sh export                images + compose + this script -> deploy/dist/ulpf-<version>.tar.gz (offline install)
#   bash deploy/ulpf.sh import FILE.tar.gz    load an exported bundle on another machine (no network, no build)
#
#   generator   the demo's log generator sends; auto-onboarding on; the SIEM and the lake connected from the start
#   devices     the real devices (demo/devices): run the device pre-flight first; the SIEM is set up, then STOPPED, and the
#               lake writers are not started — the presenter connects both on stage. Needs the lab agent (demo/devices/agent)
#
# Settings: deploy/.env (copy deploy/env.example), or the environment: ULPF_PROCESSES (default 2), ULPF_PROVIDER=model|fixture,
# ULPF_MODEL_URL, ULPF_DASHBOARDS=0 (no Dashboards: less memory), the ports, ULPF_PROJECT (a second, separate installation).
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; ROOT="$(dirname "$HERE")"
[ -f "$HERE/.env" ] && { set -a; source "$HERE/.env"; set +a; }
P="${ULPF_PROJECT:-ulpf}" VER="${ULPF_VERSION:-latest}"
export ULPF_PROJECT="$P"
DC=(docker compose -f "$HERE/compose.yaml" --project-directory "$HERE")
CONSOLE="http://127.0.0.1:${ULPF_CONSOLE_PORT:-8765}"
say() { echo "[ulpf $(date +%H:%M:%S)] $*"; }
units_rm() { local ids; ids=$(docker ps -aq --filter "label=ulpf.scaler=$P"); [ -z "$ids" ] || docker rm -f $ids > /dev/null; }
wait_url() { for _ in $(seq 1 "${2:-120}"); do curl -sf -m 2 "$1" > /dev/null && return 0; sleep 1; done; return 1; }
profiles() { local p=(); [ "${ULPF_DASHBOARDS:-1}" = 1 ] && p+=(--profile dashboards); [ "$1" = generator ] && p+=(--profile generator); echo "${p[@]}"; }

case "${1:-}" in
  build)
    [ -f "$ROOT/packs/release/fortigate/pack.json.sig" ] || { echo "packs/release missing: bash scripts/release-packs.sh (on the machine with the release key)"; exit 1; }
    cd "$ROOT"
    export DOCKER_BUILDKIT=1
    for t in runtime committer witness binaries; do say "build ulpf-$t"; docker build -q -f runtime/Dockerfile --target "$t" -t "ulpf-$t:$VER" . > /dev/null; done
    docker tag "ulpf-binaries:$VER" ulpf-binaries:latest
    for t in app scaler; do say "build ulpf-$t"; docker build -q -f deploy/Dockerfile --target "$t" -t "ulpf-$t:$VER" . > /dev/null; done
    docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E "^ulpf-(runtime|committer|witness|app|scaler):$VER " | sed 's/^/  /'
    ;;
  up)
    MODE="${2:-generator}"; case "$MODE" in generator|devices) ;; *) echo "up generator|devices"; exit 2 ;; esac
    export ULPF_MODE="$MODE"
    [ "$MODE" = devices ] && export ULPF_PROVIDER="${ULPF_PROVIDER:-model}"
    say "stopping what runs (project $P)"
    "${DC[@]}" --profile generator --profile dashboards stop console > /dev/null 2>&1 || true
    units_rm
    "${DC[@]}" --profile generator --profile dashboards down --remove-orphans > /dev/null 2>&1 || true
    if [ "${KEEP:-0}" != 1 ]; then export ULPF_FRESH=1; docker volume rm "$P-siem" > /dev/null 2>&1 || true; fi
    say "starting: $MODE, ${ULPF_PROCESSES:-2} runtime processes, provider ${ULPF_PROVIDER:-model}$([ "${KEEP:-0}" = 1 ] && echo ", state kept" || echo ", fresh state")"
    "${DC[@]}" $(profiles "$MODE") up -d
    wait_url "$CONSOLE/api/state" 300 || { say "the console did not come up:"; "${DC[@]}" logs --tail 30 init siem-setup console; exit 1; }
    [ "$MODE" = generator ] && { wait_url "http://127.0.0.1:${ULPF_GENERATOR_PORT:-8780}/" 90 || { say "the generator did not come up:"; "${DC[@]}" --profile generator logs --tail 20 generator; exit 1; }; }
    if [ "$MODE" = devices ]; then
      docker stop -t 5 "$P-opensearch" > /dev/null && say "devices mode: OpenSearch is set up and STOPPED — connect it on stage (System page)"
    fi
    say "up. System $CONSOLE/  ·  Data lake $CONSOLE/lake  ·  SIEM http://127.0.0.1:${ULPF_OSD_PORT:-5601}/$([ "$MODE" = generator ] && echo "  ·  Generator http://127.0.0.1:${ULPF_GENERATOR_PORT:-8780}/")"
    say "the OpenSearch security plugin is DISABLED (demo only)"
    ;;
  scale)
    case "${2:-}" in add|remove) ;; *) echo "scale add|remove"; exit 2 ;; esac
    curl -sf -m 10 -X POST -d "{\"action\":\"$2\"}" "$CONSOLE/api/scale" || { curl -s -m 10 -X POST -d "{\"action\":\"$2\"}" "$CONSOLE/api/scale"; echo; exit 1; }
    say "scale $2 requested — the System page shows its progress"
    ;;
  status)
    "${DC[@]}" --profile generator --profile dashboards ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
    docker ps -a --filter "label=ulpf.scaler=$P" --format 'table {{.Names}}\t{{.State}}\t{{.Status}}'
    curl -sf -m 5 "$CONSOLE/api/state" | python3 -c 'import json,sys; s=json.load(sys.stdin); print("processes:", ", ".join(f"{p[\"process\"]} {p.get(\"state\")}" for p in s["processes"]), "| scaling:", s.get("scaling", {}).get("limit"))' 2>/dev/null || true
    ;;
  down)
    "${DC[@]}" --profile generator --profile dashboards stop -t 90 console > /dev/null 2>&1 || true   # the console drains its runtime processes
    units_rm
    "${DC[@]}" --profile generator --profile dashboards down --remove-orphans
    ;;
  purge)
    "$0" down || true
    # sealed evidence carries the kernel's immutable flag: clear it before the volume can be deleted
    docker run --rm --user 0 --cap-add LINUX_IMMUTABLE --network none -v "$P-state:/state" "ulpf-app:$VER" sh -c 'chattr -R -i /state 2>/dev/null; true'
    for v in state packs keys trust tlog siem; do docker volume rm "$P-$v" > /dev/null 2>&1 && echo "  removed volume $P-$v"; done
    ;;
  export)
    mkdir -p "$HERE/dist"; d=$(mktemp -d)
    imgs=("ulpf-runtime:$VER" "ulpf-committer:$VER" "ulpf-witness:$VER" "ulpf-app:$VER" "ulpf-scaler:$VER" "opensearchproject/opensearch:${ULPF_OPENSEARCH_VERSION:-2.19.2}")
    [ "${ULPF_DASHBOARDS:-1}" = 1 ] && imgs+=("opensearchproject/opensearch-dashboards:${ULPF_OPENSEARCH_VERSION:-2.19.2}")
    say "saving ${#imgs[@]} images"
    docker save -o "$d/images.tar" "${imgs[@]}"
    mkdir -p "$d/deploy"; cp "$HERE/compose.yaml" "$HERE/ulpf.sh" "$HERE/env.example" "$d/deploy/"
    tar -C "$d" -czf "$HERE/dist/ulpf-$VER.tar.gz" images.tar deploy; rm -rf "$d"
    say "deploy/dist/ulpf-$VER.tar.gz ($(du -h "$HERE/dist/ulpf-$VER.tar.gz" | cut -f1)) — on the target: tar xzf it, bash deploy/ulpf.sh import ulpf-$VER.tar.gz"
    ;;
  import)
    f="${2:?import FILE.tar.gz}"; d=$(mktemp -d); tar -C "$d" -xzf "$f" images.tar; docker load -i "$d/images.tar"; rm -rf "$d"
    say "images loaded: bash deploy/ulpf.sh up"
    ;;
  *) sed -n 2,20p "$0"; exit 2 ;;
esac
