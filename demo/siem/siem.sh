#!/usr/bin/env bash
# The demo SIEM: OpenSearch + OpenSearch Dashboards (Apache 2.0), fully offline, on 127.0.0.1 only.
#
#   bash demo/siem/siem.sh start      fresh containers (any previous ones are removed: the demo starts empty), wait, set up
#   bash demo/siem/siem.sh setup      index template, dashboards, Security Analytics log type + rules + detector (idempotent)
#   bash demo/siem/siem.sh outage     docker stop the OpenSearch container (the egress-outage step; data is kept)
#   bash demo/siem/siem.sh recover    docker start it again and wait until it answers
#   bash demo/siem/siem.sh status     up/down and document counts
#   bash demo/siem/siem.sh stop       remove both containers
#   ULPF_SIEM_DASHBOARDS=0 ...        OpenSearch only (the no-Dashboards fallback: the System page still shows the SIEM's status and counts)
#
# DEMO ONLY: the OpenSearch security plugin is DISABLED (no TLS, no authentication) to save memory. This is not a
# production configuration and must not be presented as hardening; see docs/demo-runbook.md.
set -uo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
V="${ULPF_OPENSEARCH_VERSION:-2.19.2}"
OS_IMG="opensearchproject/opensearch:$V"; OSD_IMG="opensearchproject/opensearch-dashboards:$V"
NET=ulpf-siem; OS=ulpf-opensearch; OSD=ulpf-dashboards
OS_URL="http://127.0.0.1:${ULPF_OS_PORT:-9200}"; OSD_URL="http://127.0.0.1:${ULPF_OSD_PORT:-5601}"
HEAP="${ULPF_OS_HEAP:-512m}"
export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/ulpf-dockercfg}"; mkdir -p "$DOCKER_CONFIG"; [ -f "$DOCKER_CONFIG/config.json" ] || echo '{}' > "$DOCKER_CONFIG/config.json"

wait_os() { for _ in $(seq 1 ${1:-180}); do curl -s -m 2 "$OS_URL/_cluster/health" | grep -q '"status":"\(green\|yellow\)"' && return 0; sleep 1; done; echo "OpenSearch did not become ready at $OS_URL"; return 1; }
wait_osd() { for _ in $(seq 1 ${1:-240}); do curl -s -m 2 "$OSD_URL/api/status" | grep -q '"state":"green"' && return 0; sleep 1; done; echo "Dashboards did not become ready at $OSD_URL"; return 1; }

case "${1:-status}" in
  start)
    docker rm -f "$OSD" "$OS" > /dev/null 2>&1
    docker network inspect "$NET" > /dev/null 2>&1 || docker network create "$NET" > /dev/null
    docker run -d --name "$OS" --network "$NET" -p "127.0.0.1:${ULPF_OS_PORT:-9200}:9200" \
      -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true -e DISABLE_INSTALL_DEMO_CONFIG=true \
      -e "OPENSEARCH_JAVA_OPTS=-Xms$HEAP -Xmx$HEAP" -e bootstrap.memory_lock=false -e action.auto_create_index=true \
      "$OS_IMG" > /dev/null || exit 1
    if [ "${ULPF_SIEM_DASHBOARDS:-1}" = "1" ]; then
      docker run -d --name "$OSD" --network "$NET" -p "127.0.0.1:${ULPF_OSD_PORT:-5601}:5601" \
        -e "OPENSEARCH_HOSTS=[\"http://$OS:9200\"]" -e DISABLE_SECURITY_DASHBOARDS_PLUGIN=true \
        -e "NODE_OPTIONS=--max-old-space-size=${ULPF_OSD_NODE_MB:-512}" "$OSD_IMG" > /dev/null || exit 1
    fi
    wait_os || exit 1
    python3 "$HERE/setup.py" --os "$OS_URL" $([ "${ULPF_SIEM_DASHBOARDS:-1}" = "1" ] && echo --osd "$OSD_URL") || exit 1
    echo "SIEM up: OpenSearch $OS_URL$([ "${ULPF_SIEM_DASHBOARDS:-1}" = "1" ] && echo "  Dashboards $OSD_URL")  (security plugin DISABLED — demo only)"
    ;;
  setup) python3 "$HERE/setup.py" --os "$OS_URL" $(docker ps --format '{{.Names}}' | grep -qx "$OSD" && echo --osd "$OSD_URL") ;;
  outage)
    if [ "${ULPF_SIEM:-opensearch}" = "fake" ]; then pkill -f "demo/siem/[f]ake_bulk.py --listen 127.0.0.1:9200" && sleep 1 && echo "SIEM stand-in STOPPED (outage; its documents are kept)"; exit 0; fi
    docker stop -t 5 "$OS" > /dev/null && echo "OpenSearch STOPPED (outage): ULPF keeps ingesting and spooling for it; the lake keeps flowing" ;;
  recover)
    if [ "${ULPF_SIEM:-opensearch}" = "fake" ]; then setsid -f python3 "$HERE/fake_bulk.py" --listen 127.0.0.1:9200 --state "${ULPF_FAKE_SIEM_STATE:-/tmp/ulpf-fake-siem.json}" > /dev/null 2>&1; wait_os 20 && echo "SIEM stand-in back"; exit 0; fi
    docker start "$OS" > /dev/null && wait_os && echo "OpenSearch back: delivery resumes from its cursor" ;;
  stop) docker rm -f "$OSD" "$OS" > /dev/null 2>&1; echo "SIEM removed" ;;
  status)
    if curl -s -m 2 "$OS_URL/_cluster/health" > /dev/null; then
      echo "OpenSearch UP: $(curl -s -m 3 "$OS_URL/ulpf-ocsf-*/_count" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count"), "documents in ulpf-ocsf-*")' 2>/dev/null)"
    else echo "OpenSearch DOWN"; fi
    curl -s -m 2 "$OSD_URL/api/status" | grep -q '"state":"green"' && echo "Dashboards UP ($OSD_URL)" || echo "Dashboards not running"
    ;;
  *) echo "usage: siem.sh start|setup|outage|recover|status|stop"; exit 2 ;;
esac
