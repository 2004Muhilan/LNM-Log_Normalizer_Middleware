#!/usr/bin/env bash
# The three-app demo, walked headless through the SAME HTTP APIs the pages' buttons call. For every format given:
# new format -> onboarding (by policy, prepared sheet) -> drift -> alert + partial heal -> the operator answers the withheld
# fields -> corrected pack. Then the database: disconnect (rows stop), reconnect (catch-up from the cursor), switch connector.
#   bash demo/apps-check.sh                         # fixture proposals, formats: positional json kv
#   ULPF_DEMO_PROVIDER=model APPS_SHAPES="xml leef csv" bash demo/apps-check.sh
source "$(dirname "$(readlink -f "$0")")/lib.sh"
cd "$ROOT"
export ULPF_DEMO_PROVIDER="${ULPF_DEMO_PROVIDER:-fixture}"
[ "$ULPF_DEMO_PROVIDER" = "model" ] && WAIT=300 || WAIT=90
bash demo/start-demo.sh > /dev/null || { echo "apps-check: FAIL (start)"; exit 1; }
G=http://127.0.0.1:8780; S=http://127.0.0.1:8765; D=http://127.0.0.1:8790
fail() { echo "apps-check: FAIL — $1"; bash demo/start-demo.sh stop > /dev/null; exit 1; }
gset() { curl -s -X POST $G/api/set -d "$1"; }
dset() { curl -s -X POST $D/api/set -d "{\"connector\":\"$1\"}"; }
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
st() { curl -s $S/api/state | jq_ "$1"; }
db() { curl -s $D/api/state | jq_ "$1"; }
wait_job() { # index state seconds
  local s
  for _ in $(seq 1 $(( $3 * 2 ))); do
    s=$(st "d['jobs'][$1]['state'] if len(d['jobs'])>$1 else 'none'"); [ "$s" = "$2" ] && return 0; [ "$s" = "failed" ] && break; sleep 0.5
  done
  st "[x['text'] for x in d['jobs'][$1]['steps']] if len(d['jobs'])>$1 else 'no job'"; fail "job $1 is '$s', wanted '$2'"
}
n=0
dset http
for shape in ${APPS_SHAPES:-positional json kv}; do
  gset "{\"connector\":\"$([ $((n % 4)) -eq 0 ] && echo tcp || echo http)\",\"shape\":\"$shape\",\"drift\":false,\"running\":true}"
  wait_job $n done $WAIT; echo "$shape: onboarded — $(st "d['jobs'][$n]['steps'][-2]['text'][:90]")"; n=$((n+1))
  gset '{"drift":true}'
  wait_job $n asking $WAIT
  jid=$(st "d['jobs'][$n]['id']")
  [ "$(st "len(d['jobs'][$n]['alert']['propagated'])")" = "8" ] || fail "$shape: the heal must carry over 8 fields"
  for f in $(st "' '.join(f['field'] for f in d['jobs'][$n]['fields'] if not f['evidenced'])"); do
    case "$f" in pos_3|proto) a=connection_info.protocol_num;; *) a=src_endpoint.zone;; esac
    curl -s -X POST $S/api/answer -d "{\"job\":\"$jid\",\"field\":\"$f\",\"attribute\":\"$a\"}"
  done
  sleep 1; curl -s -X POST $S/api/promote -d "{\"job\":\"$jid\"}"
  wait_job $n done 60; echo "$shape: drift healed — $(st "d['alerts'][-1]['outcome'][:150]")"; n=$((n+1))
  for _ in $(seq 1 40); do [ "$(st "d['parse_success']")" = "1.0" ] && break; sleep 0.5; done   # the window is the last 40 events: it needs ~7 s of clean traffic
  [ "$(st "d['parse_success']")" = "1.0" ] || fail "$shape: parse success did not return to 100%"
done
dset none; sleep 4; r0=$(db "d['rows']"); sleep 3; r1=$(db "d['rows']"); [ "$r0" = "$r1" ] || fail "rows moved while disconnected"
dset http; sleep 6; r2=$(db "d['rows']"); [ "$r2" -gt "$r1" ] || fail "no catch-up after reconnecting"
dset tcp; sleep 8; dset file; sleep 6
gset '{"running":false}'; sleep 3
rows=$(db "d['rows']"); usable=$(st "d['counts']['usable']")
echo "database: disconnected $r0 = $r1 rows, reconnected $r2, after switching connectors $rows rows for $usable parsed events; by connector $(db "d['by_via']"), duplicates ignored $(db "d['duplicates_ignored']")"
[ "$rows" = "$usable" ] || fail "the database holds $rows rows, ULPF parsed $usable"
bash demo/start-demo.sh stop > /dev/null
echo "apps-check: PASS ($ULPF_DEMO_PROVIDER)"
