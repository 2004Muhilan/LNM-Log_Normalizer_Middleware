#!/usr/bin/env bash
# The demo, walked headless through the SAME HTTP APIs the pages' buttons call. For every format given: new format ->
# onboarding (by policy, prepared sheet) -> drift -> alert + partial heal -> the operator answers the withheld fields ->
# corrected pack. Then the destinations: both UP and current; the SIEM is stopped (outage) — the lake keeps flowing while
# the SIEM falls behind; the SIEM is started again — its backlog arrives, and the SIEM's document count equals the number
# of events ULPF parsed (no loss, no duplicate: _id = event_id); the lake's rows equal it too, in one schema. Finally an
# attack burst -> a Security Analytics finding -> "prove it": the original bytes, re-hashed, their Merkle proof verified,
# the same event in the lake.
#   bash demo/apps-check.sh                                   # fixture proposals, formats: positional json kv
#   ULPF_DEMO_PROVIDER=model APPS_SHAPES="kv leef json" bash demo/apps-check.sh
#   ULPF_SIEM=fake bash demo/apps-check.sh                    # no containers: the bulk stand-in, no findings step
source "$(dirname "$(readlink -f "$0")")/lib.sh"
cd "$ROOT"
export ULPF_DEMO_PROVIDER="${ULPF_DEMO_PROVIDER:-fixture}"
[ "$ULPF_DEMO_PROVIDER" = "model" ] && WAIT=300 || WAIT=90
bash demo/start-demo.sh > "$STATE/apps-check-start.log" 2>&1 || { tail -5 "$STATE/apps-check-start.log"; echo "apps-check: FAIL (start)"; exit 1; }
G=http://127.0.0.1:8780; S=http://127.0.0.1:8765; OS=http://127.0.0.1:9200
fail() { echo "apps-check: FAIL — $1"; [ "${KEEP:-0}" = "1" ] || bash demo/start-demo.sh stop > /dev/null; exit 1; }
gset() { curl -s -X POST $G/api/set -d "$1"; }
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
st() { curl -s $S/api/state | jq_ "$1"; }
dest() { st "next(e for e in d['egress'] if e['kind']=='$1')$2"; }
wait_job() { # index state seconds
  local s
  for _ in $(seq 1 $(( $3 * 2 ))); do
    s=$(st "d['jobs'][$1]['state'] if len(d['jobs'])>$1 else 'none'"); [ "$s" = "$2" ] && return 0; [ "$s" = "failed" ] && break; sleep 0.5
  done
  st "[x['text'] for x in d['jobs'][$1]['steps']] if len(d['jobs'])>$1 else 'no job'"; fail "job $1 is '$s', wanted '$2'"
}
until_true() { # seconds python-expression-over-state description
  for _ in $(seq 1 $(( $1 * 2 ))); do [ "$(st "$2")" = "True" ] && return 0; sleep 0.5; done
  fail "timed out after $1 s: $3"
}
n=0
for shape in ${APPS_SHAPES:-positional json kv}; do
  gset "{\"connector\":\"$([ $((n % 4)) -eq 0 ] && echo tcp || echo http)\",\"shape\":\"$shape\",\"drift\":false,\"running\":true}"
  wait_job $n done $WAIT; echo "$shape: onboarded — $(st "d['jobs'][$n]['steps'][-2]['text'][:90]")"; n=$((n+1))
  # healing is automatic only for drift BOUND to an onboarded source (same channel and host as events already parsed with its
  # pack): drift that arrives before one event of the new pack was parsed is refused and asked, correctly — so let it flow first
  until_true 30 "d['parse_success'] == 1.0" "$shape: events flowing under the new pack before the drift"
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
  until_true 20 "d['parse_success'] == 1.0" "$shape: parse success back to 100%"
done
until_true 30 "all(e['up'] and e['ahead_by'] <= 25 for e in d['egress'])" "both destinations UP and current"
echo "destinations: $(st "' | '.join(f\"{e['name']}: {'UP' if e['up'] else 'DOWN'}, ahead by {e['ahead_by']}, delivered {e['delivered']}, rejected {e['rejected']}\" for e in d['egress'])")"
# the outage: stop the SIEM; the lake keeps flowing
curl -s -X POST $S/api/siem -d '{"action":"outage"}'
until_true 60 "not next(e for e in d['egress'] if e['kind']=='siem')['up']" "the SIEM to go down"
sleep 15
SIEM_AHEAD=$(dest siem "['ahead_by']"); LAKE_AHEAD=$(dest lake "['ahead_by']")
echo "outage: SIEM DOWN, ahead by $SIEM_AHEAD ($(dest siem "['delivery']")); lake $(dest lake "['up']" | sed 's/True/UP/;s/False/DOWN/'), ahead by $LAKE_AHEAD"
[ "$SIEM_AHEAD" -ge 40 ] && [ "$LAKE_AHEAD" -le 25 ] || fail "during the outage the SIEM must fall behind (>= 40) while the lake stays current (<= 25)"
curl -s -X POST $S/api/siem -d '{"action":"recover"}'
until_true 120 "(lambda e: e['up'] and e['ahead_by'] <= 25)(next(e for e in d['egress'] if e['kind']=='siem'))" "the SIEM to come back and catch up"
echo "recovered: SIEM ahead by $(dest siem "['ahead_by']")"
if [ "${ULPF_SIEM:-opensearch}" != "fake" ]; then
  gset '{"burst":true}'
  echo "attack burst sent; waiting for a Security Analytics finding (the detector runs every minute)…"
  for _ in $(seq 1 90); do F=$(curl -s $S/api/findings | jq_ "d[0]['event_ids'][0] if d else ''"); [ -n "$F" ] && break; sleep 2; done
  [ -n "$F" ] || fail "no Security Analytics finding within 3 minutes"
  echo "finding: $(curl -s $S/api/findings | jq_ "d[0]['rule']") naming $F"
  sleep 12   # the lake writer rotates every 10 s: the event is in a Parquet file by now
  curl -s -X POST $S/api/prove -d "{\"event_id\":\"$F\"}"
  for _ in $(seq 1 40); do T=$(curl -s "$S/api/trace?id=$F"); [ "$T" != "null" ] && break; sleep 1; done
  echo "$T" | jq_ "'\n'.join(('  ✓ ' if s['ok'] else '  ✗ ') + s['step'] + ': ' + s['detail'][:150] for s in d['steps'])"
  [ "$(echo "$T" | jq_ "d['ok']")" = "True" ] || fail "the round trip SIEM finding -> evidence did not complete"
fi
if [ "${ULPF_SIEM:-opensearch}" != "fake" ] && [ "$(st "d['runtime']['relay_available']")" = "True" ]; then
  # unified visibility (requirement f): every source in one SIEM, one query across devices
  agg() { curl -s "$OS/ulpf-ocsf-*/_search" -H 'Content-Type: application/json' -d "{\"size\":0,\"query\":$1,\"aggs\":{\"v\":{\"terms\":{\"field\":\"metadata.product.vendor_name\",\"size\":10}}}}" | jq_ "' | '.join(sorted(b['key'] for b in d['aggregations']['v']['buckets']))"; }
  for _ in $(seq 1 60); do V=$(agg '{"match_all":{}}'); echo "$V" | grep -q Squid && echo "$V" | grep -q Fortinet && echo "$V" | grep -q "Palo Alto" && echo "$V" | grep -q Cisco && break; sleep 1; done
  echo "unified visibility: vendors in the SIEM: $V"
  for want in Cisco "Palo Alto Networks" Fortinet Squid flowtap; do echo "$V" | grep -q "$want" || fail "the SIEM does not show $want"; done
  X=$(agg '{"bool":{"filter":[{"term":{"action_id":2}},{"term":{"src_endpoint.ip":"10.0.0.0/8"}}]}}')
  echo "cross-vendor query 'denied connections from 10.0.0.0/8, every device': $X"
  [ "$(echo "$X" | tr '|' '\n' | grep -c .)" -ge 2 ] || fail "the cross-vendor query must return more than one device"
  # one attacker, two devices: 10.10.10.10 is denied by the FortiGate in the capture and by the generator (every 15th line)
  for _ in $(seq 1 60); do O=$(agg '{"bool":{"filter":[{"term":{"action_id":2}},{"term":{"src_endpoint.ip":"10.10.10.10"}}]}}'); echo "$O" | grep -q Fortinet && echo "$O" | grep -q flowtap && break; sleep 1; done
  echo "one-source query 'denied connections from 10.10.10.10': $O"
  echo "$O" | grep -q Fortinet && echo "$O" | grep -q flowtap || fail "the one-source query must show the FortiGate and the generator logging the same attacker"
  if curl -s -m 2 http://127.0.0.1:5601/api/status > /dev/null; then
    for sid in ulpf-denied-one-source ulpf-denied-internal; do
      [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:5601/api/saved_objects/search/$sid")" = 200 ] || fail "saved search $sid missing in Dashboards"
    done
    echo "saved searches in Dashboards: ulpf-denied-one-source, ulpf-denied-internal"
    # the dashboard's time axis is _lineage.ingest_time; Dashboards drops subfields of underscore objects from its field list,
    # and a panel on a field missing from the pattern fails ("Could not locate that index-pattern-field") — seen once, guarded here
    curl -s http://127.0.0.1:5601/api/saved_objects/index-pattern/ulpf-ocsf | jq_ "'ok' if any(f['name'] == '_lineage.ingest_time' and f['type'] == 'date' for f in json.loads(d['attributes']['fields'])) else ''" | grep -q ok \
      || fail "the index pattern lacks _lineage.ingest_time: the denies panel cannot render"
  fi
  curl -s -X POST $S/api/policy -d '{"vendor_relay":false}'   # the accounting below needs a stream that has stopped
fi
gset '{"running":false}'; sleep 8
USABLE=$(st "d['counts']['usable']")
curl -s -m 5 $OS/ulpf-ocsf-*/_refresh > /dev/null
DOCS=$(curl -s "$OS/ulpf-ocsf-*/_count" | jq_ "d['count']")
curl -s -m 30 http://127.0.0.1:8792/flush > /dev/null
LAKE=$(python -c "import duckdb,glob; fs=glob.glob('$STATE/app/lake/ext/*/*/*/*/*.parquet'); print(duckdb.connect().execute(f'SELECT count(*), count(DISTINCT event_id) FROM read_parquet({fs!r})').fetchone())")
REJ=$(st "sum(e['rejected'] for e in d['egress'])")
echo "accounting: ULPF parsed $USABLE events; SIEM holds $DOCS documents; lake (rows, distinct event ids) $LAKE; rejected $REJ"
[ "$DOCS" = "$USABLE" ] || fail "the SIEM holds $DOCS documents for $USABLE parsed events (lost, or stored twice)"
[ "$LAKE" = "($USABLE, $USABLE)" ] || fail "the lake holds $LAKE for $USABLE parsed events"
[ "$REJ" = "0" ] || fail "$REJ event(s) rejected by a destination"
[ "${KEEP:-0}" = "1" ] || bash demo/start-demo.sh stop > /dev/null
echo "apps-check: PASS ($ULPF_DEMO_PROVIDER, SIEM ${ULPF_SIEM:-opensearch})"
