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
  [ "$(echo "$T" | jq_ "next((s['ok'] for s in d['steps'] if s['step'] == 'Proof of Derivation'), False)")" = "True" ] || fail "Proof of Derivation did not verify"
  # the BSA 63(4) certificate: a DRAFT, Part A pre-filled, Part B blank, never presented as complete
  CERT=$(curl -s -m 120 "$S/certificate?id=$F")
  for want in "NOT COMPLETE" "Part B" "left blank" "Not legal advice" "SHA-256" "$(echo "$T" | jq_ "next(s['detail'] for s in d['steps'] if s['step'] == 'SIEM document')" | grep -o 'sha256:[0-9a-f]*' | head -1)"; do
    echo "$CERT" | grep -q -- "$want" || fail "the certificate lacks: $want"
  done
  echo "certificate: draft for $F — Part A pre-filled, Part B blank, marked NOT COMPLETE and not legal advice"
fi
# the parser transparency log: an UNLOGGED pack pushed to one process is refused, and the refusal is in its evidence log
PU=$(curl -s -m 30 -X POST $S/api/push-unlogged -d '{"process":1}')
[ "$(echo "$PU" | jq_ "d['refused']")" = "True" ] || fail "an unlogged pack was not refused: $PU"
for _ in $(seq 1 40); do [ "$(curl -s $S/api/tlog | jq_ "len(d['refusals'])")" -ge 1 ] && break; sleep 0.5; done
[ "$(curl -s $S/api/tlog | jq_ "len(d['refusals'])")" -ge 1 ] || fail "the refusal is not in the evidence log (pack_refused)"
echo "transparency log: $(echo "$PU" | jq_ "d['pack']") pushed to process 1 — REFUSED, recorded in its evidence log; history: $(curl -s $S/api/tlog | jq_ "', '.join(sorted({e['ProducedBy'] for e in d['entries']}))")"
[ "$(curl -s $S/api/tlog | jq_ "any(e['ProducedBy'] == 'auto-healed' for e in d['entries']) and any(e['ProducedBy'] == 'onboarded' for e in d['entries'])")" = "True" ] || fail "the log must hold this run's onboarded and auto-healed packs"
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
# the evidence archive: ULPF holds only a short local buffer. Shipped segments leave the local directory after the grace
# period; an event whose local copy is gone is proven from the ARCHIVED copy, through the same lookup path "Prove it" uses
until_true 150 "d['archive'].get('deleted_segments', 0) >= 3" "shipped segments deleted from the local buffer (grace ${ULPF_EVIDENCE_GRACE:-60s})"
AR=$STATE/app/evidence-archive
# the process whose evidence store has shipped and deleted the most (with N processes, traffic may miss one of them)
SFX=$(st "(lambda p: '' if p['process'] == 1 else '-' + str(p['process']))(max(d['archive']['processes'], key=lambda x: x['deleted_segments']))")
EVD=$STATE/app/ev$SFX; CMT=$STATE/app/commit$SFX
echo "evidence archive: $(st "(lambda a: f\"{a['shipped_segments']} segments shipped ({a['archived_bytes']} bytes), {a['pending_segments']} pending, {a['deleted_segments']} deleted locally; local buffer {a['local_bytes']} bytes in {a['local_segments']} segments; committer running: {a['committer']}\")(d['archive'])")"
[ "$(st "d['archive']['committer']")" = "True" ] || fail "the committer is not running"
OLD=$(head -1 "$(ls "$EVD"/catalog/seg_*.ids | head -1)")
SEG=$(basename "$(grep -l "^$OLD$" "$EVD"/catalog/seg_*.ids | head -1)" .ids)
[ -f "$EVD/$SEG.raw" ] && fail "$SEG is in the catalogue of deleted segments but still local"
rm -rf "$STATE/app/archive-proof"
"$RT" export --evidence "$EVD" --commit "$CMT" --evidence-archive "$AR" --event-id "$OLD" --out "$STATE/app/archive-proof" 2> "$STATE/app/archive-proof.err" || { cat "$STATE/app/archive-proof.err"; fail "export of $OLD (deleted locally) from the archive"; }
grep -q "EVIDENCE ARCHIVE" "$STATE/app/archive-proof.err" || fail "the export of $OLD did not read the archive"
"$VF" bundle --bundle "$STATE/app/archive-proof" --trust keys/trust | grep -q "VERIFY: OK" || fail "the bundle of $OLD, read from the archive, does not verify"
echo "archive proof: $OLD ($SEG, deleted locally) exported from the archive, its Merkle proof verified with the public key"
if [ "${ULPF_SIEM:-opensearch}" != "fake" ]; then
  # "Prove it" on the System page, for the oldest SIEM document whose segment was deleted locally
  curl -s -m 5 $OS/ulpf-ocsf-*/_refresh > /dev/null
  PID=""
  for id in $(curl -s "$OS/ulpf-ocsf-*/_search" -H 'Content-Type: application/json' -d '{"size":400,"sort":[{"_lineage.ingest_time":"asc"}],"_source":["_lineage.event_id"]}' | jq_ "' '.join(h['_id'] for h in d['hits']['hits'])"); do
    grep -qx "$id" "$STATE"/app/ev*/catalog/seg_*.ids 2>/dev/null && { PID=$id; break; }
  done
  [ -n "$PID" ] || fail "no SIEM document whose segment was deleted locally"
  curl -s -X POST $S/api/prove -d "{\"event_id\":\"$PID\"}" > /dev/null
  for _ in $(seq 1 60); do T=$(curl -s "$S/api/trace?id=$PID"); [ "$T" != "null" ] && [ -n "$T" ] && break; sleep 1; done
  echo "$T" | jq_ "'\n'.join(('  ✓ ' if s['ok'] else '  ✗ ') + s['step'] + ': ' + s['detail'][:150] for s in d['steps'])"
  [ "$(echo "$T" | jq_ "next((s.get('evidence_source') for s in d['steps'] if s.get('evidence_source')), '')")" = "archive" ] || fail "Prove it on $PID did not read the archive"
  [ "$(echo "$T" | jq_ "all(s['ok'] for s in d['steps'] if s['step'] != 'the same event in the lake')")" = "True" ] || fail "Prove it on $PID (read from the archive) did not complete"
  echo "Prove it from the archive: $PID"
fi
gset '{"running":false}'; sleep 8
USABLE=$(st "d['counts']['usable']")
curl -s -m 5 $OS/ulpf-ocsf-*/_refresh > /dev/null
DOCS=$(curl -s "$OS/ulpf-ocsf-*/_count" | jq_ "d['count']")
for port in $(st "' '.join(str(p['lake_port']) for p in d['processes'])"); do curl -s -m 60 "http://127.0.0.1:$port/flush" > /dev/null; done   # every process's lake writer
LAKE=$(python -c "import duckdb,glob; fs=glob.glob('$STATE/app/lake/ext/*/*/*/*/*.parquet'); print(duckdb.connect().execute(f'SELECT count(*), count(DISTINCT event_id) FROM read_parquet({fs!r})').fetchone())")
REJ=$(st "sum(e['rejected'] for e in d['egress'])")
echo "accounting: ULPF parsed $USABLE events; SIEM holds $DOCS documents; lake (rows, distinct event ids) $LAKE; rejected $REJ"
[ "$DOCS" = "$USABLE" ] || fail "the SIEM holds $DOCS documents for $USABLE parsed events (lost, or stored twice)"
[ "$LAKE" = "($USABLE, $USABLE)" ] || fail "the lake holds $LAKE for $USABLE parsed events"
[ "$REJ" = "0" ] || fail "$REJ event(s) rejected by a destination"
# scale-out: every connection (peer address:port) was handled by exactly one process — read off every store's evidence,
# local and archived
AFF=$(python3 - "$STATE/app" <<'PY'
import glob, json, os, sys
app = sys.argv[1]; seen = {}
for ev in sorted(glob.glob(f"{app}/ev") + glob.glob(f"{app}/ev-*")):
    proc = 1 if ev.endswith("/ev") else int(ev.rsplit("-", 1)[1])
    sid = json.load(open(f"{ev}/store.json"))["store_id"]
    idx = {os.path.basename(p): p for p in glob.glob(f"{app}/evidence-archive/{sid}/segments/seg_*.idx.jsonl")}
    idx.update({os.path.basename(p): p for p in glob.glob(f"{ev}/seg_*.idx.jsonl")})
    for p in idx.values():
        for l in open(p, encoding="utf-8"):
            r = json.loads(l)
            if r.get("framing", {}).get("method") != "gap_record" and r.get("peer"):
                seen.setdefault(r["peer"], set()).add(proc)
split = {k: sorted(v) for k, v in seen.items() if len(v) > 1}
procs = sorted({p for v in seen.values() for p in v})
print(f"{len(seen)} connections over processes {procs}; split across processes: {split or 'none'}")
sys.exit(1 if split else 0)
PY
) || fail "a connection was handled by more than one process: $AFF"
echo "affinity: $AFF"
# local evidence disk, before and after shipping: without the archive every segment would still be local
python3 - "$STATE/app" <<'PY'
import glob, json, os, sys
app = sys.argv[1]
size = lambda ps: sum(os.path.getsize(p) for p in ps if os.path.exists(p))
written = local = kept = segs_all = segs_local = 0
for ev in sorted(glob.glob(f"{app}/ev") + glob.glob(f"{app}/ev-*")):   # every process's evidence store
    if not os.path.exists(f"{ev}/store.json"):
        continue
    sid = json.load(open(f"{ev}/store.json"))["store_id"]
    loc = size([p for p in glob.glob(f"{ev}/seg_*") if p.endswith((".raw", ".idx.jsonl", ".seal.json"))])
    arch = {os.path.basename(p): os.path.getsize(p) for p in glob.glob(f"{app}/evidence-archive/{sid}/segments/seg_*") if not p.endswith(".part")}
    names = {os.path.basename(p) for p in glob.glob(f"{ev}/seg_*")}
    written += loc + sum(v for k, v in arch.items() if k not in names); local += loc
    kept += size(glob.glob(f"{ev}/catalog/*")) + size([f"{ev}/deleted.jsonl", f"{ev}/store.json"])
    segs_all += len({n.split(".")[0] for n in names | set(arch)}); segs_local += len({n.split(".")[0] for n in names})
print(f"local evidence disk (every process): {written} bytes written in {segs_all} segments — without shipping all of it would be local; "
      f"after shipping {local} bytes are local ({local / max(written, 1):.0%}) in {segs_local} segments, plus {kept} bytes of catalogue and deletion log")
PY
[ "${KEEP:-0}" = "1" ] || bash demo/start-demo.sh stop > /dev/null
echo "apps-check: PASS ($ULPF_DEMO_PROVIDER, SIEM ${ULPF_SIEM:-opensearch})"
