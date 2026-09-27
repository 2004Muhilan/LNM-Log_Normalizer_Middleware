#!/usr/bin/env bash
# P6: onboard the three anchored vendors (ASA by message id, PAN-OS CSV, FortiGate KV) through the
# P3/P4 path — given spec + recorded model proposals + the vendor's field-order documentation as the
# resolving evidence — promote each family to a signed pack, merge per source, then run the four-vendor
# MIXED stream through the runtime with every pack loaded: the routing DAG, quarantine of adversarial
# lines, the candidate-set distribution, and the ML feature tuple. Also the propagation demo (a second
# Squid-structured family onboarded with no evidence request) and family discovery ranking.
#
# Corpus fixtures are read from corpus/cache (git-ignored, ELv2); the packs built here contain corpus
# lines as samples and are therefore written under /tmp, never into the tree.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
W=${ULPF_P6_WORK:-/tmp/ulpf-p6}
rm -rf "$W"; mkdir -p "$W/samples" "$W/packs" "$W/source-packs"
REC="$PWD/spike/results/desktop-5060ti/granite-4.1-8b-q4_k_m__gpu"
CORPUS=corpus/cache
status=0
learn() { (cd learning && python -m ulpf_learn "$@"); }

[ -f "$CORPUS/beats-cisco-asa/asa.log" ] || { echo "corpus cache missing: run the P1 fetch first"; exit 2; }

echo "=== samples per family (from the corpus cache; syslog headers kept — the learning plane unwraps like the runtime)"
grep -h '%ASA-6-302013:' "$CORPUS/beats-cisco-asa/asa.log" > "$W/samples/asa-302013.log"
grep -h '%ASA-6-30201[46]:' "$CORPUS/beats-cisco-asa/asa.log" > "$W/samples/asa-302014.log"
grep -h '%ASA-4-106023:' "$CORPUS/beats-cisco-asa/asa.log" | grep -v '0x0\]"$' > "$W/samples/asa-106023.log"   # one malformed fixture line (stray quote) is evidence, not a sample
grep -h '%ASA-6-30501[12]:' "$CORPUS/beats-cisco-asa/asa.log" > "$W/samples/asa-305011.log"
cp "$CORPUS/beats-panw-panos/traffic.log" "$W/samples/panos-traffic.log"
cp "$CORPUS/beats-fortinet-firewall/traffic.log" "$W/samples/fortigate-traffic.log"
wc -l "$W"/samples/*.log | sed 's/^/  /'

onboard_family() { # vendor family spec source_id recording evidence_text
  local vendor=$1 fam=$2 spec=$3 src=$4 rec=$5 ev=$6
  echo "--- $fam ($vendor)"
  learn onboard-spec --samples "$W/samples/$fam.log" --spec "$PWD/drafts/sufficiency/$spec.json" --source-id "$src" --operator op-014 \
        --session "$W/s-$fam" --vendor "$vendor" --family-id "$fam" --unwrap-envelope --provider recorded --recording "${REC}__${rec}__whole.json" > "$W/s-$fam.onboard.txt" || { echo "  FAIL onboard"; status=1; return; }
  grep -E "^source|^promotable|REQUEST|discriminator:" "$W/s-$fam.onboard.txt" | sed 's/^/  /'
  learn respond --session "$W/s-$fam" --discriminator vendor_schema_field_order --input "$ev" > "$W/s-$fam.respond.txt" || { echo "  FAIL respond"; status=1; return; }
  grep -E "^promotable|blocker" "$W/s-$fam.respond.txt" | sed 's/^/  /'
  learn promote --session "$W/s-$fam" --out "$W/packs/$fam" --pack-id "$fam" | sed 's/^/  /' || { echo "  FAIL promote"; status=1; return; }
}

echo "=== onboarding through the P3/P4 path (recorded Granite proposals; vendor documentation resolves)"
onboard_family cisco-asa asa-302013 asa-302013 asa-fw-01 asa-302013 "Cisco Secure Firewall ASA Series Syslog Messages: 302013 Built {inbound|outbound} {protocol} connection ..."
onboard_family cisco-asa asa-302014 asa-302014 asa-fw-01 asa-302013 "Cisco Secure Firewall ASA Series Syslog Messages: 302014/302016 Teardown {TCP|UDP} connection ..."
onboard_family cisco-asa asa-106023 asa-106023 asa-fw-01 asa-106023 "Cisco Secure Firewall ASA Series Syslog Messages: 106023 Deny protocol src ... dst ... by access-group"
onboard_family cisco-asa asa-305011 asa-305011 asa-fw-01 asa-302013 "Cisco Secure Firewall ASA Series Syslog Messages: 305011 Built {dynamic|static} translation"
onboard_family paloalto-panos panos-traffic panos-traffic panos-fw-01 panos-traffic "PAN-OS 8.1 Syslog Field Descriptions: Traffic log field order"
onboard_family fortinet-fortigate fortigate-traffic fortigate-traffic fortigate-fw-01 fortigate-traffic "FortiOS 6.2 Log Reference: traffic/forward log fields"

echo "=== source packs (per source, per-family entries; anchors declared once, from the vendor table)"
learn merge "$W"/packs/asa-{302013,302014,106023,305011} --out "$W/source-packs/cisco-asa" --pack-id cisco-asa-fw-01 --vendor cisco-asa | sed 's/^/  /' || status=1
learn merge "$W/packs/panos-traffic" --out "$W/source-packs/panos" --pack-id panos-fw-01 --vendor paloalto-panos | sed 's/^/  /' || status=1
learn merge "$W/packs/fortigate-traffic" --out "$W/source-packs/fortigate" --pack-id fortigate-fw-01 --vendor fortinet-fortigate | sed 's/^/  /' || status=1
for p in cisco-asa panos fortigate; do runtime/bin/ulpf-runtime verify-pack --pack "$W/source-packs/$p" | sed 's/^/  /' || status=1; done

echo "=== propagation (§4.4 key): Squid 10-slot resolved by logformat, then an 11-slot Squid family with NO evidence request"
STORE="$W/propagation.json"
learn onboard --provider fixture --samples "$PWD/contracts/golden/squid-native/samples/access.log" --source-id squid-proxy-01 --operator op-014 --session "$W/s-squid-10" --propagation-store "$STORE" > /dev/null || status=1
learn respond --session "$W/s-squid-10" --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt" > /dev/null || status=1
learn promote --session "$W/s-squid-10" --out "$W/packs/squid-10" --pack-id squid-10 | tail -1 | sed 's/^/  10-slot: /' || status=1
learn onboard --provider fixture --samples "$PWD/learning/fixtures/squid-native-11.log" --source-id squid-proxy-01 --operator op-014 --session "$W/s-squid-11" --propagation-store "$STORE" | grep -E "^propagated|^promotable|^  blocker|resolves:" | sed 's/^/  11-slot: /'
# what propagation must show: every slot the 10-slot family resolved is resolved here with NO request; the
# only question left (if any) concerns the NEW 11th slot, which is not mandatory — the family promotes with
# zero operator responses and that certificate retained (P8 resolves retained certificates retroactively)
python - "$W/s-squid-11/session.json" <<'PY' || status=1
import json, sys
s = json.load(open(sys.argv[1]))
prop = {h["slot_index"] for h in s.get("propagated", [])}
req = s.get("pending_request") or {}
new_only = all(f == "pos_11" for f in req.get("resolves", []))
ok = prop == set(range(10)) and not s["verdict"]["blockers"] and new_only
print(f"  11-slot: propagated slots {sorted(prop)}; blockers {s['verdict']['blockers']}; pending request resolves {req.get('resolves')} -> {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
PY
learn promote --session "$W/s-squid-11" --out "$W/packs/squid-11" --pack-id squid-11 | tail -1 | sed 's/^/  11-slot: /' || status=1
python - "$W/s-squid-11/session.json" <<'PY' || status=1
import json, sys
m = json.load(open(sys.argv[1]))["metrics"]
print(f"  11-slot metrics: evidence_requests={m['evidence_requests']} operator_responses={m['operator_responses']} promoted={m['promoted']}  (10-slot family: 1 request, 1 response)")
sys.exit(0 if m["operator_responses"] == 0 and m["promoted"] else 1)
PY
learn merge "$W/packs/squid-10" "$W/packs/squid-11" --out "$W/source-packs/squid" --pack-id squid-proxy-01 | sed 's/^/  /' || status=1

echo "=== mixed live stream: four vendors + Squid's two families through one runtime, every pack loaded"
M="$W/mixed.log"; : > "$M"
paste -d'\n' <(head -20 "$W/samples/asa-302013.log") <(head -20 "$W/samples/panos-traffic.log") <(head -13 "$W/samples/fortigate-traffic.log") \
      <(sed 's/^/<134>Dec 19 00:00:00 proxy01 squid[1234]: /' contracts/golden/squid-native/samples/access.log) \
      <(sed 's/^/<134>Dec 19 00:00:01 proxy01 squid[1234]: /' learning/fixtures/squid-native-11.log) \
      <(head -10 "$W/samples/asa-302014.log") <(head -10 "$W/samples/asa-106023.log") <(head -10 "$W/samples/asa-305011.log") | grep -v '^$' >> "$M"
# adversarial, anchor-defeating lines: an ASA id outside the declared domain, a PAN-OS type outside its enum, an ASA id in the domain no family owns
cat >> "$M" <<'EOF'
Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-999999: Built outbound TCP connection 1 for outside:1.1.1.1/80 (1.1.1.1/80) to inside:2.2.2.2/1 (2.2.2.2/1)
Nov 30 16:09:08 PA-220 1,2018/11/30 16:09:07,012801096514,WEIRD,end,2049,2018/11/30 16:09:07,192.168.15.207,184.51.253.152,192.168.1.63,184.51.253.152,new_outbound_from_trust,,,apple-maps,vsys1,trust,untrust,ethernet1/2,ethernet1/1,send_to_mac,2018/11/30 16:09:07,22751,1,55113,443,16418,443,0x400053,tcp,allow,7734,1758,5976,36,2018/11/30 15:59:04,586,computer-and-internet-info,0,32091112,0x0,192.168.0.0-192.168.255.255,United States,0,16,20,tcp-fin,0,0,0,0,,PA-220,from-policy,,,0,,0,,N/A,0,0,0,0
Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-6-302015: Built outbound UDP connection 11752 for outside:100.66.205.104/53 (100.66.205.104/53) to inside:172.31.98.44/60123 (172.31.98.44/60123)
EOF
wc -l < "$M" | sed 's/^/  frames: /'
rm -rf "$W/ev"
runtime/bin/ulpf-runtime run --dev-no-evidence-archive --pack "$W/source-packs/cisco-asa" --pack "$W/source-packs/panos" --pack "$W/source-packs/fortigate" --pack "$W/source-packs/squid" \
   --source-id mixed-relay-01 --input "$M" --evidence "$W/ev" --out "$W/out.jsonl" --quarantine "$W/q.jsonl" --ml-out "$W/ml.jsonl" --fixed-clock-ms 1734567890481 2> "$W/stats.json" || status=1
python - "$W" <<'PY' || status=1
import json, sys, collections
W = sys.argv[1]
st = json.loads(open(f"{W}/stats.json").read().strip().splitlines()[-1])
print("  stats:", json.dumps({k: st[k] for k in ("frames", "emitted", "usable", "quarantined", "enveloped", "drift_signals", "ml_records")}))
print("  emitted by family:", json.dumps(st["emitted_by_family"]))
print("  candidate-set sizes after L4:", json.dumps(st["candidate_set_sizes"]), " quarantine reasons:", json.dumps(st["quarantine_reasons"]))
q = [json.loads(l) for l in open(f"{W}/q.jsonl")]
for r in q:
    print(f"  quarantined [{r['stage']}] {r['reason'][:110]}")
ok = st["quarantined"] == 3 and st["drift_signals"] == 2 and st["quarantine_reasons"].get("routing_drift") == 2 and st["quarantine_reasons"].get("routing") == 1
ok = ok and max(int(k) for k in st["candidate_set_sizes"]) <= 1 and st["ml_records"] == st["emitted"] and st["emitted"] + st["quarantined"] == st["frames"]
print("  mixed stream:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY

echo "=== outputs validate: normalized events (1.2.0) and ML feature records (draft 0.1.0)"
(cd learning && python - "$W" <<'PY') || status=1
import json, sys
from ulpf_contracts import validate_document
W = sys.argv[1]
bad = 0
for kind, f in (("normalized-event", "out.jsonl"), ("ml-feature", "ml.jsonl")):
    n = 0
    for l in open(f"{W}/{f}", encoding="utf-8"):
        n += 1
        errs = validate_document(kind, json.loads(l))
        if errs:
            bad += 1
            if bad < 4:
                print(f"  {kind} line {n}: {errs[:2]}")
    print(f"  {kind}: {n} records, {bad} invalid")
ml = [json.loads(l) for l in open(f"{W}/ml.jsonl", encoding="utf-8")]
ex = next(r for r in ml if r["template_id"].startswith("cisco-asa"))
print("  sample ML tuple:", json.dumps({k: ex[k] for k in ("template_id", "timestamp", "entity_ids")})[:220])
print("  parameter vector:", json.dumps(dict(zip(ex["parameter_names"][:6], ex["parameter_vector"][:6]))))
sys.exit(1 if bad else 0)
PY

echo "=== family discovery ranking over the mixed capture (no pack, no parser)"
(cd learning && python tools/discover.py "$M" --top 12 --json "$W/discovery.json") | sed 's/^/  /' || status=1

echo "=== agreement with the reference parser (crosswalk draft; effort metric, not correctness)"
runtime/bin/ulpf-runtime run --dev-no-evidence-archive --pack "$W/source-packs/cisco-asa" --input "$W/samples/asa-302013.log" --evidence "$W/ev-asa" --out "$W/asa-out.jsonl" --quarantine "$W/asa-q.jsonl" 2>/dev/null || status=1
(cd learning && python tools/agreement.py --normalized "$W/asa-out.jsonl" --expected "../$CORPUS/beats-cisco-asa/asa.log-expected.json" --raw "$W/samples/asa-302013.log" --json "$W/agreement-asa.json") | tail -9 | sed 's/^/  /' || status=1

echo "p6-build-packs: $([ $status = 0 ] && echo PASS || echo FAIL)"
exit $status
