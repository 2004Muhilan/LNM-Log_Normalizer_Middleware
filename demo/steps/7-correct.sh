#!/usr/bin/env bash
# Step 7 (P8, NOT part of the six-step sequence: `bash demo/run.sh 7 7` after a full run) — versioned
# corrections, invariant 8. Step 4 promoted the 11-slot Squid family with a RETAINED certificate: the
# 11th slot rested on a proposal (`http_request.length`), its rival `http_response.length` unrefuted. Now
# the operator supplies the evidence — the device's full logformat, whose last code is %>st — and:
#   1. the certificate resolves; the family is promoted as pack version 1.1 (same session, new evidence);
#   2. the runtime re-derives the affected events FROM THE EVIDENCE LOG under the corrected packs and seals
#      them as normalization@v2 with derived_from 1;
#   3. normalization@v1 is byte-identical (sha256 before = after = manifest), both versions of an event
#      are retrievable, and there is no write path to v1 (the attempt is shown failing).
# Step 6 left one byte of the evidence flipped. A correction derives from evidence, so it is REFUSED over
# altered evidence — shown first — and runs after the byte is put back from step 6's own record.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 7 "Versioned correction (invariant 8)"
D="$STATE/step7"; rm -rf "$D" "$STATE/packs/squid-11-v1.1" "$STATE/source-packs/squid-v1.1"; mkdir -p "$D"
LAKE="$STATE/lake"; EV="$STATE/ev"; S="$STATE/step4/session"
[ -f "$LAKE/normalization-v1.manifest.json" ] || step_fail "no sealed normalization@v1 in $LAKE: step 5 has not run"
[ -f "$S/session.json" ] || step_fail "no step-4 session"
[ -f "$LAKE/normalization-v2.jsonl" ] && step_fail "the lake already holds v2: reset first (a version is never rewritten — that is the point)"
V1="$LAKE/normalization-v1.jsonl"
sha256sum "$V1" | cut -d' ' -f1 > "$D/v1.sha256.before"
echo "normalization@v1: $(grep -c '' "$V1") events, sha256 $(cat "$D/v1.sha256.before")"
EVENT=$(python3 - "$V1" <<'EOF'
import json, sys
for l in open(sys.argv[1]):
    e = json.loads(l)
    if e["_lineage"]["family_id"] == "positional-11":
        print(e["_lineage"]["event_id"]); break
EOF
)
[ -n "$EVENT" ] || step_fail "no 11-slot Squid event in v1"

echo "--- 1. the retained certificate is resolved by evidence; the family is promoted as pack version 1.1"
LOGFORMAT11="$LOGFORMAT %>st"
echo "operator answer: $LOGFORMAT11"
learn respond --session "$S" --discriminator device_logformat_configuration --input "$LOGFORMAT11" > "$D/respond.txt" || { tail -3 "$D/respond.txt"; step_fail "respond"; }
learn certificates --session "$S" | grep -A4 "pos11" | tee "$D/certificate.txt"
grep -q "resolved -> traffic.bytes_in" "$D/certificate.txt" || step_fail "the retained certificate did not resolve to traffic.bytes_in"
learn promote --session "$S" --out "$STATE/packs/squid-11-v1.1" --pack-id squid-native-11 --pack-version 1.1 | tee "$D/promote.txt" || step_fail "promote 1.1"
learn merge "$STATE/packs/squid-10" "$STATE/packs/squid-11-v1.1" --out "$STATE/source-packs/squid-v1.1" --pack-id squid-proxy-01 --pack-version 1.1 > "$D/merge.txt" || step_fail "merge"
"$RT" verify-pack --pack "$STATE/source-packs/squid-v1.1" | tee -a "$D/merge.txt" || step_fail "verify corrected pack"
PACKS=(--pack "$STATE/p6/source-packs/cisco-asa" --pack "$STATE/p6/source-packs/panos" --pack "$STATE/p6/source-packs/fortigate" --pack "$STATE/source-packs/squid-v1.1")
REASON="cert_squid-proxy-01_pos11 resolved by device_logformat_configuration (%>st -> traffic.bytes_in); squid-proxy-01 pack 1.1"

if [ -f "$STATE/step6/tamper.json" ]; then
  echo "--- 2a. the evidence still carries step 6's flipped byte: the correction must be refused"
  if "$RT" renormalize "${PACKS[@]}" --evidence "$EV" --lake "$LAKE" --reason "$REASON" > "$D/refused.txt" 2>&1; then step_fail "a correction ran over altered evidence"; fi
  grep -q "evidence was altered" "$D/refused.txt" || { cat "$D/refused.txt"; step_fail "refused, but not for the altered evidence"; }
  sed 's/^/  /' "$D/refused.txt"
  [ -f "$LAKE/normalization-v2.jsonl" ] && step_fail "a refused correction sealed a version"
  echo "--- 2b. put the byte back (from step 6's own tamper record) and verify the evidence again"
  python3 - "$STATE/step6/tamper.json" "$EV" <<'EOF' || step_fail "could not restore the tampered byte"
import json, os, sys
t = json.load(open(sys.argv[1])); raw = os.path.join(sys.argv[2], t["file"])
os.chmod(raw, 0o644)
b = bytearray(open(raw, "rb").read())
assert b[t["offset"]] == t["tampered_byte"], "the byte is not the one step 6 wrote"
b[t["offset"]] = t["original_byte"]; open(raw, "wb").write(b); os.chmod(raw, 0o444)
print(f"  byte {t['offset']} restored to 0x{t['original_byte']:02x}")
EOF
  "$VF" evidence --evidence "$EV" --trust keys/trust | tail -1 | tee "$D/verify-evidence.txt"
  grep -q "VERIFY: OK" "$D/verify-evidence.txt" || step_fail "evidence does not verify after the restore"
fi

echo "--- 2. the correction: re-derive from the evidence under the corrected packs -> normalization@v2"
"$RT" renormalize "${PACKS[@]}" --evidence "$EV" --lake "$LAKE" --reason "$REASON" > "$D/renormalize.json" || { cat "$D/renormalize.json"; step_fail "renormalize"; }
python3 - "$D/renormalize.json" <<'EOF' || step_fail "unexpected correction stats"
import json, sys
r = json.load(open(sys.argv[1]))
print(f"  derived_from v{r['derived_from']} -> v{r['normalization_version']}: read {r['events_read']}, corrected {r['events_corrected']} {json.dumps(r['corrected_by_family'])}, unchanged {r['events_unchanged']}, not applicable {r['events_not_applicable']}")
ok = r["derived_from"] == 1 and r["normalization_version"] == 2 and r["corrected_by_family"] == {"squid-proxy-01/positional-11": 6} and r["events_corrected"] == 6 and r["events_not_applicable"] == 0 and r["events_unchanged"] == r["events_read"] - 6
sys.exit(0 if ok else 1)
EOF

echo "--- 3. v1 is byte-identical; both versions are retrievable; v2 validates; there is no write path to v1"
sha256sum "$V1" | cut -d' ' -f1 > "$D/v1.sha256.after"
cmp -s "$D/v1.sha256.before" "$D/v1.sha256.after" || step_fail "normalization@v1 CHANGED"
echo "  v1 sha256 before = after = $(cat "$D/v1.sha256.after")"
"$RT" lake verify --lake "$LAKE" | tee "$D/lake-verify.txt" | sed 's/^/  /'
grep -q "^LAKE: OK — 2 version" "$D/lake-verify.txt" || step_fail "lake does not verify"
"$RT" lake get --lake "$LAKE" --event-id "$EVENT" > "$D/event-versions.jsonl" || step_fail "lake get"
(cd learning && python - "$D/event-versions.jsonl" "$LAKE/normalization-v2.jsonl" <<'EOF') || step_fail "version check"
import json, sys
from ulpf_contracts import validate_document
v = [json.loads(l) for l in open(sys.argv[1])]
assert len(v) == 2, f"expected both versions of the event, got {len(v)}"
a, b = v
la, lb = a["_lineage"], b["_lineage"]
assert (la["normalization_version"], lb["normalization_version"], lb.get("derived_from"), la.get("derived_from")) == (1, 2, 1, None), (la, lb)
for k in ("event_id", "raw_hash", "segment_id", "offset", "length", "ingest_time"):
    assert la[k] == lb[k], k
assert (la["parser_version"], lb["parser_version"]) == ("1.0", "1.1")
assert a["http_request"].get("length") == "412" and "traffic" in a and "bytes_in" not in a["traffic"], a
assert b["traffic"]["bytes_in"] == 412 and "length" not in b["http_request"], b
n = bad = 0
for l in open(sys.argv[2]):
    n += 1; bad += bool(validate_document("normalized-event", json.loads(l)))
assert n == 6 and bad == 0, (n, bad)
print(f"  {la['event_id']}: v1 http_request.length=\"412\" (model proposal, parser 1.0)  ->  v2 traffic.bytes_in=412 (device configuration, parser 1.1, derived_from 1)")
print(f"  v2: {n} events, 0 invalid against normalized-event")
EOF
echo "  write attempts on v1:"
if ( echo '{"forged":true}' >> "$V1" ) 2>/dev/null; then step_fail "v1 accepted an append"; else echo "    shell append           -> refused (read-only)"; fi
if "$RT" run --pack "$STATE/source-packs/squid" --input "$SAMPLES" --evidence "$D/ev-scratch" --out /dev/null --lake "$LAKE" > "$D/rewrite-attempt.txt" 2>&1; then step_fail "the runtime re-created v1"; fi
grep -q "never reopened" "$D/rewrite-attempt.txt" || { cat "$D/rewrite-attempt.txt"; step_fail "v1 re-creation failed for the wrong reason"; }
echo "    runtime --lake (v1)    -> refused: $(grep -o 'version 1 refused.*' "$D/rewrite-attempt.txt" | head -1)"
cmp -s "$D/v1.sha256.before" <(sha256sum "$V1" | cut -d' ' -f1) || step_fail "normalization@v1 CHANGED after the write attempts"
python3 - "$D" "$EVENT" <<'EOF'
import json, sys
d, ev = sys.argv[1:3]
json.dump({"event_id": ev, "v1_sha256": open(f"{d}/v1.sha256.after").read().strip(), "renormalize": json.load(open(f"{d}/renormalize.json")),
           "versions": [json.loads(l) for l in open(f"{d}/event-versions.jsonl")], "lake_verify": open(f"{d}/lake-verify.txt").read()}, open(f"{d}/result.json", "w"), indent=1)
EOF
step_end "6 events corrected to normalization@v2 (derived_from 1); v1 byte-identical; write path to v1 refused"
