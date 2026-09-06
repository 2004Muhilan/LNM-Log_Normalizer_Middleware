#!/usr/bin/env bash
# Step 3 — the unresolved case: pos_2, Squid's duration column. Nothing runs against the model here; this
# step reads step 2's session and shows the two forms "no guess" takes:
#   (a) live session: the model's lone label for pos_2 (the 4B says http_status) has no rival the library
#       can name and 800+ type-compatible survivors — it is UNEVIDENCED: blocked, not accepted, not guessed,
#       covered by the one request; after the logformat answer the field is `duration` with device
#       provenance and the model's label is gone;
#   (b) the P3 fixture path (run here in 0.1 s, labelled as such): two fixture candidates, duration and
#       http_response.latency, no library discriminator between them — an UNRESOLVED certificate,
#       `no_library_discriminator`, no guess is made.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 3 "The unresolved case (pos_2)"
[ -f "$STATE/step2/session-after.json" ] || step_fail "step 2 has not run"
FS="$STATE/step3/session-fixture"; rm -rf "$FS"
learn onboard --provider fixture --samples "$SAMPLES" --source-id squid-proxy-01 --operator op-014 --session "$FS" > /dev/null || step_fail "fixture session"
python3 - "$STATE/step2/session-before.json" "$STATE/step2/session-after.json" "$FS/session.json" "$STATE/step3/unresolved.json" <<'EOF' | tee "$STATE/step3/unresolved.txt"
import json, sys
before, after, fixture = (json.load(open(p)) for p in sys.argv[1:4])
out = {"live": [], "fixture": []}
def slot_mapping(sess, field):
    for s in sess["plan"]["slots"]:
        for part in s.get("parts", []):
            if part.get("field") == field or (field == f"pos_{s['index']+1}" and not part.get("field", "").startswith("pos_")):
                m = (part.get("mappings") or [{}])[0]
                return {"field": part.get("field"), "attribute": m.get("attribute"), "provenance": (m.get("provenance") or {}).get("category"),
                        "discriminator": (m.get("provenance") or {}).get("discriminator_id"), "evidence": (m.get("provenance") or {}).get("evidence_ref"),
                        "proposed_by": part.get("proposed_by"), "candidates": part.get("candidates")}
    return None
print("(a) the live session — a lone model label with no evidence behind it")
for u in before.get("unevidenced", []):
    b = slot_mapping(before, u["field"]); a = slot_mapping(after, u["field"])
    out["live"].append({"field": u["field"], "proposed": u["attribute"], "reason": u["reason"], "before": b, "after": a})
    if u["field"] == "pos_2":
        print(f"  {u['field']}: model proposed {u['attribute']} — {u['reason']}")
        print(f"     -> blocked, no guess; covered by the request; after the answer: {a['attribute']} ({a['provenance']}, {a['discriminator']})")
print("(b) the P3 fixture path — two candidates the library cannot separate")
certs = fixture["certificates"]; certs = list(certs.values()) if isinstance(certs, dict) else certs
for c in certs:
    if c.get("status") == "unresolved" or c.get("unresolved_reason"):
        out["fixture"].append(c)
        print(f"  {c['certificate_id']}: field {c['field']['path']} slot {c['context']['slot_index']+1} [{c['context']['token_class']}] status={c['status']}")
        print("     candidates: " + " > ".join(f"{r['rank']}. {r['attribute']} ({r['proposed_by']})" for r in c["ranked_candidates"]))
        print(f"     UNRESOLVED: {c.get('unresolved_reason')} — no guess is made")
json.dump(out, open(sys.argv[4], "w"), indent=1)
ok = any(u["field"] == "pos_2" for u in out["live"]) or any(c["field"]["path"] == "pos_2" for c in out["fixture"])
sys.exit(0 if ok else 1)
EOF
[ ${PIPESTATUS[0]} -eq 0 ] || step_fail "pos_2 was neither unevidenced nor unresolved"
step_end "pos_2: no guess in either form; resolved to duration by the logformat"
