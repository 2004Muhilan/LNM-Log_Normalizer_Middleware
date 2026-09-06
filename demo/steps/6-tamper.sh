#!/usr/bin/env bash
# Step 6 — tamper and suppression: the committer commits step 5's sealed segment under a signed
# checkpoint and a daily root; the verifier recomputes every root: OK. One event and the silence gap
# record are exported as bundles; the witness container (only ulpf-verify and the public key, no
# network) verifies both. Then one byte of the sealed segment is flipped: the verifier fails the
# checkpoint and names the exact leaf; the gap record's own root check fails with it.
# The commit here is the development seam (ULPF_COMMIT_SEALED=1: the segment is SEALED, not
# kernel-IMMUTABLE — the checkpoint says so in commit_mode); the kernel-flag version of the same test is
# scripts/p5-boundary-test.sh, two containers with the capability split — run it in Q&A if asked.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 6 "Tamper and suppression"
EV="$STATE/ev"; [ -d "$EV" ] || step_fail "no evidence store: step 5 has not run"
D="$STATE/step6"; rm -rf "$D"/*; mkdir -p "$D"
echo "--- commit (signed minute checkpoint + daily root)"
ULPF_COMMIT_SEALED=1 "$CM" commit --evidence "$EV" --key keys/dev/ulpf-committer-dev.json 2>/dev/null | tee "$D/commit.json" | cut -c1-200
"$CM" daily --evidence "$EV" --key keys/dev/ulpf-committer-dev.json | tee "$D/daily.txt"
echo "--- verify before"
"$VF" evidence --evidence "$EV" --trust keys/trust | tee "$D/verify-before.txt"
echo "--- export: one event and the silence gap record; the witness verifies both with only the public key"
EVID=$(python3 -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1])][3]["event_id"])' "$EV/seg_00000.idx.jsonl")
GAPID=$(python3 -c 'import json,sys; rs=[json.loads(l) for l in open(sys.argv[1])]; print(next(r["event_id"] for r in rs if r["record"]["kind"]=="silence"))' "$STATE/step5/gaps.json")
"$RT" export --evidence "$EV" --event-id "$EVID" --out "$D/bundle-event" 2>&1 | tee "$D/export.txt"
"$RT" export --evidence "$EV" --event-id "$GAPID" --out "$D/bundle-gap" 2>&1 | tee -a "$D/export.txt"
for b in bundle-event bundle-gap; do
  docker run --rm --name ulpf-demo-witness --network none -v "$D/$b:/bundle:ro" -v "$ROOT/keys/trust:/trust:ro" ulpf-verify bundle --bundle /bundle --trust /trust 2>&1 | tee "$D/witness-$b.txt"
done
grep -q "VERIFY: OK" "$D/witness-bundle-event.txt" && grep -q "VERIFY: OK" "$D/witness-bundle-gap.txt" || step_fail "witness did not verify the bundles"
echo "--- tamper: flip one byte inside the first event of the sealed segment"
RAW="$EV/seg_00000.raw"; OFF="${ULPF_DEMO_TAMPER_OFFSET:-8}"
python3 - "$RAW" "$OFF" "$D/tamper.json" <<'EOF'
import json, sys, os
raw, off, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
b = bytearray(open(raw, "rb").read())
lo, hi = max(0, off - 24), min(len(b), off + 24)
before = bytes(b[lo:hi])
orig = b[off]
b[off] ^= 0x01
os.chmod(raw, 0o644)
open(raw, "wb").write(bytes(b))
after = bytes(b[lo:hi])
json.dump({"file": os.path.basename(raw), "offset": off, "window_start": lo, "before_hex": before.hex(), "after_hex": after.hex(),
           "before_text": before.decode("latin-1"), "after_text": after.decode("latin-1"), "original_byte": orig, "tampered_byte": b[off]}, open(out, "w"), indent=1)
print(f"byte {off} of {os.path.basename(raw)}: 0x{orig:02x} -> 0x{b[off]:02x}")
EOF
echo "--- verify after"
"$VF" evidence --evidence "$EV" --trust keys/trust | tee "$D/verify-after.txt"
grep -q "tampered leaf" "$D/verify-after.txt" || step_fail "verifier did not name the leaf"
echo "--- gap records after the tamper"
"$VF" gaps --evidence "$EV" --trust keys/trust | tee "$D/gaps-after.txt"
"$VF" gaps --evidence "$EV" --trust keys/trust --json > "$D/gaps-after.json" 2>/dev/null
python3 - "$D" <<'EOF'
import json, sys, re
d = sys.argv[1]
ck = json.load(open(f"{d}/commit.json"))
ver_after = open(f"{d}/verify-after.txt").read()
leaf = re.search(r"tampered (leaf .*)", ver_after)
json.dump({"checkpoint_id": ck["checkpoint"]["checkpoint_id"], "commit_mode": ck["checkpoint"].get("commit_mode"), "committed": ck["committed"],
           "verify_before": open(f"{d}/verify-before.txt").read(), "verify_after": ver_after, "tampered_leaf": leaf.group(1) if leaf else None,
           "witness_event": open(f"{d}/witness-bundle-event.txt").read(), "witness_gap": open(f"{d}/witness-bundle-gap.txt").read(),
           "export": open(f"{d}/export.txt").read(), "tamper": json.load(open(f"{d}/tamper.json")),
           "gaps_after": open(f"{d}/gaps-after.txt").read()}, open(f"{d}/result.json", "w"), indent=1)
EOF
step_end "verifier named: $(grep -o 'tampered leaf.*' "$D/verify-after.txt" | head -1 | cut -c1-80)"
