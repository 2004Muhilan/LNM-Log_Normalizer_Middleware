#!/usr/bin/env bash
# Real mode (optional): run steps 5 and 6 of the demo for real on this Linux machine with the bundled
# static binaries — no Go, no Docker, no model, no venv. Steps 1–4 stay recorded: they are the learning
# plane (Python with google-re2 / jsonschema / cryptography), which the standard library cannot replace.
#   bash real/run-real.sh [capture-file]      # default: the recorded mixed capture
#   python3 serve.py --real                   # then serve the real state for steps 5 and 6
# What runs: the four recorded packs (three vendors from recorded Granite, Squid from the recorded live
# session) loaded into ulpf-runtime; the file streamed over TCP with RFC 6587 framing from two peers
# (one goes silent); commit, verify, export, in-process witness verification (no container), one byte
# flipped, verify again. The dev signing keys travel in real/keys (demo-grade, see NOTICE.md).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; B="$HERE/.."
CAPFILE="${1:-$B/capture/state/p6/mixed.log}"
[ -f "$CAPFILE" ] || { echo "capture file not found: $CAPFILE"; exit 1; }
chmod +x "$HERE"/bin/* 2>/dev/null   # a zip extracted with python's zipfile drops the executable bit
for x in ulpf-runtime ulpf-committer ulpf-verify; do [ -x "$HERE/bin/$x" ] || { echo "missing $HERE/bin/$x (this bundle was built without binaries: pure replay only)"; exit 1; }; done
export ULPF_ROOT="$HERE/root"    # contracts and pinned tables for the pack loader
RT="$HERE/bin/ulpf-runtime"; CM="$HERE/bin/ulpf-committer"; VF="$HERE/bin/ulpf-verify"
STATE="$B/state-real"; rm -rf "$STATE"; mkdir -p "$STATE/step5" "$STATE/step6"
# steps 1–4 are the recording: copy their artifacts so the UI has them
for d in step1 step2 step3 step4 packs source-packs p6 preflight.json; do [ -e "$B/capture/state/$d" ] && cp -r "$B/capture/state/$d" "$STATE/"; done
python3 - "$B/capture/status.json" "$STATE/status.json" <<'EOF'
import json, sys
st = json.load(open(sys.argv[1])); st["real_mode"] = True
for k in ("5", "6"): st["steps"].pop(k, None)
json.dump(st, open(sys.argv[2], "w"), indent=1)
EOF
mark() { python3 - "$STATE/status.json" "$1" "$2" "$3" "${4:-}" <<'EOF'
import json, sys, time
p, step, state, title, secs = sys.argv[1:6]
st = json.load(open(p)); s = st["steps"].setdefault(step, {}); s["title"] = title; s["state"] = state
if secs: s["seconds"] = float(secs)
if state == "running": st["current"] = step
json.dump(st, open(p, "w"), indent=1)
EOF
}
PORT=6514; N=$(grep -c '' "$CAPFILE"); TOTAL=$((N + 3))
TRUST="$HERE/keys/trust"; KEY="$HERE/keys/dev/ulpf-committer-dev.json"
PACKS=(--pack "$STATE/p6/source-packs/cisco-asa" --pack "$STATE/p6/source-packs/panos" --pack "$STATE/p6/source-packs/fortigate" --pack "$STATE/source-packs/squid")
echo "================ step 5 (REAL on this machine): mixed stream, $N lines from $CAPFILE"
mark 5 running "Mixed stream: four packs, one runtime (real)"
t0=$(date +%s.%N)
"$RT" run "${PACKS[@]}" --trust "$TRUST" --contracts "$ULPF_ROOT/contracts" --pinned "$ULPF_ROOT/ocsf/pinned/index.json" \
   --source-id mixed-relay-01 --listen "tcp:127.0.0.1:$PORT" --max-frames "$TOTAL" --silence-after 4s --idle-timeout 20s \
   --evidence "$STATE/ev" --out "$STATE/step5/out.jsonl" --quarantine "$STATE/step5/q.jsonl" --ml-out "$STATE/step5/ml.jsonl" 2> "$STATE/step5/runtime.err" &
RTPID=$!; sleep 0.7
kill -0 $RTPID 2>/dev/null || { cat "$STATE/step5/runtime.err"; exit 1; }
( while kill -0 $RTPID 2>/dev/null; do "$VF" gaps --evidence "$STATE/ev" --trust "$TRUST" --json > "$STATE/step5/gaps.json.tmp" 2>/dev/null && mv "$STATE/step5/gaps.json.tmp" "$STATE/step5/gaps.json"; sleep 1; done ) &
python3 "$HERE/sender.py" "$PORT" "$CAPFILE" "$STATE/step5/progress.json" 12 &
wait $RTPID; rc=$?
"$VF" gaps --evidence "$STATE/ev" --trust "$TRUST" --json > "$STATE/step5/gaps.json" 2>/dev/null
[ $rc -eq 0 ] || { cat "$STATE/step5/runtime.err"; exit 1; }
grep -E '^\{' "$STATE/step5/runtime.err" | tail -1 > "$STATE/step5/stats.json"
python3 -c 'import json,sys; st=json.load(open(sys.argv[1])); print(f"frames {st[\"frames\"]}  emitted {st[\"emitted\"]}  quarantined {st[\"quarantined\"]}  drift {st[\"drift_signals\"]}  gap records {st[\"gap_records\"]} {st[\"gap_kinds\"]}"); print("by family:", json.dumps(st["emitted_by_family"]))' "$STATE/step5/stats.json" | tee "$STATE/step5/summary.txt"
"$VF" gaps --evidence "$STATE/ev" --trust "$TRUST" | tee "$STATE/step5/gaps.txt"
mark 5 done "Mixed stream: four packs, one runtime (real)" "$(python3 -c 'import sys,time; print(round(time.time()-float(sys.argv[1]),1))' "$t0")"
echo "================ step 6 (REAL on this machine): commit, verify, export, in-process witness, tamper"
mark 6 running "Tamper and suppression (real, in-process witness)"
t0=$(date +%s.%N); D="$STATE/step6"; EV="$STATE/ev"
ULPF_COMMIT_SEALED=1 "$CM" commit --evidence "$EV" --key "$KEY" 2>/dev/null | tee "$D/commit.json" | cut -c1-160
"$CM" daily --evidence "$EV" --key "$KEY" | tee "$D/daily.txt"
"$VF" evidence --evidence "$EV" --trust "$TRUST" | tee "$D/verify-before.txt"
EVID=$(python3 -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1])][3]["event_id"])' "$EV/seg_00000.idx.jsonl")
GAPID=$(python3 -c 'import json,sys; rs=[json.loads(l) for l in open(sys.argv[1])]; print(next((r["event_id"] for r in rs if r["record"]["kind"]=="silence"), ""))' "$STATE/step5/gaps.json")
"$RT" export --evidence "$EV" --event-id "$EVID" --out "$D/bundle-event" 2>&1 | tee "$D/export.txt"
[ -n "$GAPID" ] && "$RT" export --evidence "$EV" --event-id "$GAPID" --out "$D/bundle-gap" 2>&1 | tee -a "$D/export.txt"
"$VF" bundle --bundle "$D/bundle-event" --trust "$TRUST" 2>&1 | sed 's/^/WITNESS (in-process, no container): /' | tee "$D/witness-bundle-event.txt"
[ -n "$GAPID" ] && "$VF" bundle --bundle "$D/bundle-gap" --trust "$TRUST" 2>&1 | sed 's/^/WITNESS (in-process, no container): /' | tee "$D/witness-bundle-gap.txt"
python3 - "$EV/seg_00000.raw" 8 "$D/tamper.json" <<'EOF'
import json, sys, os
raw, off, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
b = bytearray(open(raw, "rb").read()); lo, hi = max(0, off - 24), min(len(b), off + 24)
before = bytes(b[lo:hi]); orig = b[off]; b[off] ^= 1; os.chmod(raw, 0o644); open(raw, "wb").write(bytes(b)); after = bytes(b[lo:hi])
json.dump({"file": os.path.basename(raw), "offset": off, "window_start": lo, "before_hex": before.hex(), "after_hex": after.hex(),
           "before_text": before.decode("latin-1"), "after_text": after.decode("latin-1"), "original_byte": orig, "tampered_byte": b[off]}, open(out, "w"), indent=1)
print(f"byte {off}: 0x{orig:02x} -> 0x{b[off]:02x}")
EOF
"$VF" evidence --evidence "$EV" --trust "$TRUST" | tee "$D/verify-after.txt"
"$VF" gaps --evidence "$EV" --trust "$TRUST" | tee "$D/gaps-after.txt"
python3 - "$D" <<'EOF'
import json, sys, re, os
d = sys.argv[1]; ck = json.load(open(f"{d}/commit.json")); va = open(f"{d}/verify-after.txt").read(); leaf = re.search(r"tampered (leaf .*)", va)
rd = lambda n: open(f"{d}/{n}").read() if os.path.exists(f"{d}/{n}") else "(none)"
json.dump({"checkpoint_id": ck["checkpoint"]["checkpoint_id"], "commit_mode": ck["checkpoint"].get("commit_mode"), "committed": ck["committed"],
           "verify_before": rd("verify-before.txt"), "verify_after": va, "tampered_leaf": leaf.group(1) if leaf else None,
           "witness_event": rd("witness-bundle-event.txt"), "witness_gap": rd("witness-bundle-gap.txt"), "export": rd("export.txt"),
           "tamper": json.load(open(f"{d}/tamper.json")), "gaps_after": rd("gaps-after.txt")}, open(f"{d}/result.json", "w"), indent=1)
EOF
mark 6 done "Tamper and suppression (real, in-process witness)" "$(python3 -c 'import sys,time; print(round(time.time()-float(sys.argv[1]),1))' "$t0")"
echo "real mode done: state-real/ written. Now: python3 serve.py --real"
