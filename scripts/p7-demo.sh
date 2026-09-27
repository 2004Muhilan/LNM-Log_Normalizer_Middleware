#!/usr/bin/env bash
# P7 canned demos with the built binaries and the signed golden Squid pack (no model, no corpus):
#   1. octet-counted syslog over TCP (RFC 6587), mixed with a non-transparent line and one oversized
#      message, plus a peer that disconnects mid-frame: every byte is evidence, the stream reconstructs,
#      the partial frame is retained and a connection_lost gap record sits next to it;
#   2. a batched JSON array dropped into the pull directory explodes into independently hashed events;
#   3. two UDP senders; one goes silent; the runtime appends a silence gap record; the committer commits
#      it under a signed checkpoint; `ulpf-verify gaps` displays it; the gap record is exported as a bundle
#      and verified by the witness with only the public key (in Docker when available, else in-process).
# Ports are chosen free at run time. Needs: scripts/keys-bootstrap.sh done (every pN-check does it).
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
export ULPF_ROOT="$PWD"
status=0
W=$(mktemp -d)
RT=runtime/bin/ulpf-runtime; CM=runtime/bin/ulpf-committer; VF=runtime/bin/ulpf-verify
PACK=contracts/golden/squid-native
SAMPLES=$PACK/samples/access.log
freeport() { python3 - <<'EOF'
import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
EOF
}

echo "=== 1. octet-counted syslog over TCP: counted frames, a non-transparent line, a 300 KiB message against a 64 KiB cap, a peer cut off mid-frame"
P=$(freeport)
$RT run --dev-no-evidence-archive --pack $PACK --listen "tcp:127.0.0.1:$P" --evidence "$W/ev1" --out "$W/out1.jsonl" --quarantine "$W/q1.jsonl" --max-frames 12 --idle-timeout 2s --silence-after 0 2> "$W/rt1.err" &   # 3 counted + 1 LF + 5 pieces of the big message + 1 partial + 2 counted = 12
RTPID=$!
for _ in $(seq 1 100); do grep -q "listening for syslog" "$W/rt1.err" 2>/dev/null && break; sleep 0.1; done   # the listener, not a fixed time (load)
python3 - "$P" "$SAMPLES" "$W/sent1.bin" <<'EOF'
import socket, sys, time
port, samples, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
lines = open(samples, "rb").read().rstrip(b"\n").split(b"\n")
sent = bytearray()
c = socket.create_connection(("127.0.0.1", port))
for i, l in enumerate(lines[:4]):
    msg = b"<134>Dec 19 00:00:0%d proxy01 squid[1234]: " % i + l
    if i == 2:
        frame = b"<134>Dec 19 00:00:02 proxy01 squid[1234]: " + l + b"\n"      # non-transparent (LF) frame
    else:
        frame = str(len(msg)).encode() + b" " + msg                            # RFC 6587 octet counting
    c.sendall(frame); sent += frame
big = b"<134>Dec 19 00:00:09 proxy01 squid[1234]: " + b"x" * (300 * 1024)      # over the 64 KiB cap: 5 pieces
frame = str(len(big)).encode() + b" " + big
c.sendall(frame); sent += frame
c.close()
# a second peer declares 200 bytes and disconnects after 40
c2 = socket.create_connection(("127.0.0.1", port))
partial = b"200 <134>Dec 19 00:00:05 proxy01 squid[1234]: cut"
c2.sendall(partial); sent += partial
time.sleep(0.2); c2.close()
# a third peer: two more counted lines so the runtime reaches --max-frames
c3 = socket.create_connection(("127.0.0.1", port))
for i, l in enumerate(lines[4:6]):
    msg = b"<134>Dec 19 00:00:0%d proxy01 squid[1234]: " % (i + 4) + l
    frame = str(len(msg)).encode() + b" " + msg
    c3.sendall(frame); sent += frame
c3.close()
open(out, "wb").write(bytes(sent))
EOF
wait $RTPID
grep -o '"frames":[0-9]*,"emitted":[0-9]*' "$W/rt1.err" | tail -1 | sed 's/^/  stats: /'
grep -E "tcp:" "$W/rt1.err" | sed 's/^/  /'
$RT reconstruct --evidence "$W/ev1" --out "$W/rec1.bin" 2>&1 | sed 's/^/  /'
python3 - "$W" <<'EOF' || status=1
import sys, json, glob
W = sys.argv[1]
sent = open(f"{W}/sent1.bin", "rb").read()
rec = open(f"{W}/rec1.bin", "rb").read()
# reconstruction is per-connection-ordered; the demo sent three connections sequentially, so byte order matches
ok = rec == sent
recs = []
for idx in sorted(glob.glob(f"{W}/ev1/seg_*.idx.jsonl")):
    recs += [json.loads(l) for l in open(idx)]
methods = {}
for r in recs:
    methods[r["framing"]["method"]] = methods.get(r["framing"]["method"], 0) + 1
trunc = sum(1 for r in recs if r["framing"]["truncation_status"] != "none")
gaps = [r for r in recs if r["framing"]["method"] == "gap_record"]
print(f"  records={len(recs)} methods={methods} flagged_pieces={trunc} gap_records={len(gaps)} reconstruct_byte_exact={ok}")
passed = ok and methods.get("octet_count", 0) >= 10 and methods.get("newline") == 1 and trunc >= 6 and len(gaps) == 1
print("  octet capture:", "PASS" if passed else "FAIL")
sys.exit(0 if passed else 1)   # one condition for the verdict and the status (they used to differ)
EOF

echo "=== 2. a batched JSON array dropped into the pull directory: N independently hashed events"
mkdir -p "$W/drop"
python3 - "$SAMPLES" "$W/drop/batch-001.json" <<'EOF'
import sys, json
lines = open(sys.argv[1]).read().rstrip("\n").split("\n")
# a collector batching raw lines as JSON strings (the golden pack is positional; the elements route as
# json surface and are quarantined — what the demo shows is framing, hashing and reconstruction)
open(sys.argv[2], "w").write(json.dumps(lines, indent=1) + "\n")
EOF
cp "$W/drop/batch-001.json" "$W/batch-copy.json"
$RT run --dev-no-evidence-archive --pack $PACK --pull-dir "$W/drop" --pull-once --evidence "$W/ev2" --out "$W/out2.jsonl" --quarantine "$W/q2.jsonl" 2> "$W/rt2.err"
grep -o '"received_frames":[0-9]*,"batch_elements":[0-9]*' "$W/rt2.err" | sed 's/^/  stats: /'
$RT reconstruct --evidence "$W/ev2" --out "$W/rec2.bin" 2>&1 | sed 's/^/  /'
python3 - "$W" <<'EOF' || status=1
import sys, json
W = sys.argv[1]
recs = [json.loads(l) for l in open(f"{W}/ev2/seg_00000.idx.jsonl")]
hashes = {r["raw_hash"] for r in recs}
bh = {r["framing"].get("batch_hash") for r in recs}
ok = len(recs) == 6 and len(hashes) == 6 and len(bh) == 1 and all(r["framing"]["method"] == "batch_element" for r in recs) and open(f"{W}/rec2.bin","rb").read() == open(f"{W}/batch-copy.json","rb").read()
print(f"  batch elements={len(recs)} distinct raw hashes={len(hashes)} batch hashes={bh} done-file={'yes' if __import__('os').path.exists(f'{W}/drop/batch-001.json.done') else 'no'}")
print("  batched drop:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
EOF

echo "=== 3. silencing a source: two UDP senders, one stops; the silence becomes a signed, exportable, verifiable leaf"
P=$(freeport)
$RT run --dev-no-evidence-archive --pack $PACK --listen "udp:127.0.0.1:$P" --evidence "$W/ev3" --out "$W/out3.jsonl" --quarantine "$W/q3.jsonl" --max-frames 9 --silence-after 400ms 2> "$W/rt3.err" &
RTPID=$!
for _ in $(seq 1 100); do grep -q "listening for syslog" "$W/rt3.err" 2>/dev/null && break; sleep 0.1; done   # a datagram sent before the bind is lost
python3 - "$P" "$SAMPLES" <<'EOF'
import socket, sys, time
port, samples = int(sys.argv[1]), sys.argv[2]
lines = open(samples, "rb").read().rstrip(b"\n").split(b"\n")
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); a.bind(("127.0.0.1", 0))
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b.bind(("127.0.0.1", 0))
for i in range(3):
    a.sendto(b"<134>Dec 19 00:00:01 proxyA squid[1]: " + lines[i], ("127.0.0.1", port)); time.sleep(0.05)
    b.sendto(b"<134>Dec 19 00:00:01 proxyB squid[2]: " + lines[i], ("127.0.0.1", port)); time.sleep(0.05)
time.sleep(1.2)   # B is now silent past the threshold; A resumes
for i in range(3, 6):
    a.sendto(b"<134>Dec 19 00:00:02 proxyA squid[1]: " + lines[i], ("127.0.0.1", port)); time.sleep(0.05)
EOF
wait $RTPID
grep -o '"gap_records":[0-9]*,"gap_kinds":{[^}]*}' "$W/rt3.err" | sed 's/^/  stats: /'
ULPF_COMMIT_SEALED=1 $CM commit --evidence "$W/ev3" --key keys/dev/ulpf-committer-dev.json 2>/dev/null | cut -c1-160 | sed 's/^/  /'
$VF gaps --evidence "$W/ev3" --trust keys/trust | sed 's/^/  /' || status=1
GAPID=$($VF gaps --evidence "$W/ev3" --trust keys/trust --json | python3 -c 'import sys,json; rs=[json.loads(l) for l in sys.stdin]; print(next(r["event_id"] for r in rs if r["record"]["kind"]=="silence"))')
$RT export --evidence "$W/ev3" --event-id "$GAPID" --out "$W/bundle" 2>&1 | sed 's/^/  /' || status=1
if [ "${ULPF_SKIP_DOCKER:-0}" != "1" ] && docker image inspect ulpf-verify >/dev/null 2>&1; then
  docker run --rm --network none -v "$W/bundle:/bundle:ro" -v "$PWD/keys/trust:/trust:ro" ulpf-verify bundle --bundle /bundle --trust /trust | sed 's/^/  WITNESS (docker): /' || status=1
else
  $VF bundle --bundle "$W/bundle" --trust keys/trust | sed 's/^/  WITNESS (in-process): /' || status=1
fi
python3 - "$W/bundle/bundle.json" <<'EOF' || status=1
import sys, json
b = json.load(open(sys.argv[1]))
raw = open(sys.argv[1].replace("bundle.json", b["raw_file"]), "rb").read()
g = json.loads(raw)
ok = b["record"]["framing"]["method"] == "gap_record" and g["kind"] == "silence" and g["silence_ms"] >= 400
print(f"  exported gap record: kind={g['kind']} peer={g['peer']} silence_ms={g['silence_ms']} leaf={b['leaf_index']} of {b['record']['segment_id']} checkpoint={b['checkpoint_id']}")
print("  silence demo:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
EOF
rm -rf "$W"
echo "p7-demo: $([ $status = 0 ] && echo PASS || echo FAIL)"
exit $status
