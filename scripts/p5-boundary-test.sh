#!/usr/bin/env bash
# P5 privilege-boundary test — REAL, not a flag check. Two containers over one ext4 volume:
#   store     runs as root WITH CAP_LINUX_IMMUTABLE: ingests, seals, sets FS_IMMUTABLE_FL through the kernel ioctl
#   committer runs as an unprivileged user with ALL capabilities dropped and the volume mounted READ-WRITE:
#             commits roots and signs checkpoints — and is asked to append to, truncate, rename, delete and
#             un-flag a sealed segment. Every attempt must be refused by the kernel (EPERM), not by a mount
#             option; then the committer is shown able to READ the same bytes. A root shell WITHOUT the
#             capability is tried too: the flag holds against root.
# Also: the ordering rule (an OPEN segment is refused by the committer by name), and the verifier.
# Needs: Docker, the runtime image built by scripts/p2-check.sh (or built here), keys/ present.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
status=0
VOL=ulpf-p5-evidence     # the store's volume: written by the store, flagged immutable, READ by the committer
CVOL=ulpf-p5-commit      # the committer's volume: roots and signed checkpoints; the store never touches it
cleanup() {
  # immutable files cannot be removed by anyone without the capability — not even docker volume rm
  docker run --rm --user 0 --cap-add LINUX_IMMUTABLE -v "$VOL:/ev" alpine:3.20 sh -c 'for f in /ev/*; do chattr -i "$f" 2>/dev/null; done' >/dev/null 2>&1
  docker volume rm -f "$VOL" "$CVOL" >/dev/null 2>&1
}
cleanup
docker volume create "$VOL" >/dev/null
docker volume create "$CVOL" >/dev/null
# the committer runs as distroless nonroot (65532): give it its own volume
docker run --rm --user 0 -v "$CVOL:/commit" alpine:3.20 chown 65532:65532 /commit
export DOCKER_BUILDKIT=1
docker build -q -f runtime/Dockerfile --target runtime -t ulpf-runtime . >/dev/null || { echo "runtime image build failed"; exit 1; }
docker build -q -f runtime/Dockerfile --target committer -t ulpf-committer . >/dev/null || { echo "committer image build failed"; exit 1; }
docker build -q -f runtime/Dockerfile --target verify -t ulpf-verify . >/dev/null || { echo "verify image build failed"; exit 1; }

echo "=== 1. store (root + CAP_LINUX_IMMUTABLE): ingest the golden samples, seal, flag immutable"
# small segments so several seal during one run; the last one stays OPEN on purpose (no Close before exit? Run closes; so we ingest twice: the second run leaves nothing open — instead we create an OPEN segment by writing a partial one below)
docker run --rm --user 0 --cap-add LINUX_IMMUTABLE --network none \
  -v "$VOL:/ev" -v "$PWD/contracts/golden/squid-native:/pack:ro" -v "$PWD/ocsf/pinned:/ocsf/pinned:ro" -v "$PWD/keys/trust:/keys/trust:ro" \
  ulpf-runtime run --pack /pack --input /pack/samples/access.log --evidence /ev --out /dev/null --contracts /contracts --pinned /ocsf/pinned/index.json --trust /keys/trust \
  --deterministic-ids --fixed-clock-ms 1734567890481 2>/dev/null
# make an OPEN segment by hand: raw+idx without a seal manifest (what a crashed writer leaves behind)
docker run --rm --user 0 -v "$VOL:/ev" alpine:3.20 sh -c 'printf "open event\n" > /ev/seg_00009.raw; printf "{\"event_id\":\"ev_open\",\"raw_hash\":\"sha256:0\",\"segment_id\":\"seg_00009\",\"offset\":0,\"length\":11}\n" > /ev/seg_00009.idx.jsonl'
docker run --rm --user 0 -v "$VOL:/ev" alpine:3.20 sh -c 'ls -la /ev; lsattr /ev/seg_00000.raw /ev/seg_00000.idx.jsonl /ev/seg_00000.seal.json 2>&1' | sed 's/^/  /'
if docker run --rm --user 0 -v "$VOL:/ev" alpine:3.20 lsattr /ev/seg_00000.raw | grep -q -- '----i'; then echo "  ok: sealed segment carries the kernel immutable flag"; else echo "  FAIL: immutable flag not set (does the store run with CAP_LINUX_IMMUTABLE on an ext4 volume?)"; status=1; fi

echo "=== 2. committer (uid 65532, --cap-drop ALL, volume rw): commit; the OPEN segment must be refused by name"
docker run --rm --cap-drop ALL --network none -v "$VOL:/ev" -v "$CVOL:/commit" -v "$PWD/keys/dev:/keys/dev:ro" ulpf-committer commit --evidence /ev --commit /commit --key /keys/dev/ulpf-committer-dev.json > /tmp/ulpf-p5-commit.json
sed 's/^/  /' /tmp/ulpf-p5-commit.json | cut -c1-400
grep -q '"seg_00009":"open' /tmp/ulpf-p5-commit.json && echo "  ok: open segment refused (ordering rule)" || { echo "  FAIL: open segment not refused"; status=1; }
grep -q '"committed":\["seg_00000"' /tmp/ulpf-p5-commit.json && echo "  ok: immutable segment committed" || { echo "  FAIL: nothing committed"; status=1; }

echo "=== 3. the committer's process tries to modify sealed evidence (same uid/caps as the committer, volume rw)"
docker run --rm --cap-drop ALL --user 65532 -v "$VOL:/ev" alpine:3.20 sh -c '
  f=/ev/seg_00000.raw; r=0
  (echo tamper >> $f) 2>/dev/null && { echo "  FAIL: append succeeded"; r=1; } || echo "  ok: append refused"
  (: > $f) 2>/dev/null && { echo "  FAIL: truncate succeeded"; r=1; } || echo "  ok: truncate refused"
  mv $f /ev/x.raw 2>/dev/null && { echo "  FAIL: rename succeeded"; r=1; } || echo "  ok: rename refused"
  rm -f $f 2>/dev/null; [ -f $f ] && echo "  ok: delete refused" || { echo "  FAIL: delete succeeded"; r=1; }
  chattr -i $f 2>/dev/null; lsattr $f | grep -q -- "----i" && echo "  ok: cannot clear the immutable flag" || { echo "  FAIL: flag cleared"; r=1; }
  head -c 40 $f >/dev/null && echo "  ok: can still READ the sealed bytes (verification needs that)"
  exit $r' || status=1

echo "=== 4. root WITHOUT the capability tries the same"
docker run --rm --user 0 -v "$VOL:/ev" alpine:3.20 sh -c '
  f=/ev/seg_00000.raw; r=0
  (echo tamper >> $f) 2>/dev/null && { echo "  FAIL: root appended"; r=1; } || echo "  ok: root append refused"
  (: > $f) 2>/dev/null && { echo "  FAIL: root truncated"; r=1; } || echo "  ok: root truncate refused"
  mv $f $f.moved 2>/dev/null && { echo "  FAIL: root renamed"; r=1; } || echo "  ok: root rename refused"
  rm -f $f 2>/dev/null; [ -s $f ] && echo "  ok: root delete refused (file still there, non-empty)" || { echo "  FAIL: root deleted or emptied the segment"; r=1; }
  chattr -i $f 2>/dev/null; lsattr $f | grep -q -- "----i" && echo "  ok: root cannot clear the flag without CAP_LINUX_IMMUTABLE" || { echo "  FAIL: root cleared the flag"; r=1; }
  exit $r' || status=1

echo "=== 5. verifier over both volumes (read-only, no capability, no key material but the trust store)"
docker run --rm --cap-drop ALL --network none -v "$VOL:/ev:ro" -v "$CVOL:/commit:ro" -v "$PWD/keys/trust:/keys/trust:ro" ulpf-verify evidence --evidence /ev --commit /commit --trust /keys/trust | sed 's/^/  /' || status=1

echo "=== 6. a process WITH the capability tampers one byte (the only way in), then the verifier names the leaf"
docker run --rm --user 0 --cap-add LINUX_IMMUTABLE -v "$VOL:/ev" alpine:3.20 sh -c 'chattr -i /ev/seg_00000.raw && printf "X" | dd of=/ev/seg_00000.raw bs=1 seek=5 conv=notrunc 2>/dev/null && chattr +i /ev/seg_00000.raw && echo "  (tampered byte 5 of seg_00000.raw with the capability)"'
docker run --rm --cap-drop ALL --network none -v "$VOL:/ev:ro" -v "$CVOL:/commit:ro" -v "$PWD/keys/trust:/keys/trust:ro" ulpf-verify evidence --evidence /ev --commit /commit --trust /keys/trust | sed 's/^/  /'
docker run --rm --cap-drop ALL --network none -v "$VOL:/ev:ro" -v "$CVOL:/commit:ro" -v "$PWD/keys/trust:/keys/trust:ro" ulpf-verify evidence --evidence /ev --commit /commit --trust /keys/trust >/dev/null 2>&1 && { echo "  FAIL: tamper not detected"; status=1; } || echo "  ok: verifier fails and names the tampered leaf"

cleanup
[ $status -eq 0 ] && echo "P5 BOUNDARY: PASS" || echo "P5 BOUNDARY: FAIL"
exit $status
