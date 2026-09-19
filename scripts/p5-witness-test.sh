#!/usr/bin/env bash
# P5 external-witness test: an evidence bundle exported by a ULPF instance verifies on a container that
# has never run ULPF — it holds ONLY the standalone verifier binary, the trust-store public key, and the
# bundle. Then the bundle is tampered (one raw byte) and must fail on the witness too.
# Needs: Docker, keys/, a built runtime (scripts/p5-keygen.sh builds the binaries).
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
status=0
W=$(mktemp -d)
EV="$W/ev"; B="$W/bundle"
echo "=== 1. a ULPF instance ingests, seals and commits (unprivileged here: segments are SEALED, so the committer is told to treat sealed as committed -- the kernel boundary is the other script's job)"
runtime/bin/ulpf-runtime run --pack contracts/golden/squid-native --input contracts/golden/squid-native/samples/access.log --evidence "$EV" --out /dev/null --deterministic-ids --fixed-clock-ms 1734567890481 2>/dev/null
# In an unprivileged dev shell the flag cannot be set; use the committer's test seam: ULPF_COMMIT_SEALED=1
ULPF_COMMIT_SEALED=1 runtime/bin/ulpf-committer commit --evidence "$EV" --key keys/dev/ulpf-committer-dev.json | cut -c1-300 | sed 's/^/  /'
runtime/bin/ulpf-committer daily --evidence "$EV" --key keys/dev/ulpf-committer-dev.json | sed 's/^/  /'
echo "=== 2. one-command export of event 3"
runtime/bin/ulpf-runtime export --evidence "$EV" --event-id ev_00000000000000000000000003 --out "$B" 2>&1 | sed 's/^/  /' || status=1
ls "$B" | tr '\n' ' ' | sed 's/^/  bundle files: /'; echo
echo "=== 3. the witness: a fresh container with only ulpf-verify, the public key and the bundle (no ULPF, no network)"
DOCKER_BUILDKIT=1 docker build -q -f runtime/Dockerfile --target verify -t ulpf-verify . >/dev/null || { echo "  FAIL: the witness image did not build (refusing to test a stale ulpf-verify)"; exit 1; }
docker run --rm --network none -v "$B:/bundle:ro" -v "$PWD/keys/trust:/trust:ro" ulpf-verify bundle --bundle /bundle --trust /trust | sed 's/^/  /' || status=1
cp -r "$B" "$W/bundle-clean"; cp -r "$B" "$W/bundle-nosig"   # untampered copies: steps 5 and 6 must fail for THEIR reason only
echo "=== 4. tamper one raw byte in the bundle; the witness must refuse and say where"
python3 - "$B/event.raw" <<'EOF'
import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[3]^=1; open(p,'wb').write(b)
EOF
out=$(docker run --rm --network none -v "$B:/bundle:ro" -v "$PWD/keys/trust:/trust:ro" ulpf-verify bundle --bundle /bundle --trust /trust 2>&1); rc=$?; echo "$out" | sed 's/^/  /'
if [ $rc -ne 0 ] && echo "$out" | grep -q "FINDING event.raw" && echo "$out" | grep -q "VERIFY: FAIL"; then echo "  ok: tampered bundle refused on the witness, naming event.raw"; else echo "  FAIL: tampered bundle not refused for the tamper (rc=$rc)"; status=1; fi
echo "=== 5. an unknown authority: witness with an empty trust store"
mkdir -p "$W/empty-trust"
out=$(docker run --rm --network none -v "$W/bundle-clean:/bundle:ro" -v "$W/empty-trust:/trust:ro" ulpf-verify bundle --bundle /bundle --trust /trust 2>&1); rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -q "trust store" && ! echo "$out" | grep -q "FINDING event.raw"; then echo "  ok: an UNTAMPERED bundle is refused without the authority's public key ($(echo "$out" | grep -m1 FINDING | cut -c1-90))"; else echo "$out" | sed 's/^/  /'; echo "  FAIL: not refused for the missing authority (rc=$rc)"; status=1; fi
echo "=== 6. a bundle with its checkpoint signature file removed must FAIL (it once printed VERIFY: OK)"
rm -f "$W/bundle-nosig/checkpoint.json.sig"
out=$(docker run --rm --network none -v "$W/bundle-nosig:/bundle:ro" -v "$PWD/keys/trust:/trust:ro" ulpf-verify bundle --bundle /bundle --trust /trust 2>&1); rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -q "signature file missing" && ! echo "$out" | grep -q "VERIFY: OK"; then echo "  ok: refused: signature file missing"; else echo "$out" | sed 's/^/  /'; echo "  FAIL: a bundle without its signature verified (rc=$rc)"; status=1; fi
rm -rf "$W"
[ $status -eq 0 ] && echo "P5 WITNESS: PASS" || echo "P5 WITNESS: FAIL"
exit $status
