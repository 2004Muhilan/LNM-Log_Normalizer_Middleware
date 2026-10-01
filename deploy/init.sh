#!/usr/bin/env bash
# ULPF INIT — one-shot, before anything else starts (2026-10-01). Runs as root with CAP_LINUX_IMMUTABLE (to wipe a state
# whose sealed evidence the kernel made immutable) and nothing else.
#
#   1. this installation's OWN keys, generated once into the keys volume, never in an image: the pack authority (packs this
#      installation onboards or heals), the committer, the transparency log, the witness. Public halves -> the trust volume,
#      with the release authority's public key (the shipped packs).
#   2. the shipped packs (release-signed, inside the image) -> the packs volume, each APPENDED to this installation's own
#      transparency log: the runtime loads nothing that is not in the log, shipped packs included.
#   3. ULPF_FRESH=1: a fresh state (the demo starts from nothing every time; a deployment keeps its state).
set -euo pipefail
cd /ulpf
BIN=/ulpf/runtime/bin K=/ulpf/keys/dev T=/ulpf/keys/trust NONROOT=65532
mkdir -p "$K" "$T" /ulpf/packs /ulpf/tlog /state
chmod 700 "$K"
for a in ulpf-pack-authority-dev ulpf-committer-dev; do
  [ -f "$K/$a.json" ] && [ -f "$T/$a.pub.json" ] || "$BIN/ulpf-committer" keygen --authority "$a" --out "$K/$a.json" --pub "$T/$a.pub.json"
done
for k in "ulpf-tlog-dev log" "ulpf-witness-dev witness"; do
  set -- $k
  [ -f "$K/$1.json" ] && [ -f "$T/$1.vkey" ] || "$BIN/ulpf-tlog" keygen --name "$1" --kind "$2" --key "$K/$1.json" --vkey "$T/$1.vkey" > /dev/null
done
cp /ulpf/release/trust/*.pub.json "$T/"
# the committer and the witness run as the distroless nonroot user: each reads its own key, and only its own
chmod 600 "$K"/*.json; chmod 711 "$K"
chown "$NONROOT" "$K/ulpf-committer-dev.json" "$K/ulpf-witness-dev.json"
chmod 644 "$T"/*

if [ "${ULPF_FRESH:-0}" = 1 ] && [ -d /state/app ]; then
  chattr -R -i /state/app 2>/dev/null || true
  rm -rf /state/app
  echo "init: fresh state"
fi
mkdir -p /state/app/evidence-archive /state/witness
chown "$NONROOT" /state/app/evidence-archive /state/witness

for src in /ulpf/release/packs/*/; do
  n=$(basename "$src"); dst="/ulpf/packs/$n"
  rm -rf "$dst"; cp -r "$src" "$dst"
  how=$([ "$n" = squid-native ] && echo hand-written || echo vendor-onboarded)
  "$BIN/ulpf-tlog" append --pack "$dst" --produced-by "$how" > /dev/null
  "$BIN/ulpf-tlog" verify --pack "$dst" > /dev/null
  "$BIN/ulpf-runtime" verify-pack --pack "$dst" | tail -1 | sed "s#^#init: $n: #"
done
echo "init: keys ready ($(ls "$T" | tr '\n' ' ')); shipped packs logged; transparency log: $("$BIN/ulpf-tlog" list | tail -1)"
