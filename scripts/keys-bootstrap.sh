#!/usr/bin/env bash
# Idempotent key bootstrap (P5 boundary decision 2): the DEV signing key pairs are generated locally and
# never committed — no private key material in git, no seed either (a seed is a private key wearing
# another name). Each clone gets its own dev authorities; the golden pack.json is byte-identical across
# clones and is re-signed here with the local key, so pack.json.sig is local and git-ignored.
# Called by every scripts/pN-check.sh and by the clean-clone test after wsl-bootstrap.
set -euo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
(cd runtime && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime && go build -o bin/ulpf-committer ./cmd/ulpf-committer && go build -o bin/ulpf-verify ./cmd/ulpf-verify \
   && go build -o bin/ulpf-tlog ./cmd/ulpf-tlog && go build -o bin/ulpf-witness ./cmd/ulpf-witness)
mkdir -p keys/dev keys/trust
for a in ulpf-pack-authority-dev ulpf-committer-dev; do
  if [ ! -f "keys/dev/$a.json" ] || [ ! -f "keys/trust/$a.pub.json" ] || [ "${FORCE:-0}" = 1 ]; then
    runtime/bin/ulpf-committer keygen --authority "$a" --out "keys/dev/$a.json" --pub "keys/trust/$a.pub.json"
  fi
done
# the Parser Transparency Log (2026-09-27): the log's key (origin ulpf-tlog-dev) and the witness's key (ulpf-witness-dev);
# their verifier keys go to the trust store (*.vkey) — the runtime refuses any pack whose inclusion proof does not verify
for k in "ulpf-tlog-dev log" "ulpf-witness-dev witness"; do
  set -- $k
  if [ ! -f "keys/dev/$1.json" ] || [ ! -f "keys/trust/$1.vkey" ] || [ "${FORCE:-0}" = 1 ]; then
    runtime/bin/ulpf-tlog keygen --name "$1" --kind "$2" --key "keys/dev/$1.json" --vkey "keys/trust/$1.vkey" > /dev/null
  fi
done
python - <<'EOF'
import sys; sys.path.insert(0, "learning")
from ulpf_learn.signing import sign_pack, verify_pack
from pathlib import Path
sign_pack(Path("contracts/golden/squid-native"), produced_by="hand-written"); verify_pack(Path("contracts/golden/squid-native"))
print("golden pack signed with the local dev authority and logged in the parser transparency log")
EOF
