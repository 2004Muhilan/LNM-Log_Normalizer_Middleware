#!/usr/bin/env bash
# Build the three runtime binaries and (re)generate the DEMO-GRADE dev key pairs (plan §1 "Signatures":
# file-based keys, no ceremony). keys/dev/*.json hold private seeds and are committed as test fixtures
# for the dev authorities only; keys/trust/*.pub.json is the trust store the runtime verifies against.
# Never reuse these keys outside the repository's own tests and demo.
set -euo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/.."
(cd runtime && gofmt -w ./internal ./cmd && go build -o bin/ulpf-runtime ./cmd/ulpf-runtime && go build -o bin/ulpf-committer ./cmd/ulpf-committer && go build -o bin/ulpf-verify ./cmd/ulpf-verify)
mkdir -p keys/dev keys/trust
for a in ulpf-pack-authority-dev ulpf-committer-dev; do
  if [ ! -f "keys/dev/$a.json" ] || [ "${FORCE:-0}" = 1 ]; then
    runtime/bin/ulpf-committer keygen --authority "$a" --out "keys/dev/$a.json" --pub "keys/trust/$a.pub.json"
  else
    echo "keeping existing key $a"
  fi
done
ls -la keys/dev keys/trust
pip install --quiet 'cryptography>=42'
python -c 'import cryptography; print("cryptography", cryptography.__version__)'
