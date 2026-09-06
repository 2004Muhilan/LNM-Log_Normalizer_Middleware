#!/usr/bin/env bash
# Developer bootstrap for WSL2 (Ubuntu). No root required.
# Installs a pinned Go toolchain under ~/sdk and a Python venv under ~/.venvs/ulpf, and writes the env
# file the scripts source. Every location is overridable so the clean-clone test can build a genuinely
# fresh venv and env file instead of reusing the developer's (the reuse hid an undeclared dependency,
# `cryptography`, until the first run on a fresh machine — fix pass 2026-09-07):
#   ULPF_SDK       Go SDK root            (default ~/sdk; shared across clones — Go is pinned by go.mod/go.sum)
#   ULPF_VENV      Python venv            (default ~/.venvs/ulpf)
#   ULPF_ENV_FILE  env file to write      (default ~/.ulpf-env; every script sources ${ULPF_ENV_FILE:-~/.ulpf-env})
# Python dependencies come from learning/requirements.txt — the single declaration, also used by the
# learning image — plus pytest for the suites.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

GO_VERSION="${GO_VERSION:-}"
SDK="${ULPF_SDK:-$HOME/sdk}"
VENV="${ULPF_VENV:-$HOME/.venvs/ulpf}"
ENV_FILE="${ULPF_ENV_FILE:-$HOME/.ulpf-env}"

if [ -z "$GO_VERSION" ]; then
  GO_VERSION="$(curl -sS 'https://go.dev/dl/?mode=json' | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["version"])')"
fi

if [ ! -x "$SDK/$GO_VERSION/bin/go" ]; then
  mkdir -p "$SDK"
  echo "downloading $GO_VERSION"
  curl -sSL "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz" -o "/tmp/${GO_VERSION}.tgz"
  rm -rf "$SDK/$GO_VERSION"
  mkdir -p "$SDK/$GO_VERSION"
  tar -C "$SDK/$GO_VERSION" --strip-components=1 -xzf "/tmp/${GO_VERSION}.tgz"
  rm -f "/tmp/${GO_VERSION}.tgz"
fi
ln -sfn "$SDK/$GO_VERSION" "$SDK/go"
echo "go: $("$SDK/go/bin/go" version)"

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r learning/requirements.txt "pytest>=8"
echo "python: $("$VENV/bin/python" --version)  venv: $VENV"
"$VENV/bin/python" - <<'EOF'
import importlib.metadata as md
import jsonschema, re2, yaml, cryptography  # every runtime import of the learning plane, by name
for pkg in ("jsonschema", "google-re2", "pyyaml", "cryptography", "pytest"):
    print(f"  {pkg} {md.version(pkg)}")
EOF

cat > "$ENV_FILE" <<EOF
export PATH="$SDK/go/bin:\$HOME/go/bin:$VENV/bin:\$PATH"
export GOFLAGS=-mod=mod
EOF
echo "env file written: $ENV_FILE (source it, or use scripts/wsl-run.sh)"
