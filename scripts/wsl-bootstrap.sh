#!/usr/bin/env bash
# Developer bootstrap for WSL2 (Ubuntu). No root required.
# Installs a pinned Go toolchain under ~/sdk and a Python venv under ~/.venvs/ulpf.
set -euo pipefail

GO_VERSION="${GO_VERSION:-}"
SDK="$HOME/sdk"
VENV="$HOME/.venvs/ulpf"

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
"$VENV/bin/pip" install --quiet "jsonschema>=4.23" "google-re2>=1.1" "pyyaml>=6" "pytest>=8"
echo "python: $("$VENV/bin/python" --version)"
"$VENV/bin/python" - <<'EOF'
import jsonschema, re2, yaml
print("jsonschema", jsonschema.__version__ if hasattr(jsonschema, "__version__") else "ok")
print("re2", re2.__version__ if hasattr(re2, "__version__") else "ok")
EOF

cat > "$HOME/.ulpf-env" <<EOF
export PATH="$SDK/go/bin:\$HOME/go/bin:$VENV/bin:\$PATH"
export GOFLAGS=-mod=mod
EOF
echo "env file written: ~/.ulpf-env (source it, or use scripts/wsl-run.sh)"
