#!/usr/bin/env bash
# Reproducibility test: fresh clone into a separate directory, bootstrap INTO A FRESH VENV AND ENV FILE,
# refetch every cache from the pinned commits/hashes, and confirm the committed catalogue and pinned
# tables reproduce byte for byte and that the P1 checks give the same result.
# Usage: clean-clone-test.sh <clone-url-or-path> [dir]
#
# Fix pass 2026-09-07: this test used to source the developer's ~/.ulpf-env and therefore ran the clone
# against the developer's venv, so an undeclared Python dependency (`cryptography`, imported by the
# signing module since P5) went unnoticed until the first run on a fresh machine. Now ULPF_VENV and
# ULPF_ENV_FILE point at the clone's own paths for the whole run; the Go SDK is shared on purpose (pinned
# by go.mod/go.sum, and re-downloading it proves nothing). The test asserts the venv is really fresh.
set -uo pipefail
SRC="${1:?clone url or path}"
DIR="${2:-/tmp/ulpf-clean-clone}"
rm -rf "$DIR" "$DIR-venv"
export ULPF_VENV="$DIR-venv"
export ULPF_ENV_FILE="$DIR-env"
rm -f "$ULPF_ENV_FILE"
# Under WSL2 the private remote needs credentials that live in the Windows Git Credential Manager;
# bridge to it per-command (no global config change) when it is present.
GCM="/mnt/c/Program Files/Git/mingw64/bin/git-credential-manager.exe"
CRED=()
if [ -x "$GCM" ] && [[ "$SRC" == https://* ]]; then
  CRED=(-c "credential.helper=${GCM// /\\ }")   # absolute path => git runs it via sh; escape the space
fi
echo "=== clone $SRC -> $DIR"
GIT_TERMINAL_PROMPT=0 git "${CRED[@]}" clone --quiet "$SRC" "$DIR" || { echo "clone failed"; exit 1; }
cd "$DIR"
echo "commit: $(git rev-parse --short HEAD)  files: $(git ls-files | wc -l)"
echo "=== no caches present after clone (expected: none)"
ls corpus/cache ocsf/cache 2>&1 | head -3

echo "=== bootstrap into a fresh venv ($ULPF_VENV) and env file ($ULPF_ENV_FILE)"
bash scripts/wsl-bootstrap.sh 2>&1 | sed 's/^/  /' || { echo "bootstrap failed"; exit 1; }
# shellcheck disable=SC1090
source "$ULPF_ENV_FILE"
case "$(command -v python)" in
  "$ULPF_VENV"/bin/python) echo "fresh venv in use: $(command -v python)" ;;
  *) echo "NOT the fresh venv: $(command -v python)"; exit 1 ;;
esac
[ -e "$HOME/.venvs/ulpf" ] && python - <<'EOF'
# the developer's venv must be invisible from here: nothing on sys.path may point into it
import os, sys
dev = os.path.expanduser("~/.venvs/ulpf")
leak = [p for p in sys.path if p.startswith(dev)]
print("developer venv leaked into sys.path:", leak) if leak else print("developer venv not on sys.path")
sys.exit(1 if leak else 0)
EOF
python -c 'import jsonschema, re2, yaml, cryptography; print("learning-plane imports resolve in the fresh venv")' || { echo "import failed in the fresh venv"; exit 1; }

echo "=== keys bootstrap (dev authorities generated locally, golden pack signed)"
bash scripts/keys-bootstrap.sh >/dev/null 2>&1 && echo "keys bootstrapped locally" || { echo "key bootstrap failed"; exit 1; }

echo "=== refetch corpus from pinned commits; catalogue must reproduce"
python corpus/tools/fetch_corpus.py 2>/dev/null | tail -1
git diff --quiet -- corpus/catalogue.json && echo "catalogue.json: identical to committed" || { echo "catalogue.json DIFFERS"; git diff --stat -- corpus/catalogue.json; }

echo "=== refetch OCSF definitions; manifest and pinned tables must reproduce"
python ocsf/tools/fetch_ocsf.py >/dev/null && python ocsf/tools/build_pinned.py >/dev/null
git diff --quiet -- ocsf/pinned && echo "ocsf/pinned: identical to committed" || { echo "ocsf/pinned DIFFERS"; git diff --stat -- ocsf/pinned; }
python ocsf/tools/crosscheck_source.py | tail -1

echo "=== p1-check"
bash scripts/p1-check.sh 2>&1 | grep -E "vectors behaved|passed|^ok|FAIL"

echo "=== drafts"
bash scripts/check-drafts.sh 2>&1 | grep -E "full-match|layout-match|undeclared|declared cells"

echo "=== working tree after all checks (expected: clean)"
git status --short | head -10
[ -z "$(git status --short)" ] && echo "clean" || echo "DIRTY"
