#!/usr/bin/env bash
# Reproducibility test: fresh clone into a separate directory, bootstrap, refetch every cache from
# the pinned commits/hashes, and confirm the committed catalogue and pinned tables reproduce byte
# for byte and that the P1 checks give the same result. Usage: clean-clone-test.sh <clone-url-or-path> [dir]
set -uo pipefail
SRC="${1:?clone url or path}"
DIR="${2:-/tmp/ulpf-clean-clone}"
rm -rf "$DIR"
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

echo "=== bootstrap (idempotent)"
bash scripts/wsl-bootstrap.sh >/dev/null 2>&1 && echo "bootstrap ok" || { echo "bootstrap failed"; exit 1; }
source "$HOME/.ulpf-env"

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
