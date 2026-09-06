#!/usr/bin/env bash
# Fetch every manifest model into models/cache (git-ignored), digest-verified, resumable. ~27 GB.
set -uo pipefail
source "${ULPF_ENV_FILE:-$HOME/.ulpf-env}"
cd "$(dirname "$(readlink -f "$0")")/.."
python learning/tools/models.py fetch --all "$@"
python learning/tools/models.py list
