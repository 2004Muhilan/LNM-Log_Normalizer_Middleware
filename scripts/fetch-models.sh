#!/usr/bin/env bash
# Fetch every manifest model into models/cache (git-ignored), digest-verified, resumable. ~27 GB.
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/.."
python learning/tools/models.py fetch --all "$@"
python learning/tools/models.py list
