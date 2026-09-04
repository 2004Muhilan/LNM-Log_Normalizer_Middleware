#!/usr/bin/env bash
set -uo pipefail
source "$HOME/.ulpf-env"
cd "$(dirname "$(readlink -f "$0")")/.."
python drafts/sufficiency/check_drafts.py 2>&1 | grep -v "absl::InitializeLog"
