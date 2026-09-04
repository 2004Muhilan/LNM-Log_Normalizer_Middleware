#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.ulpf-env"
go version
python --version
python -c 'import re2; print("re2 search ok:", re2.compile("a+b").search("xaab") is not None)'
python -c 'import jsonschema; from jsonschema import Draft202012Validator; print("jsonschema draft 2020-12 available")'
