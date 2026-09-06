#!/usr/bin/env bash
# Step 1 — family discovery: the mixed capture (four vendors, six families, three adversarial lines),
# clustered by the router's own surface (no parser, no pack), ranked by volume.
source "$(dirname "$(readlink -f "$0")")/../lib.sh"
cd "$ROOT"
step_begin 1 "Family discovery"
CAP="$STATE/p6/mixed.log"
[ -f "$CAP" ] || step_fail "no mixed capture: run demo/reset.sh"
cp "$CAP" "$STATE/step1/capture.log"
(cd learning && python tools/discover.py "$CAP" --top 12 --json "$STATE/step1/discovery.json") | tee "$STATE/step1/discovery.txt" || step_fail "discover.py"
n=$(grep -c '' "$CAP")
step_end "$n lines, $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$STATE/step1/discovery.json") families ranked"
