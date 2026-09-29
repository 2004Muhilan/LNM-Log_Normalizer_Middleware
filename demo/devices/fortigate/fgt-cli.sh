#!/usr/bin/env bash
# One SSH session on the lab FortiGate (key auth on admin, never the password), commands from the arguments, one per
# argument. Runs in the Containerlab distro; from the ULPF side: wsl.exe -d Containerlab -- bash …/fgt-cli.sh "get system status"
# Every session is itself real device output: FortiOS logs the admin's login and logout as system events.
printf '%s\n' "$@" | ssh -o BatchMode=yes -o ConnectTimeout=10 -T admin@172.20.20.2 2>&1 | tr -d '\r'
