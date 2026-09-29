#!/usr/bin/env bash
# Switch the FortiGate's syslog format LIVE — real drift, from the vendor's own code paths:
#
#     wsl -d Containerlab -- bash .../demo/devices/fortigate/syslog-format.sh default|csv|cef|json|rfc5424
#
# Nothing else changes: same device, same connection target, same traffic. Over SSH with the admin key (no password).
set -euo pipefail
f="${1:?default|csv|cef|json|rfc5424}"
case "$f" in default|csv|cef|json|rfc5424) ;; *) echo "unknown format $f"; exit 2 ;; esac
# every commit of this block asks again to confirm the non-default port (6515): the "y" after "end" answers it — without
# it FortiOS silently falls back to port 514 and ULPF hears nothing
printf 'config log syslogd setting\nset port 6515\nset format %s\nend\ny\nget log syslogd setting\n' "$f" |
  ssh -o BatchMode=yes -o ConnectTimeout=10 -T admin@172.20.20.2 2>&1 | tr -d '\r' | grep -E "^(format|port|mode|server) " || true
echo "$(date -u +%FT%TZ) FortiGate syslog format -> $f"
