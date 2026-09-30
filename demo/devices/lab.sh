#!/usr/bin/env bash
# The device-side actions of the real-device demo, one entry point — the System page calls it (demo/apps/devices.py);
# a person can too. RUNS IN THE `Containerlab` WSL distro:
#
#     wsl -d Containerlab -- bash …/demo/devices/lab.sh status
#
#   status                       key=value lines: licence, serial, FortiOS, syslog (status/server/port/format), containers
#   fgt-connect [format]         FortiGate syslog ON to ULPF (172.20.20.1:6515, TCP reliable) — its ingress connector
#   fgt-disconnect               FortiGate syslog OFF
#   fgt-format default|json|csv|cef   live format switch (real drift)
#   fgt-logins N                 N admin SSH sessions: each is a real login + logout system event
#   ids-connect | ids-disconnect Suricata's forwarder (rsyslog, 172.20.20.11 -> ULPF) started / stopped
#   attack                       a burst of attack traffic from fgt-client through the FortiGate: Telnet/SMB/RDP attempts
#                                and the web attack — denied and logged by the FortiGate, alerted on by Suricata
#
# FortiGate over SSH with the admin key (never the password). Every commit of `config log syslogd setting` asks to confirm
# the non-default port: the "y" after "end" answers it, or FortiOS silently falls back to 514. NEVER containerlab
# deploy/destroy here: the licence is bound to this VM.
set -uo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
fgt() { printf '%s\n' "$@" | ssh -o BatchMode=yes -o ConnectTimeout=10 -T admin@172.20.20.2 2>&1 | tr -d '\r' | sed -E 's/^[A-Za-z0-9_-]+ (\([a-z]+\) )?# //'; }
syslog_set() { fgt "config log syslogd setting" "$@" "end" "y" "get log syslogd setting" | grep -E "^(status|server|port|mode|format) " | sed 's/ *: */=/;s/^/syslog_/'; }

case "${1:-status}" in
  status)
    out=$(fgt "get system status" "get log syslogd setting")
    grep -E "^(Version|Serial-Number|License Status|License Expiration Date):" <<< "$out" | sed 's/: /=/;s/ /_/g;s/^/fgt_/'
    grep -E "^(status|server|port|mode|format) " <<< "$out" | sed 's/ *: */=/;s/^/syslog_/'
    for c in clab-fortigate-fgt fgt-client fgt-server fgt-ids fgt-ids-syslog; do
      echo "container_$c=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
    done
    echo "traffic_loop=$(docker exec fgt-client sh -c 'pgrep -f "[s]h /traffic.sh" >/dev/null && echo running || echo stopped' 2>/dev/null || echo unknown)"
    echo "keepalive=$(pgrep -f '[u]lpf-clab-keepalive' > /dev/null && echo running || echo none)"
    ;;
  fgt-connect)
    syslog_set "set status enable" 'set server "172.20.20.1"' "set mode reliable" "set port 6515" ${2:+"set format $2"} ;;
  fgt-disconnect)
    syslog_set "set status disable" ;;
  fgt-format)
    case "${2:-}" in default|json|csv|cef) ;; *) echo "format: default|json|csv|cef"; exit 2 ;; esac
    syslog_set "set status enable" "set port 6515" "set format $2" ;;
  fgt-logins)
    for _ in $(seq 1 "${2:-8}"); do fgt "get system status" > /dev/null; done; echo "logins=${2:-8}" ;;
  ids-connect)
    docker start fgt-ids-syslog > /dev/null && docker start fgt-ids > /dev/null
    for _ in $(seq 1 20); do docker exec fgt-ids-syslog test -S /run/ulpf-log/log 2>/dev/null && break; sleep 0.5; done
    echo "ids_forwarder=$(docker inspect -f '{{.State.Status}}' fgt-ids-syslog)" ;;
  ids-disconnect)
    docker stop -t 2 fgt-ids-syslog > /dev/null; echo "ids_forwarder=$(docker inspect -f '{{.State.Status}}' fgt-ids-syslog)" ;;
  attack)
    docker exec fgt-client sh -c 'S=172.20.20.10; for i in 1 2 3 4 5; do for p in 23 445 3389; do nc -z -w 1 $S $p; done;
      wget -q -T 2 -U "sqlmap/1.7.2#stable" -O /dev/null "http://$S/cgi-bin/view?file=../../../../etc/passwd"; done 2>/dev/null; true'
    echo "attack=sent" ;;
  *) sed -n 2,17p "$0"; exit 2 ;;
esac
