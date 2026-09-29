#!/usr/bin/env bash
# Suricata (IDS) on the FortiGate lab's wire. RUN INSIDE THE `Containerlab` WSL distro, after the FortiGate lab is up
# (demo/devices/fortigate/start.sh — fgt-client must exist):
#
#     wsl -d Containerlab -- bash /mnt/c/.../laptop-commit-pull/demo/devices/suricata/start.sh
#
# No VM, no licence. Two containers from one image (Alpine's suricata + rsyslog packages, built here once while online):
#   fgt-ids         Suricata in fgt-client's NETWORK NAMESPACE, sniffing eth1 — the client's end of the FortiGate's port2,
#                   so it sees exactly the connections the FortiGate filters and logs (one attack, two devices). Offline
#                   ruleset: local.rules only (-S), no suricata-update. EVE JSON (alerts) through syslog(3) to /dev/log.
#   fgt-ids-syslog  rsyslog on the lab bridge (172.20.20.11): /dev/log of fgt-ids is its socket (a shared volume); it
#                   forwards to ULPF, 172.20.20.1:6515, TCP with RFC 6587 octet counting. fgt-client's own network has
#                   no path to ULPF except through the FortiGate (which would deny and log it), hence the forwarder.
# Re-running is safe: existing containers are started, not recreated. Removal: demo/devices/fortigate/teardown.ps1.
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
IMG=ulpf/suricata:alpine3.20 LABEL=ulpf.device=suricata-lab VOL=ulpf-ids-log

docker inspect fgt-client > /dev/null 2>&1 || { echo "fgt-client does not exist: start the FortiGate lab first (demo/devices/fortigate/start.sh)"; exit 1; }
docker image inspect "$IMG" > /dev/null 2>&1 || docker build -t "$IMG" --label "$LABEL" "$HERE"
docker volume inspect "$VOL" > /dev/null 2>&1 || docker volume create --label "$LABEL" "$VOL" > /dev/null

docker inspect fgt-ids-syslog > /dev/null 2>&1 || docker create --name fgt-ids-syslog --label "$LABEL" --hostname suricata-ids \
  --network clab --ip 172.20.20.11 -v "$VOL:/run/ulpf-log" -v "$HERE/rsyslog.conf:/etc/rsyslog.conf:ro" \
  "$IMG" rsyslogd -n -f /etc/rsyslog.conf > /dev/null
docker start fgt-ids-syslog > /dev/null
for _ in $(seq 1 20); do docker exec fgt-ids-syslog test -S /run/ulpf-log/log && break; sleep 0.5; done

# -k none: the veth pair hands packets over before their checksums are filled in (offload); Suricata would otherwise
# drop every TCP stream as invalid. The rules are the lab's own (-S replaces rule-files); the config is Alpine's default
# plus ulpf-suricata.yaml (HOME_NET, EVE to syslog, alerts only).
docker inspect fgt-ids > /dev/null 2>&1 || docker create --name fgt-ids --label "$LABEL" --network container:fgt-client \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_NICE -v "$VOL:/run/ulpf-log" -v "$HERE:/etc/ulpf-suricata:ro" \
  "$IMG" sh -c 'ln -sf /run/ulpf-log/log /dev/log && exec suricata -c /etc/suricata/suricata.yaml --include /etc/ulpf-suricata/ulpf-suricata.yaml -S /etc/ulpf-suricata/local.rules -i eth1 -k none' > /dev/null
docker start fgt-ids > /dev/null
for _ in $(seq 1 60); do docker logs fgt-ids 2>&1 | grep -q "Engine started" && break; sleep 1; done
docker logs fgt-ids 2>&1 | grep -E "This is Suricata|rules successfully loaded|Engine started|[Ee]rror" | tail -5
echo "Suricata up: sniffing fgt-client eth1 (the FortiGate's port2 wire); EVE alerts -> rsyslog 172.20.20.11 -> 172.20.20.1:6515 (TCP)"
