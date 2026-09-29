#!/usr/bin/env bash
# Start the lab FortiGate (a real FortiOS 7.4.12 VM, evaluation licence) and the small network behind it.
# RUN INSIDE THE `Containerlab` WSL distro (its own Docker engine, separate from Docker Desktop):
#
#     wsl -d Containerlab -- bash /mnt/c/.../laptop-commit-pull/demo/devices/fortigate/start.sh
#
# THE LICENCE. There is one free evaluation per account and it is bound to this VM:
#   * only `docker start` / `docker stop` on clab-fortigate-fgt — NEVER `containerlab deploy` or `destroy` (a new firewall,
#     a new serial number);
#   * vrnetlab.py inside the container is patched (patch-vrnetlab.py, idempotent): the VM UUID is pinned to the one the
#     licence was activated with, and the VM gets one data NIC (port2) for the traffic container;
#   * the Containerlab distro stops when nothing runs in it, and the FortiGate with it: keep a process alive there
#     (this script leaves one: `sleep infinity` under setsid).
#
# THE NETWORK (docs/real-device-fortigate.md):
#   fgt-client 10.10.1.10 --eth1/veth-- [port2 10.10.1.1  FortiGate  port1 10.0.0.15 (DHCP, qemu user-mode NAT)] --
#       container eth0 172.20.20.2 -- clab bridge 172.20.20.1 -- fgt-server 172.20.20.10 (HTTP)
#   Syslog leaves port1 to 172.20.20.1:6515 — the clab bridge's address in the network namespace that ALL WSL2 distros
#   share, so ULPF (in the Ubuntu distro) listens there directly.
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
FGT=clab-fortigate-fgt IMG=vrnetlab/vr-fortios:7.4.12 SMALL=alpine:3.20
LABEL=ulpf.device=fortigate-lab

# keep the distro alive while the lab runs
pgrep -f "ulpf-fortigate-keepalive" > /dev/null || setsid -f bash -c 'exec -a ulpf-fortigate-keepalive sleep infinity'

# 1. the vrnetlab patch (UUID pinned, port2) — into the container's writable layer, before the VM starts
t=$(mktemp -d)
docker cp "$FGT:/vrnetlab.py" "$t/vrnetlab.py"
if ! grep -q "ULPF: port2" "$t/vrnetlab.py" || ! grep -q "ULPF: pinned" "$t/vrnetlab.py"; then
  docker run --rm --entrypoint /.venv/bin/python -v "$t:/w" -v "$HERE:/p:ro" "$IMG" /p/patch-vrnetlab.py /w/vrnetlab.py /w/vrnetlab.new
  docker cp "$t/vrnetlab.new" "$FGT:/vrnetlab.py"
fi
# the launcher's prompt fix: without it vrnetlab never sees "fgt #", hangs at "Password", and ~68 min after boot its read
# times out and the launcher crashes, taking the VM with it
docker cp "$FGT:/launch.py" "$t/launch.py"
if ! grep -q "login only when it is the last thing shown" "$t/launch.py" || ! grep -q "console login skipped" "$t/launch.py"; then
  docker run --rm --entrypoint /.venv/bin/python -v "$t:/w" -v "$HERE:/p:ro" "$IMG" /p/patch-vrnetlab.py /w/launch.py /w/launch.new
  docker cp "$t/launch.new" "$FGT:/launch.py"
fi
rm -rf "$t"

# 2. the traffic client (no network of its own: its eth1 is the other end of the FortiGate's port2) and the server
docker inspect fgt-client > /dev/null 2>&1 || docker create --name fgt-client --label "$LABEL" --network none --cap-add NET_ADMIN "$SMALL" sleep infinity > /dev/null
docker inspect fgt-server > /dev/null 2>&1 || docker create --name fgt-server --label "$LABEL" --network clab --ip 172.20.20.10 "$SMALL" \
  sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n" | nc -l -p 80 > /dev/null; done' > /dev/null
docker start "$FGT" fgt-client fgt-server > /dev/null

# 3. the link: a veth pair, one end eth1 in the FortiGate container (vrnetlab mirrors it to the VM's port2), the other
#    eth1 in the client — exactly what containerlab does for a topology link
pid() { docker inspect -f '{{.State.Pid}}' "$1"; }
FP=$(pid "$FGT") CP=$(pid fgt-client)
if ! sudo nsenter -t "$FP" -n ip link show eth1 > /dev/null 2>&1; then
  sudo ip link del ulpf-fgt1 2> /dev/null || true
  sudo ip link add ulpf-fgt1 mtu 1500 type veth peer name ulpf-cli1 mtu 1500
  sudo ip link set ulpf-fgt1 netns "$FP"; sudo nsenter -t "$FP" -n ip link set ulpf-fgt1 name eth1
  sudo nsenter -t "$FP" -n ip link set eth1 up
  sudo ip link set ulpf-cli1 netns "$CP"; sudo nsenter -t "$CP" -n ip link set ulpf-cli1 name eth1
  sudo nsenter -t "$CP" -n ip link set eth1 up
  sudo nsenter -t "$CP" -n ip addr add 10.10.1.10/24 dev eth1
  sudo nsenter -t "$CP" -n ip route replace default via 10.10.1.1
fi

# 4. wait for the VM (SSH with the key installed on admin), then say what it is
echo "waiting for the FortiGate to answer on SSH ..."
for _ in $(seq 1 60); do
  if out=$(ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -T admin@172.20.20.2 <<< "get system status" 2>/dev/null | tr -d '\r') && grep -q "License Status" <<< "$out"; then
    grep -E "(Version|Serial-Number|License Status|VM Resources|System time):" <<< "$out"
    grep -q "License Status: Valid" <<< "$out" || { echo "LICENCE NOT VALID — stop here"; exit 2; }
    break
  fi
  sleep 5
done

# 5. traffic: allowed and blocked connections through the FortiGate, forever (a few per second)
docker cp "$HERE/traffic.sh" fgt-client:/traffic.sh
docker exec fgt-client sh -c 'pkill -f "[s]h /traffic.sh" 2>/dev/null; true'
docker exec -d fgt-client sh /traffic.sh
echo "FortiGate lab up: syslog -> 172.20.20.1:6515 (TCP); traffic from fgt-client 10.10.1.10"
