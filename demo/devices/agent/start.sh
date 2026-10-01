#!/usr/bin/env bash
# Start the lab agent on the lab's Docker engine (RUNS IN the Containerlab distro): host network (it reaches the FortiGate at
# 172.20.20.2 and listens on 127.0.0.1:8799), the host's PID namespace (lab.sh's status reports the distro's keep-alive), the
# Docker socket (Suricata's forwarder is a container), the lab user's SSH key read-only (the FortiGate's admin key; never the
# password). Lab equipment only: ULPF's own containers never get any of this.
#
#     wsl -d Containerlab -- bash …/demo/devices/agent/start.sh        (stop: docker rm -f ulpf-lab-agent)
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
docker build -q -t ulpf-lab-agent -f "$HERE/Dockerfile" "$(dirname "$HERE")" > /dev/null
docker rm -f ulpf-lab-agent > /dev/null 2>&1 || true
docker run -d --name ulpf-lab-agent --restart unless-stopped --network host --pid host --label ulpf.device=lab-agent \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.ssh:/root/.ssh:ro" ulpf-lab-agent > /dev/null
for _ in $(seq 1 20); do
  out=$(curl -s -m 60 -X POST -d '{"args":["status"]}' http://127.0.0.1:8799/run) && grep -q fgt_License_Status <<< "$out" && { echo "lab agent up: $(grep -o 'fgt_License_Status=[A-Za-z]*' <<< "$out")"; exit 0; }
  sleep 1
done
echo "the lab agent did not answer with the FortiGate's status:"; echo "$out" | tail -5; docker logs --tail 5 ulpf-lab-agent; exit 1
