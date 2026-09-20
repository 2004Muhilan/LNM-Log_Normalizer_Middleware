#!/usr/bin/env bash
# Requirement (k) for the LEARNING plane, on a freshly built image: bundled weights, no network.
# Builds ulpf-learning:<id> from the current tree, asserts no private key material is inside, starts it with
# --network none (GPU if present), waits for readiness (FAILS on timeout), and runs a real onboarding INSIDE the
# container against the bundled model: proposals, certificates and one evidence request, with no route out.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
id="${1:-qwen3.5-4b-q4_k_m}"; name=ulpf-learning-check; status=0
export DOCKER_BUILDKIT=1
t0=$(date +%s)
docker build -q -f learning/Dockerfile --target learning --build-arg MODEL="$id" --build-context models=models/cache -t "ulpf-learning:$id" . >/dev/null || { echo "FAIL: image build"; exit 1; }
echo "built ulpf-learning:$id in $(( $(date +%s)-t0 ))s: $(docker image inspect "ulpf-learning:$id" --format '{{.Size}}' | awk '{printf "%.2f GB", $1/1e9}'), created $(docker image inspect "ulpf-learning:$id" --format '{{.Created}}' | cut -c1-19)"
leak=$(docker run --rm --network none --entrypoint sh "ulpf-learning:$id" -c 'ls /ulpf/keys/dev 2>/dev/null; grep -rl private_key /ulpf/keys 2>/dev/null' | head -5)
[ -z "$leak" ] && echo "ok: no private key material in the image (keys/trust only: $(docker run --rm --network none --entrypoint sh "ulpf-learning:$id" -c 'ls /ulpf/keys/trust | wc -l') file(s))" || { echo "FAIL: key material in the image: $leak"; status=1; }
docker rm -f $name >/dev/null 2>&1
gpus=""; docker run --rm --gpus all --network none --entrypoint true "ulpf-learning:$id" >/dev/null 2>&1 && gpus="--gpus all"
docker run -d --name $name --network none $gpus -e ULPF_NGL="${ULPF_NGL:-20}" "ulpf-learning:$id" >/dev/null || { echo "FAIL: container start"; exit 1; }
ready=0; for i in $(seq 1 150); do sleep 2; docker logs $name 2>&1 | grep -qE "listening on http" && { ready=1; break; }; docker inspect -f '{{.State.Running}}' $name | grep -q true || break; done
docker logs $name 2>&1 | grep -E "model_hash|verified|MISMATCH" | head -3 | sed 's/^/  /'
[ $ready = 1 ] || { echo "FAIL: the bundled server did not become ready (network none, ${gpus:-cpu})"; docker logs $name 2>&1 | tail -5; docker rm -f $name >/dev/null; exit 1; }
echo "ok: bundled llama-server ready with --network none (${gpus:-cpu only}); interfaces inside: $(docker exec $name sh -c 'ls /sys/class/net | tr "\n" " "')"
docker exec $name sh -c 'cd /ulpf/learning && python -m ulpf_learn onboard --provider model --model-id '"$id"' --server http://127.0.0.1:8080 --mode whole --backend "image network-none" --samples /ulpf/contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session /tmp/s >/tmp/onboard.txt 2>&1; echo rc=$?; python -m ulpf_learn certificates --session /tmp/s | grep -c "^cert_"; grep -E "^source|discriminator:" /tmp/onboard.txt' > /tmp/p8-learning.out 2>&1
sed 's/^/  /' /tmp/p8-learning.out
grep -q "^rc=0" /tmp/p8-learning.out && grep -q "state: awaiting_evidence" /tmp/p8-learning.out && [ "$(sed -n 2p /tmp/p8-learning.out)" -ge 1 ] && echo "ok: onboarding ran inside the image with no network: model proposals, certificates, one evidence request" || { echo "FAIL: onboarding inside the offline image"; status=1; }
docker rm -f $name >/dev/null
echo "p8-learning-image-check: $([ $status = 0 ] && echo PASS || echo FAIL)"
exit $status
