# ULPF — the container deployment's Python images (2026-10-01). Build context: the repository root.
#   docker build -f deploy/Dockerfile --target app    -t ulpf-app .      console, learning plane, lake writer, generator, init
#   docker build -f deploy/Dockerfile --target scaler -t ulpf-scaler .   the ONLY container that holds the Docker socket
# The Go images (runtime, committer, witness) come from runtime/Dockerfile. deploy/ulpf.sh builds all of them.
# Offline at run time: nothing here fetches anything once built. No private key is in any layer (.dockerignore: keys/dev,
# keys/release); the shipped packs' signatures are.
ARG PY=python:3.12-slim-bookworm

FROM ${PY} AS app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ULPF_ROOT=/ulpf
WORKDIR /ulpf
COPY learning/requirements.txt learning/requirements.txt
RUN pip install --no-cache-dir -r learning/requirements.txt  && apt-get update && apt-get install -y --no-install-recommends e2fsprogs && rm -rf /var/lib/apt/lists/*
# the Go tools the console and the init container call (pack verification, the transparency log, export/verify, keygen)
COPY --from=ulpf-binaries / /ulpf/runtime/bin/
COPY contracts contracts
COPY ocsf/pinned ocsf/pinned
COPY library library
COPY acceptance acceptance
COPY learning learning
COPY models/manifest.json models/manifest.json
COPY adapters adapters
COPY demo/apps demo/apps
COPY demo/ui demo/ui
COPY demo/siem/setup.py demo/siem/setup.py
COPY demo/live demo/live
COPY deploy deploy
# shipped: the release-signed packs (scripts/release-packs.sh) and the release authority's PUBLIC key
COPY packs/release /ulpf/release/packs
COPY keys/trust/ulpf-pack-release.pub.json /ulpf/release/trust/ulpf-pack-release.pub.json
RUN rm -rf learning/tests demo/apps/__pycache__ && test -f /ulpf/release/packs/fortigate/pack.json.sig
CMD ["python", "demo/apps/system.py", "--help"]

# The scaler: standard library only, talks to the Docker Engine API over the mounted socket. It accepts four things
# (start a process unit's part, stop it, signal its runtime, read its log) for containers labelled as ULPF's, from a fixed
# template: the image, the mounts, the user, the capability and the network are the scaler's, never the caller's.
FROM ${PY} AS scaler
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY deploy/scaler.py /scaler.py
USER 0
ENTRYPOINT ["python", "/scaler.py"]
