# ULPF learning plane — Python + llama-server + bundled, digest-verified weights. Offline at run time.
# Build context: repository root. Weights come from a bind mount of models/cache (never the build
# context, never git); models/manifest.json pins name, source and sha256, verified here and at start.
#
#   DOCKER_BUILDKIT=1 docker build -f learning/Dockerfile --target llama -t ulpf-llama .
#   DOCKER_BUILDKIT=1 docker build -f learning/Dockerfile --target learning --build-arg MODEL=<manifest id> \
#       --build-context models=models/cache -t ulpf-learning:<id> .
#
# One CUDA build serves both machines: sm_75 (GTX 1650, Turing) and sm_120 (RTX 5060 Ti, Blackwell).
# CUDA 12.8 is the oldest toolkit that knows sm_120 and still targets sm_75 (CUDA 13 also keeps
# Turing; 12.8 asks less of the host driver: >= R570). CPU inference works with no GPU present.
ARG CUDA_VERSION=12.8.1
ARG UBUNTU_VERSION=24.04
ARG LLAMA_TAG=b10819
ARG CUDA_ARCHS=75-real;120-real

FROM docker.io/nvidia/cuda:${CUDA_VERSION}-devel-ubuntu${UBUNTU_VERSION} AS llama-build
ARG LLAMA_TAG
ARG CUDA_ARCHS
RUN apt-get update && apt-get install -y --no-install-recommends git cmake build-essential ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch ${LLAMA_TAG} https://github.com/ggml-org/llama.cpp.git . \
 && git rev-parse HEAD > /llama-commit
# GGML_BACKEND_DL: backends are shared libraries loaded at run time, so the same binary runs on a host
# with a CUDA driver (loads libggml-cuda) and on one without (CPU only). Without it the CUDA-linked
# binary needs libcuda.so.1 even for --device none (found by the P4 start check). CPU_ALL_VARIANTS picks
# the CPU kernel variant for the host at run time (the two machines have different CPUs).
RUN cmake -B build -DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES="${CUDA_ARCHS}" -DGGML_NATIVE=OFF \
      -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=ON -DBUILD_SHARED_LIBS=ON \
      -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
      -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --config Release -j"$(nproc)" --target llama-server llama-cli
RUN mkdir -p /out && cp build/bin/llama-server build/bin/llama-cli /out/ \
 && find build -name "*.so*" -exec cp -P {} /out/ \; && ls /out

# llama-server alone (used by the spike; the learning image below builds on the same binaries)
FROM docker.io/nvidia/cuda:${CUDA_VERSION}-runtime-ubuntu${UBUNTU_VERSION} AS llama
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=llama-build /out/ /app/
COPY --from=llama-build /llama-commit /app/llama-commit
ENV LLAMA_ARG_HOST=0.0.0.0 LD_LIBRARY_PATH=/app GGML_BACKEND_PATH=/app
ENTRYPOINT ["/app/llama-server"]

# Learning plane + one bundled model. MODEL is a manifest id; the GGUF is read from the `models`
# build context (bind mount), verified against models/manifest.json, and verified again at start.
FROM docker.io/nvidia/cuda:${CUDA_VERSION}-runtime-ubuntu${UBUNTU_VERSION} AS learning
ARG MODEL
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 python3 python3-venv ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=llama-build /out/ /app/
COPY --from=llama-build /llama-commit /app/llama-commit
WORKDIR /ulpf
COPY learning/requirements.txt learning/requirements.txt
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -r learning/requirements.txt
COPY contracts contracts
COPY ocsf/pinned ocsf/pinned
COPY library library
COPY acceptance acceptance
COPY learning learning
COPY models/manifest.json models/manifest.json
RUN --mount=type=bind,from=models,target=/models-in \
    /venv/bin/python learning/tools/models.py install --manifest models/manifest.json --cache /models-in --dest /ulpf/models/cache --id "${MODEL}"
ENV PATH="/venv/bin:/app:${PATH}" ULPF_ROOT=/ulpf ULPF_MODEL_ID=${MODEL} LD_LIBRARY_PATH=/app GGML_BACKEND_PATH=/app
ENTRYPOINT ["/venv/bin/python", "learning/tools/models.py", "serve", "--manifest", "models/manifest.json", "--cache", "/ulpf/models/cache"]
