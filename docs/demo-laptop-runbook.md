# Demo laptop runbook — GTX 1650 4 GB, 16 GB RAM, Windows + WSL2 + Docker Desktop

The demo machine is the constraint: every latency figure that reaches a slide is measured here, not on
the development desktop. This runbook is what has to be true on the laptop before `scripts/p4-spike.sh`
can run, in the order the problems bite. Nothing here is optional; each step has a check.

**Revised 2026-09-06 after the first setup run on the actual laptop** (hostname `MSI`, i5-10500H 6c/12t,
16 GB, GTX 1650 4 GB, Windows 11, WSL2 kernel 6.6.87, Docker Desktop 29.2). Sections marked *measured*
are what that run found; the rest is the procedure as originally written where it still holds. The
short version: **the driver is the blocker (§1), the WSL cap bit exactly as predicted (§2), weights must
live on the WSL ext4 disk (§2a), port 8080 is taken (§3a), Docker Hub is locked out by a stale login (§3b),
and the CPU floor is 434 s for the Squid session (§5).** *Revised again 2026-09-07:* the driver was updated (616.64, CUDA 13.4) and the GPU figures for both candidate models are in §5a.

## 0. What the two machines share — and what changed on the laptop

One `ulpf-llama` image (`learning/Dockerfile`, target `llama`) built once with
`CMAKE_CUDA_ARCHITECTURES=75-real;120-real`, CUDA 12.8.1, and **`GGML_BACKEND_DL`** (backends are
shared libraries loaded at run time). CUDA 13 dropped Maxwell/Pascal/Volta but keeps Turing (`sm_75` is
now the oldest supported architecture), so either toolkit could serve both cards; 12.8 was chosen because
it asks less of the host driver (see §1). The same image runs on the RTX 5060 Ti (`sm_120`), on the GTX
1650 (`sm_75`), and **on a host with no NVIDIA driver at all** (CPU backend only — verified: the first
build, statically linked against CUDA, needed `libcuda.so.1` even for `--device none` and would have failed
on a GPU-less machine; the dynamic-backend build was the fix). **No rebuild between machines** was the
plan: export once (`docker save ulpf-llama | zstd`), load on the laptop.

*Measured 2026-09-06:* the desktop was gone before the image was exported, so the laptop has no
`ulpf-llama`. Rebuilding it here costs ~75 min of CUDA compile on a stronger CPU plus a ~3 GB
`nvidia/cuda:12.8.1-devel` download on a link that measured 0.5–4 MB/s, and it would still need the §1
driver. **The route taken instead is the upstream image `ghcr.io/ggml-org/llama.cpp:server-cuda`**
(6.99 GB pulled; llama.cpp `b10820`, one commit after the pinned `b10819`; CUDA 12.8.1, Ubuntu 24.04,
`GGML_BACKEND_DL=ON`, `GGML_CPU_ALL_VARIANTS=ON`, same entrypoint `/app/llama-server`, same
`LD_LIBRARY_PATH`/backend layout). What differs from our build:

| | `ulpf-llama` (desktop build) | upstream `server-cuda` |
|---|---|---|
| llama.cpp | `b10819` (pinned in `models/manifest.json`) | `b10820-74a7c897f` (recorded in every result's `provenance.llama_cpp.build_info`) |
| CUDA archs | `75-real;120-real` — SASS for Turing, no PTX | ggml default: `75-virtual` (PTX for Turing, JIT-compiled by the driver on first load), `86-real`, `89-real`, `120a-real`, … |
| driver needed | ≥ R570 (CUDA 12.8) | ≥ R570 **and** a JIT-capable driver for the sm_75 PTX (any R570+ is) |
| first GPU start | immediate | PTX JIT once per container start unless `CUDA_CACHE_PATH` is mounted as a volume — expect minutes on the first load; mount a volume to keep the cache |
| CPU path | identical (`--device none`) | identical — the CPU floor in §5 was measured on it |

Pass it to the spike as `--image ghcr.io/ggml-org/llama.cpp:server-cuda`. The pack's `model_hash` is
the weights digest and does not change; the llama.cpp build string is provenance, not contract.

## 1. NVIDIA driver on the Windows host — **BLOCKER on this laptop (measured)**

CUDA 12.8 user-mode libraries in the container need a host driver **≥ R570** (the CUDA 12.8 minimum).
Check on the host:

```powershell
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
```

*Measured 2026-09-06:* **driver 531.68 (CUDA 12.1)**. Two things were tried and both fail, so this is
not a soft requirement:

- Plain start: the NVIDIA container runtime refuses before llama-server runs —
  `nvidia-container-cli: requirement error: unsatisfied condition: cuda>=12.8, please update your driver`.
- With `-e NVIDIA_DISABLE_REQUIRE=1` (bypassing that check): the container starts, then
  `ggml_cuda_init: failed to initialize CUDA: no CUDA-capable device is detected` — the 12.8 runtime does
  not initialise on the 12.1 driver, so CUDA "minor version compatibility" does not rescue it under WSL.
  Our own `75-real` build would hit the same wall; a CUDA ≤ 12.1 rebuild of llama.cpp is the only
  no-driver-update path and is not recommended (older toolkit, untested against `b10819`, ~1 h build).

**Fix: update the GeForce driver on Windows to the current release (any R570 or later; Turing is still
supported), reboot, re-run the check above, then §3.** This is a Windows-side install by the operator;
**do not install a Linux driver inside WSL**. Until it is done there is no GPU path on this machine, only
the CPU floor (§5).

## 2. WSL2 memory — the one that bites on the day (**it did — measured**)

WSL2 gives the VM about half of system RAM by default: **7.7 GB on this laptop** (`free -g` → 7, no
`.wslconfig` present). Docker Desktop runs inside that VM.

*Measured 2026-09-06, Granite 4.1 8B-Q4 on CPU:* llama.cpp maps the 5.07 GB file **and** builds a
3.67 GB `CPU_REPACK` buffer (the AVX2 repacked copy of the Q4_K weights), so the working set is ~6.1 GB in
the container with the VM at 7.3 GB used and under 100 MB free, 1.2 GB into swap. With the weights read
through the Docker Desktop mount of `/mnt/c` the server sat at 0 % CPU for 17 minutes after
`threadpool init` and never became ready (page-cache thrash over the 9p/grpcfuse share). With the same
file on the distro's ext4 disk (§2a) it loaded in 35 s and ran. **The 8B fits the default cap only just,
and only from ext4.** The 4B (2.7 GB + ~1.9 GB repack) has room to spare.

Host side, under that load: `vmmemWSL` 5.1 GB working set, Windows free 2.4 GB, i.e. **Windows plus the
other applications on this laptop take ~8 GB**. The original advice of `memory=12GB` would leave ~4 GB
for Windows and push it into paging; for a live demo with the 8B set:

```ini
[wsl2]
memory=10GB
swap=8GB
processors=6
```

then `wsl --shutdown` in PowerShell (this also stops Docker Desktop; reopen it) and check `free -g` ≥ 9.
Close browsers and anything else heavy before the demo; `processors=6` keeps llama.cpp on the six
physical cores (it picked `n_threads = 6` itself). **Not applied during the setup run** — the CPU floor
was measured at the default 7.7 GB precisely so the number reflects the machine as found; apply it before
the GPU measurements once §1 is done. With the 4B model the default is enough.

### 2a. Weights on the ext4 disk, not on `/mnt/c` (measured)

`models/cache/` lives in the repository on `C:`; the spike mounts it into the container with `-v`. On
Docker Desktop that is a bind mount through the Windows file-sharing layer, and llama.cpp's mmap over it
is what stalled in §2. Keep the digest-verified copy in `models/cache/` (so `models.py verify` and the
image build still work) **and** keep a second copy on the distro disk for serving:

```bash
mkdir -p ~/ulpf-models && cp models/cache/granite-4.1-8b-Q4_K_M.gguf ~/ulpf-models/   # ~3 min
sha256sum ~/ulpf-models/granite-4.1-8b-Q4_K_M.gguf                                     # must equal the manifest digest
bash scripts/p4-spike.sh laptop-1650 cpu ... --cache /home/$USER/ulpf-models            # the run reads from ext4; the wrapper's verify step reads models/cache
```

The distro disk had 937 GB free. Do not symlink from `models/cache/` — the symlink does not resolve
inside the container.

## 3. GPU visible inside Docker

```bash
docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi -L    # any CUDA base image the driver accepts
```

Must print the GTX 1650. *Measured:* it does (`GPU 0: NVIDIA GeForce GTX 1650`), so WSL integration and
the container runtime are fine; only the driver version (§1) stands in the way.

### 3a. Port 8080 is taken inside the distro (measured)

A Jenkins service (`/usr/bin/java -jar /usr/share/java/jenkins.war`, Jetty on `*:8080`) runs in the
Ubuntu distro. The spike publishes llama-server on `-p 8080:8080` and polls `http://127.0.0.1:8080/health`
**from inside the distro**, where that address is Jenkins (HTTP 302 to `/health/`), so the runner waits
for readiness until its 30-minute timeout — the container itself is healthy and reachable from Windows.
**Always pass `--port 8081`** (or stop Jenkins for the day: `sudo systemctl stop jenkins`).

### 3b. Docker Hub is locked out by a stale login (measured)

Docker Desktop's credential store holds an expired Docker Hub login; every pull from `docker.io` —
`golang:1.24-alpine`, `alpine:3.20`, `nvidia/cuda:*` — fails with `401 Unauthorized: incorrect username
or password`, which breaks the container stages of `p2-check.sh` and `p5-check.sh`. Anonymous pulls work.
Either log out (`docker logout`, a change to the operator's account state) or run with a clean config:

```bash
mkdir -p /tmp/ulpf-dockercfg && echo '{}' > /tmp/ulpf-dockercfg/config.json
export DOCKER_CONFIG=/tmp/ulpf-dockercfg      # per shell; every check script below was run this way
```

`ghcr.io` pulls are unaffected.

### 3c. Invoking from Windows

Git Bash rewrites `/mnt/c/...` arguments into `C:/Program Files/Git/mnt/c/...`. From a Git Bash shell use
`MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- bash /mnt/c/VSCode/sih2026-ulpf/scripts/<script>.sh`; from
PowerShell the plain form in the README works. Background jobs started inside a `wsl.exe -- bash -c`
call die when the call returns; use `setsid -f` and a log file for anything longer than a few minutes.
`/mnt/c` also produced one transient `No such file or directory` on `scripts/keys-bootstrap.sh` during a
back-to-back check chain (the file was there; the next run passed) — re-run before believing a
file-not-found from a script on `/mnt/c`.

### 3d. Python venv needs `cryptography`

`learning/ulpf_learn/signing.py` imports `cryptography` (P5), but `scripts/wsl-bootstrap.sh`,
`learning/requirements.txt` and `pyproject.toml` do not declare it — on the desktop it was already in the
shared venv, which is why the clean-clone test never noticed. On a fresh machine every `pN-check.sh` fails
at `keys-bootstrap` until `pip install cryptography` is run in `~/.venvs/ulpf`. Raised for the code fix
(add it to the three declarations); the setup run installed it by hand.

## 4. Offload split — a knob, not a guess

`llama-server` is started with `--n-gpu-layers auto` (`-fit on` is llama.cpp's default), which sizes the
offload to free VRAM at start; the spike runner records what the server actually did (`offloaded N/M
layers to GPU`, buffer sizes) in every result file, so a silent misconfiguration is visible in the data,
not silent. The knob is explicit when needed: `--ngl 20` on `scripts/p4-spike.sh`, or `ULPF_NGL` for the
learning-plane image. Expected on 4 GB: 4B-Q4 (~2.7 GB) fits entirely with KV cache to spare; Granite
8B-Q4 (5.07 GB of tensors, 41 layers on the desktop) offloads roughly half to 60 %; 9B-Q4 (~5.6 GB)
roughly two thirds at best; 12B-Q4 (~7.2 GB) about half. The default `--ctx-size 16384` KV cache competes
for the same 4 GB — pass `--ctx 8192` on the 1650 if `auto` offloads fewer layers than expected. The
runner's `fits_in_vram` field is the record. *Not yet measured here* (§1).

## 5. CPU-only floor — **measured 2026-09-06**

Before any GPU number, run the floor once so it is known to work:

```bash
export DOCKER_CONFIG=/tmp/ulpf-dockercfg                                                  # §3b
MODELS=granite-4.1-8b-q4_k_m REPEAT=1 bash scripts/p4-spike.sh laptop-1650 cpu \
    --cases squid-native --modes whole --image ghcr.io/ggml-org/llama.cpp:server-cuda \
    --cache /home/$USER/ulpf-models --port 8081
```

Result (`spike/results/laptop-1650/granite-4.1-8b-q4_k_m__cpu__squid-native__whole.json`):

| model | mode | case | wall s (CPU, laptop) | calls | prompt / predicted tokens | iters | agreement | class | byte-identical |
|---|---|---|---|---|---|---|---|---|---|
| granite-4.1-8b-q4_k_m | whole | squid-native | **433.8** | 3 | 3256 / 387 | 2 | 0.50 | http_activity ✓ | ✓ (1 repeat) |

Same case, same prompt tokens (3256), same iteration count on the desktop GPU: **13.1 s** — the laptop CPU
is 33× slower. Model load from ext4: 35 s (not counted in the wall). `n_threads = 6`, AVX2, REPACK on. The
desktop's CPU floor for the 4B was 266 s on a Ryzen 2700X, so the 8B on this i5 is in line. **This is the
number to quote if the GPU path is not working on the day: a Squid onboarding session is ~7½ minutes on
CPU, plus half a minute of model load.** Only one model was fetched (Granite; 5.35 GB took ~30 min at
0.5–4 MB/s); the 4B floor is not measured here.

## 5a. GPU measurements — **measured 2026-09-07 after the driver update** (616.64, CUDA 13.4)

Both candidate models, whole mode, all five cases, `--repeat 2`, weights on ext4, `--port 8081`, the compute
cache mounted (`--cuda-cache ulpf-cuda-cache`, so the upstream image's sm_75 PTX is JIT-compiled once per
machine). The GPU has ~3.2 GB free at start (Windows holds the rest of the 4 GB).

**Qwen3.5-4B-Q4** (`--ctx 8192`, `-fit` chose 22/33 layers on the GPU, 1.87 GB CUDA + 1.23 GB host):

| case | wall s (session, first repeat) | iterations | agreement | byte-identical |
|---|---|---|---|---|
| asa-106023 | 118.8 | 2 | 0.82 | yes |
| asa-302013 | 161.8 | 3 | 0.36 | yes |
| fortigate-traffic | 436.4 | 3 | 0.49 | yes |
| panos-traffic | 296.3 | 2 | 0.51 | yes |
| squid-native | 121.0 | 3 | 0.50 | yes |

Server throughput: prompt eval ~115 tokens/s, generation ~9–11 tokens/s. Model load 6 s.

**Granite 4.1 8B-Q4 with `--n-gpu-layers auto` and the 16k default context is slower than CPU on this
card** (prompt eval 6 tokens/s, generation 1.8 tokens/s): the fit heuristic offloaded 41/41 layers of a
5 GB model into 4 GB and the driver paged VRAM through shared memory. **Rule for the 8B on the 1650: `--ngl 20
--ctx 8192`.** Its measured figures under that rule are in `spike/results/laptop-1650/` and the P7 report's
demo-shape recommendation; `python learning/tools/spike.py summarize` merges both machines.

The spike tool recorded the offload split from the **first** `offloaded N/M layers` line; llama.cpp's fit
loop logs several probes and only the last is what runs (the first said 33/33 for the 4B, 22/33 ran).
Fixed in P7 to read the last line; laptop results written before the fix carry the wrong `offload` field
and are superseded by re-runs.

## 6. The measurements

Order on this machine, after §1 is fixed and §2 applied:

```bash
export DOCKER_CONFIG=/tmp/ulpf-dockercfg
docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi -L                # §3
docker run --rm --gpus all ghcr.io/ggml-org/llama.cpp:server-cuda --list-devices          # must list CUDA0 = GTX 1650
MODELS=granite-4.1-8b-q4_k_m bash scripts/p4-spike.sh laptop-1650 gpu \
    --image ghcr.io/ggml-org/llama.cpp:server-cuda --cache /home/$USER/ulpf-models --port 8081   # all five cases, both modes, --repeat 2
python learning/tools/spike.py summarize
```

Results land in `spike/results/laptop-1650/` and are committed. The desktop's results are in
`spike/results/desktop-5060ti/`; the report labels every number with its machine. The first GPU start
will JIT the sm_75 PTX (§0); if it takes minutes, add `-v ulpf-cuda-cache:/root/.nv/ComputeCache` by
running the server by hand and passing `--server http://127.0.0.1:8081` to the spike.

## 7. Known failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `nvidia-container-cli: requirement error: unsatisfied condition: cuda>=12.8` at `docker run --gpus all` | host driver < R570 (this laptop: 531.68) | §1 — update the Windows driver; nothing inside WSL helps |
| `ggml_cuda_init: failed to initialize CUDA: no CUDA-capable device is detected` | same, with the requirement check bypassed | §1 |
| server `healthy` but the spike never prints `== model on laptop-1650` | port 8080 inside the distro is Jenkins | `--port 8081` (§3a) |
| `401 Unauthorized` on any `docker.io` pull | stale Docker Hub login in Docker Desktop | `DOCKER_CONFIG` with `{}` or `docker logout` (§3b) |
| server at 0 % CPU after `threadpool init`, `free -m` shows < 100 MB free | 8B mmap + REPACK over the `/mnt/c` mount under the 7.7 GB cap | weights on ext4 (§2a); `.wslconfig` (§2) |
| container killed, no message, `free -g` small | WSL2 memory cap (§2) | `.wslconfig`, `wsl --shutdown` |
| container exits at start, `cudaMalloc failed` / OOM | too many layers for 4 GB, or another process holds VRAM | `--ngl` lower, `--ctx 8192`; close the browser's GPU process |
| `ModuleNotFoundError: No module named 'cryptography'` from `keys-bootstrap` | undeclared dependency (§3d) | `pip install cryptography` in the venv |
| `nvidia-smi` works on host, not in Docker | WSL integration or container runtime | §3 |
| `the provided PTX was compiled with an unsupported toolchain` | driver's JIT older than the image's CUDA | §1 — the upstream image carries PTX for sm_75 |
| very slow first request | prompt processing on CPU for the non-offloaded layers; PTX JIT on the upstream image | expected; onboarding is once per source; mount the compute cache (§6) |
| `No such file or directory` for a script that exists, on `/mnt/c` | transient 9p hiccup | re-run (§3c) |
| `.part` left in `models/cache` with `DIGEST MISMATCH` after a short download | the server closed the connection early; `models.py fetch` treats EOF as complete | re-run `fetch` — it resumes with a Range request; loop until `verified sha256` |
