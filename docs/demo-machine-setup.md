# Demo machine setup — what must be true on the machine before the live demo runs

**Two demo documents, two jobs.** This one is about the *machine*: requirements, the checks, and every
finding from setting up **both** machines — the GTX 1650 laptop (4 GB VRAM, 16 GB RAM) and the RTX 5060 Ti
desktop (16 GB VRAM, 48 GB RAM), both Windows 11 + WSL2 + Docker Desktop. **§A is the two-machine summary:
which settings are universal, which are one machine's constraint, and what behaves differently between
them.** §0–§7 are the laptop's setup log as measured; read them when a laptop-class machine is being
prepared. Read this document once, when preparing a machine. [demo-runbook.md](demo-runbook.md) is about *presenting*: the
six steps, what to say and click, the fallback per step. Read that on the day.

The demo machine is the constraint: every latency figure that reaches a slide is measured here, not on
the development desktop. This runbook is what has to be true on the laptop before `scripts/p4-spike.sh`
can run, in the order the problems bite. Nothing here is optional; each step has a check.

**Revised 2026-09-06 after the first setup run on the actual laptop** (i5-10500H 6c/12t,
16 GB, GTX 1650 4 GB, Windows 11, WSL2 kernel 6.6.87, Docker Desktop 29.2). Sections marked *measured*
are what that run found; the rest is the procedure as originally written where it still holds. The
short version: **the driver is the blocker (§1), the WSL cap bit exactly as predicted (§2), weights must
live on the WSL ext4 disk (§2a), port 8080 is taken (§3a), Docker Hub is locked out by a stale login (§3b),
and the CPU floor is 434 s for the Squid session (§5).** *Revised again 2026-09-07:* the driver was updated (616.64, CUDA 13.4) and the GPU figures for both candidate models are in §5a.

## A. Two machines, side by side (added 2026-09-20, after the first desktop run of P7 and the demo)

The desktop last built P6; the fix pass, P7, the demo and the replay bundle were built on the laptop and ran
on the desktop for the first time on 2026-09-20. Everything below was measured on that run.

### A.1 Settings: universal, or one machine's constraint

| Setting | Laptop (GTX 1650, 4 GB / 16 GB RAM) | Desktop (RTX 5060 Ti, 16 GB / 48 GB RAM) | Verdict |
|---|---|---|---|
| Weights served from WSL ext4 (`~/ulpf-models`), never `/mnt/c` | required — the 8B never loaded over `/mnt/c` (§2a) | kept: `demo/preflight.sh` enforces ext4 and `demo/llama-server.sh` reads `~/ulpf-models`; copy 33 s (4B) / 66 s (8B), digests verified on the copy | **universal** (pre-flight fails without it) |
| `--n-gpu-layers 20 --ctx 8192` (`ULPF_LLAMA_NGL`, `ULPF_LLAMA_CTX`; defaults in `demo/lib.sh`) | required for the 8B; the demo default for the 4B (20/33 layers) | **not needed**: `ULPF_LLAMA_NGL=99` puts 33/33 layers on the card (2.6 GB model + 256 MiB KV; ~3.1 GB VRAM delta of 16 GB). **But the offload split changes the model's labels — see A.3 before changing it for a demo** | laptop constraint, with a consequence |
| `.wslconfig` `memory=10GB` | sized against 16 GB host RAM | none present; WSL default is 23 GB of 48, 22 GB available — nothing to set | laptop constraint |
| Port 8081 instead of 8080 | Jenkins holds 8080 in the distro | 8080 and 8081 both free; the demo default 8081 is harmless and was kept | laptop constraint, harmless default |
| llama image | upstream `ghcr.io/ggml-org/llama.cpp:server-cuda` (b10820; the demo default `ULPF_LLAMA_IMAGE`) | upstream image **not present**; the local build `ulpf-llama` (b10819, `ARCHS = 750,1200`) is — run with `ULPF_LLAMA_IMAGE=ulpf-llama`. Same entrypoint and flags; starts in ~10 s, no PTX JIT | per machine — with the default, `llama-server.sh start` would pull 7 GB here |
| `DOCKER_CONFIG=/tmp/ulpf-dockercfg` (empty config; `demo/lib.sh` sets it) | required — stale Docker Hub login (§3b) | not required (no stale login) and harmless; anonymous pulls work | laptop constraint, harmless default |
| Driver | 616.64 after the update (§1) | 595.79 — already ≥ R570 | universal requirement, met on both |
| P7 load-test sizes (`ULPF_LOAD_*` in `p7-check.sh`) | 3,000 conns / 32 MiB / 400 idle, chosen against ~6 GB free | same sizes pass; far larger sizes run — see A.4 | laptop constraint |

Desktop invocation used for every figure below:

```bash
export ULPF_LLAMA_IMAGE=ulpf-llama ULPF_LLAMA_NGL=99      # ULPF_LLAMA_CTX stays 8192
mkdir -p ~/ulpf-models && cp models/cache/Qwen3.5-4B-Q4_K_M.gguf ~/ulpf-models/
bash demo/llama-server.sh start && (setsid -f python3 demo/serve-ui.py) && bash demo/reset.sh && bash demo/preflight.sh
```

Pre-flight: 15/15 clear on the desktop (20 s). Its `gpu visible to docker` check pulls
`nvidia/cuda:12.1.1-base-ubuntu22.04` (340 MB, docker.io) the first time on a machine — a network
dependency inside pre-flight that a venue without a link would hit (it falls back to host `nvidia-smi`).

### A.2 Demo timings

| step | laptop (4B, 20/33 layers, upstream image) | desktop (4B, 33/33 layers, `ulpf-llama`) |
|---|---|---|
| 1 discovery | 0.4 s | 0.4–0.5 s |
| 2 live onboarding | **141–149 s** (model ≈ 116 s) | **35.2–36.5 s** (model proposal 14.2–15.1 s; seven runs, 35.2–36.6 s) — and **80–81 s with `--n-gpu-layers 20`** on the same card (model 58.8–59.7 s) |
| 3 unresolved | 0.5 s | 0.5–0.6 s |
| 4 propagation | ~2 s | 2.1–2.2 s |
| 5 mixed stream | 8–10 s | 9.9 s (rate-paced by the sender, not by the machine) |
| 6 tamper | ~2 s | 2.0–2.1 s |
| total | 153–161 s | **50.9–51.6 s** |
| reset / pre-flight | 24 s / 15 s | 26–28 s / 20 s |

`twice.sh` on the desktop: 50.9 s and 51.1 s, no manual repair. Step 2 is the only step the GPU moves.
Server-side on the desktop: prompt eval ~3,200–3,400 tokens/s (laptop ~115); generation 79 tokens/s on the
class call but **12 tokens/s on the grammar-heavy label call** (laptop 9–11) — consistent with the label call being
bound by grammar-constrained sampling on the CPU rather than by the GPU (not profiled), which would explain why a card eight times larger buys 4×
on step 2, not 8×. Only steps 1–6 are comparable across machines; nothing else in the demo is GPU-bound.

### A.3 Machine-dependent behaviour found (raised on 2026-09-20; fix pass of the same day noted per item)

*Fix pass:* item 1 — `ULPF_LLAMA_NGL=20` is now pinned by pre-flight on every machine and the runbook states the
dependence; item 2 — the label is derived from the GPU name (`demo/lib.sh: machine_label`); item 3 — pre-flight
fails on CRLF working copies and hash-bearing paths are `-text` in `.gitattributes`, so `git status` shows the
divergence; item 4 — the loader accepts 1.3.0 and **every `go test` in the check scripts and the Dockerfile runs
with `-count=1`** (eight test files in five packages read outside the module; uncached costs 4.6–5.5 s against
2.7 s cached); item 5 — unchanged (transient). The `run-real.sh` summary line and the bundle docs' machine
and step-2 figures are fixed (substituted at build).

1. **The certificates shown on stage depend on the offload split.** Same weights (digest-verified), same
   prompt, same seed, same image, same card: with `--n-gpu-layers 20` the 4B labels slot 5
   `http_response.length` and the session shows **pos_1, pos_3, pos_5** (the laptop's three cards — timestamp,
   client IP, bytes counter; the runbook's script). With all 33 layers on the GPU it leaves slot 5 unlabelled,
   labels slot 4 `status`, and the session shows **pos_1, pos_3, pos_4** (`action_outcome`). Each
   configuration is byte-stable across repeats and restarts (P4's finding — determinism is scoped to backend
   and decoding — now also scoped to the *layer split*). Two consequences for a desktop demo: the runbook's
   step-2 narration ("the bytes counter") does not match the third card; and `cert_…_pos4` **stays
   `ambiguous` in the promoted session** — the logformat splits slot 4 into `cache_result`/`status_code`,
   neither of which is among that certificate's survivors, so nothing resolves it, while the pack still
   promotes (the slot's mappings carry device-configuration provenance). The evidence request and the single
   answer that resolves it are the same on both machines (the packs were not compared byte for byte). **To present the laptop's three cards on the desktop,
   run with `ULPF_LLAMA_NGL=20`** (step 2 then takes ~80 s).
2. **`demo/steps/2-onboard.sh` records `--backend "cuda ngl=$LLAMA_NGL laptop-1650"`** — the machine label
   is hardcoded, so a pack promoted on the desktop carries `laptop-1650` in `provenance.proposal.backend`.
3. **Working-tree CRLF on the desktop.** Five files created on this machine during P6 by Python on Windows
   (`learning/fixtures/squid-native-11.log`, `squid-native-proposals.json`, `tests/op_matrix.py`,
   `ulpf_learn/envelope.py`, `ulpf_learn/session.py`) were CRLF on disk while the committed blobs are LF
   (`.gitattributes eol=lf` normalises at commit and never rewrites the working copy; `git status` was clean).
   The laptop, a fresh clone, had LF. Effect: step 5 on the desktop first ran **92 emitted / 9 quarantined**
   — the six 11-slot Squid lines failed at parse (`value "412\r" does not match token class integer`) because
   the TCP octet-counted path carries the bytes as sent, while file input strips the CR (which is why
   `p6-build-packs.sh` never noticed). After re-checking-out the five files (`git ls-files --eol | grep
   w/crlf` → none) step 5 gives the laptop's **98 emitted / 3 quarantined**. Check on any Windows-side
   working copy: `git ls-files --eol | grep w/crlf` must print nothing.
4. **`TestGoldenVectors` fails on the desktop and cannot have run on the laptop.** P7 regenerated
   `contracts/golden/squid-native/normalized/line1.json` at lineage 1.3.0 and added 1.3.0 to the Python
   validator, but `runtime/contracts/loader.go` still lists normalized-event `1.0.0–1.2.0`. `go test ./...`
   therefore fails in `p1-check.sh` … `p7-check.sh` and in the container test stage (`p2-check.sh`). On the
   laptop it reported `ok (cached)`: the golden vectors live outside the `runtime/` module root, and Go's
   test cache does not re-check files outside the module — demonstrated here (pass with the P6 golden,
   restore the P7 golden byte for byte → still `ok (cached)`; `-count=1` → FAIL). The desktop's cache had
   aged out, so it ran the test. Every other section of all seven checks passes. **Not fixed** — it is a
   one-line contract-loader change plus a decision on whether the check scripts should run the contract
   suite with `-count=1`.
5. **`p5-witness-test.sh` failed once** (`open /bundle/bundle.json: no such file or directory`, both
   container runs of one invocation — the bind mount of a just-created `/tmp` directory came up empty), on
   the first Docker activity after 13 idle days; then passed 8/8 standalone and 3/3 inside `p5-check.sh`.
   Transient, same family as the laptop's `/mnt/c` hiccup (§3c): re-run before believing it.

Found in passing, not machine-dependent: `demo/replay/real/run-real.sh` line 54 prints its step-5 summary
with `\"` inside a single-quoted `python3 -c` f-string — a `SyntaxError` on any Python (the run continues,
rc 0, only the summary line is lost); re-running step 2 alone after a full run (`demo/run.sh 2 2`, the
runbook's Q&A suggestion) finds step 2's own resolution in `propagation.json` and shows **zero
certificates**; `bundle-docs/README.md`, `PRESENTER.md` and `serve.py` say "145 s" and "recorded on our demo
laptop" whatever machine built the bundle (the timings table is substituted correctly: 35.2 s here).

### A.4 P7 load tests at desktop scale (16 threads, 22.9 GB available, `ulimit -n` 10,240)

| size (conns / MiB / idle) | flood | oversized message | idle peers |
|---|---|---|---|
| 3,000 / 32 / 400 (laptop sizes) | pass — 64 served at peak, 2,925 refused, heap +8 MiB (bound 32) | 512 / 513 pieces, heap +0 MiB | pass |
| 10,000 / 256 / 2,000 | pass — heap +12 MiB | 4,096 / 4,097 pieces, heap +0–1 MiB | pass |
| 13,000 and 16,000 conns | pass — heap +11 / +18 MiB | — | — |
| 20,000, 25,000, 40,000 conns | **accounting assertion fails** (accepted + refused ≈ 8.6–14.5 k of N); the heap bound was not breached | 1,024 MiB → 16,384 / 16,385 pieces, heap +4–5 MiB, 14 s | 20,000 idle peers pass (34 s) |

What the larger sizes say that the laptop run could not: (a) the oversized-message bound is flat — heap
growth stays in single MiB from 32 MiB to 1 GiB, so it is bounded by the frame cap as asserted, not by
luck at a small size; (b) the flood test's heap growth **rises with the connection count** (8 → 12 → 18 MiB)
because client and server share one test process and `HeapInuse` counts the clients' buffers too — the
32 MiB bound is a bound on the whole harness and would eventually be crossed by the client side, not the
server; (c) above ~16–20 k simultaneous dials the kernel's accept queue overflows (`somaxconn` 4096;
`TcpExtListenOverflows` 191,877 after these runs) and the clients' 2 s dial timeout expires — a harness
ceiling, not a server failure; raising `ulimit -n` to 200,000 changed nothing. Invariant 7's asserted
bounds held at every size where the harness could deliver the load.

### A.5 Replay bundle on the desktop

`capture.sh` 85 s, `build.sh` 8 s → `~/demo-replay.zip`, 8.2 MB, 312 entries. Tested from a clean extract
with the repository absent: a container with `--network none`, no repository mount, only the zip (extracted
with `python3 -m zipfile`): index, `app.js`, `replay.js`, `style.css` and `/state/status.json` served;
`PRESENTER.md` carries this run's timings; real mode ran steps 5 and 6 with the bundled static binaries
(gap record, verify OK, in-process witness OK ×2, tamper named leaf 0, verify FAIL as intended), apart from
the summary-line `SyntaxError` above.

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
`MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- bash /mnt/c/<path-to-repo>/scripts/<script>.sh`; from
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
--ctx 8192`** — 20/41 layers, 2.49 GB CUDA + 2.60 GB host mapped, KV 608 MiB CUDA + 672 MiB host, VRAM delta
3,282 MiB of the 3,294 MiB free (the card is full; there is no room for a browser's GPU process on the day).
Prompt eval ~54 tokens/s, generation ~5 tokens/s — half the 4B per token, but fewer iterations per session:

| case | wall s (session, first repeat) | iterations | agreement | byte-identical |
|---|---|---|---|---|
| asa-106023 | 76.0 | 1 | 0.82 | yes |
| asa-302013 | 93.1 | 1 | 0.50 | yes |
| fortigate-traffic | 379.7 | 1 | 0.74 | yes |
| panos-traffic | 435.4 | 1 | 0.58 | yes |
| squid-native | 155.8 | 2 | 0.50 | yes |

Across the five cases: 4B mean wall 227 s (median 162), agreement 0.54, 2.6 iterations; Granite mean 228 s
(median 156), agreement 0.63, 1.2 iterations. Both are byte-identical across the two repeats in one server
lifetime on this backend. `python learning/tools/spike.py summarize` merges both machines.

**Does the model change what the operator sees?** `scripts/p4-request-compare.sh` ran the live Squid
onboarding session (the demo's sequence: onboard → certificates → one logformat response → promote →
`verify-pack`) against each model's server:

| | Qwen3.5-4B-Q4 (22/33 layers) | Granite 4.1 8B-Q4 (20/41) |
|---|---|---|
| model proposal + certificates, wall | 103.5 s | 127.5 s |
| evidence request | `device_logformat_configuration`, resolves pos_1…pos_10 | identical |
| certificates issued | 3 (`pos_1` temporal_role, `pos_3` endpoint_orientation, `pos_5` volume_direction) | 2 (`pos_1`, `pos_3`) |
| operator responses to promote | 1 | 1 |
| promoted pack | verified, signed | verified, signed |
| VRAM in use while serving | 2,529 MiB | 3,547 MiB |

**The same one question, the same one answer, the same promoted pack.** The agreement gap between the two
models (0.54 vs 0.63 across cases; 0.50 vs 0.50 on Squid) does not reach the stage: every unlabelled or
mis-labelled field is covered by the single logformat request either way. What differs on stage is the
certificate list shown before the request (three vs two — the 4B labels the bytes counter, which is the
richer demo) and the wait: ~100–160 s for a Squid session on either model, ~75–95 s for an ASA family,
5–7 minutes for the wide PAN-OS/FortiGate formats.

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
| step 5 shows `quarantine reasons: {"parse": 6, …}` and 92 emitted instead of 98 | CRLF working copy of `learning/fixtures/squid-native-11.log` on a Windows-side checkout | `git ls-files --eol \| grep w/crlf`; delete and `git checkout --` each listed file (§A.3.3) |
| `TestGoldenVectors/squid-native/normalized/line1.json … unsupported schema_version "1.3.0"` | Go loader not updated for normalized-event 1.3.0; hidden on a warm Go test cache | open — §A.3.4 |
| step 2 shows a different third certificate than the runbook describes | the offload split changes the 4B's labels | `ULPF_LLAMA_NGL=20` for the laptop's set (§A.3.1) |
| `.part` left in `models/cache` with `DIGEST MISMATCH` after a short download | the server closed the connection early; `models.py fetch` treats EOF as complete | re-run `fetch` — it resumes with a Range request; loop until `verified sha256` |
