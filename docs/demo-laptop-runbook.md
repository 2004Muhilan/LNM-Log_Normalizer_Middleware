# Demo laptop runbook — GTX 1650 4 GB, 16 GB RAM, Windows + WSL2 + Docker Desktop

The demo machine is the constraint: every latency figure that reaches a slide is measured here, not on
the development desktop. This runbook is what has to be true on the laptop before `scripts/p4-spike.sh`
can run, in the order the problems bite. Nothing here is optional; each step has a check.

## 0. What the two machines share

One `ulpf-llama` image (`learning/Dockerfile`, target `llama`) built once with
`CMAKE_CUDA_ARCHITECTURES=75-real;120-real`, CUDA 12.8.1. CUDA 13 dropped Maxwell/Pascal/Volta but
keeps Turing (`sm_75` is now the oldest supported architecture), so either toolkit could serve both
cards; 12.8 was chosen because it asks less of the host driver (see §1). The same image runs on the
RTX 5060 Ti (`sm_120`), on the GTX 1650 (`sm_75`), and with no GPU at all (`--device none`, CPU).
**No rebuild between machines.** The image is exported once (`docker save ulpf-llama | zstd`) and
loaded on the laptop; the weights come from `models/cache/` (fetched by `scripts/fetch-models.sh` or
copied) and are digest-verified before any use.

## 1. NVIDIA driver on the Windows host

CUDA 12.8 user-mode libraries in the container need a host driver **≥ R570** (the CUDA 12.8 minimum).
Check on the host:

```powershell
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
```

Driver below 570 → update from NVIDIA before anything else. The driver must be the Windows driver
with WSL support (every current GeForce driver is); **do not install a Linux driver inside WSL**.

## 2. WSL2 memory — the one that bites on the day

WSL2 gives the VM about half of system RAM by default: **~8 GB on a 16 GB laptop**. Docker Desktop runs
inside that VM. A 9B Q4 model is 5.6 GB on disk, mmaps the whole file, and keeps whatever does not fit
in 4 GB of VRAM in system RAM; llama-server plus the learning plane plus Docker's own overhead do not
fit in 8 GB with a 9B model, and the failure mode is the container being OOM-killed with no useful
message. Fix before the first run: create or edit `%UserProfile%\.wslconfig` on the Windows host:

```ini
[wsl2]
memory=12GB
swap=4GB
processors=4
```

then restart WSL completely (`wsl --shutdown` in PowerShell, then reopen Docker Desktop). Check inside
WSL: `free -g` must show ≥ 11 GB total. 12 GB leaves 4 GB for Windows itself, which is tight but
workable for a demo; close browsers. With the 4B model (2.7 GB) the default 8 GB is enough, which is one
more argument for the 4B on this machine.

## 3. GPU visible inside Docker

```bash
docker run --rm --gpus all ubuntu:22.04 nvidia-smi -L
```

Must print the GTX 1650. If it fails: Docker Desktop → Settings → Resources → WSL integration on for the
distro; the NVIDIA container runtime ships with Docker Desktop, nothing to install inside WSL.

## 4. Offload split — a knob, not a guess

`llama-server` is started with `--n-gpu-layers auto` (`-fit on` is llama.cpp's default), which sizes the
offload to free VRAM at start; the spike runner records what the server actually did (`offloaded N/M
layers to GPU`, buffer sizes) in every result file, so a silent misconfiguration is visible in the data,
not silent. The knob is explicit when needed: `--ngl 20` on `scripts/p4-spike.sh`, or `ULPF_NGL` for the
learning-plane image. Expected on 4 GB: 4B-Q4 (~2.7 GB) fits entirely with KV cache to spare; 9B-Q4
(~5.6 GB) offloads roughly two thirds; 12B-Q4 (~7.2 GB) about half. The runner's `fits_in_vram` field is
the record.

## 5. CPU-only floor

Before any GPU number, run the floor once so it is known to work:

```bash
bash scripts/p4-spike.sh laptop-1650 cpu --models qwen3.5-4b-q4_k_m --cases squid-native --modes per-slot
```

This starts the same image with `--device none`. It must complete; its wall-clock is the number quoted
if the GPU path fails on the day.

## 6. The measurements

```bash
bash scripts/fetch-models.sh                                   # or copy models/cache from the desktop (27 GB); digests are re-verified
bash scripts/build-llama-image.sh                              # or: zstd -d < ulpf-llama.tar.zst | docker load
bash scripts/p4-spike.sh laptop-1650 gpu                        # all six models, all cases, both modes, --repeat 2
bash scripts/p4-spike.sh laptop-1650 cpu --models qwen3.5-4b-q4_k_m qwen3.5-2b-q4_k_m
python learning/tools/spike.py summarize
```

Results land in `spike/results/laptop-1650/` and are committed. The desktop's results are in
`spike/results/desktop-5060ti/`; the report labels every number with its machine.

## 7. Known failure modes

| Symptom | Cause | Fix |
|---|---|---|
| container exits at start, `cudaMalloc failed` / OOM | too many layers for 4 GB, or another process holds VRAM | `--ngl` lower; close the browser's GPU process |
| container killed, no message, `free -g` small | WSL2 memory cap (§2) | `.wslconfig`, `wsl --shutdown` |
| `nvidia-smi` works on host, not in Docker | WSL integration or container runtime | §3 |
| CUDA error mentioning driver/runtime version | host driver < R570 | §1 |
| `the provided PTX was compiled with an unsupported toolchain` | image built for another arch set | rebuild with `75-real;120-real` — the shipped image already is |
| very slow first request | prompt processing on CPU for the non-offloaded layers | expected; onboarding is once per source; the per-slot mode has shorter outputs |
