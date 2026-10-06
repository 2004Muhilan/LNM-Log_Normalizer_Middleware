# ULPF — Universal Log Pre-processing Framework

Smart India Hackathon 2026 · Problem Statement 26156 (NTRO)

ULPF takes logs from perimeter devices (firewalls, IDS sensors, proxies), keeps every original byte, turns each event
into one common schema (**OCSF 1.3.0**) and delivers it to a **SIEM** (OpenSearch) and a **data lake** (Parquet). It runs
fully offline, ships as Docker containers, and onboards a new log format without anyone writing a parser by hand.

Step-by-step installation: **[SETUP.md](SETUP.md)**.

---

## What makes it different

- **AI proposes, never decides.** A small local model (Qwen3.5-4B, 4-bit, no internet) suggests what each field of a new
  format means. It writes only a declarative description, never code, and a validator checks every suggestion against
  the OCSF type tables. The runtime that parses live traffic (Go) has no model in it at all.
- **Ambiguity certificates.** When the sample lines cannot tell two meanings apart (source or destination? event time or
  logged time?), ULPF does not guess. It issues a certificate naming the candidates and asks for the cheapest evidence
  that settles it: a labelled sample, the vendor's documentation, or the operator's answer. With a prepared answer sheet,
  onboarding a device is one click.
- **Self-healing on format change.** When a known device changes its format, ULPF quarantines the new lines (bytes kept),
  raises an alert and heals by reusing earlier answers by field name. A real FortiGate switched to JSON live healed
  45–47 of about 52 fields automatically; only 6–7 new fields were asked.
- **Raw evidence first.** No event is parsed or delivered until its raw bytes are durable on disk. Sealed segments are
  made immutable by the kernel; a separate committer signs Merkle checkpoints and ships the evidence to an archive.
- **A transparency log for parsers.** Every parser pack is signed and appended to a witnessed Merkle log; the runtime
  refuses any pack that is not in it.
- **Proof of Derivation.** From any SIEM event, ULPF re-runs the exact logged parser on the original bytes and shows the
  output equals the SIEM document, field for field, in a bundle anyone can verify offline. It also prints a draft
  certificate under the Bharatiya Sakshya Adhiniyam 2023, Section 63(4).

## System requirements

| | Minimum | Recommended | What we tested on |
|---|---|---|---|
| OS | Windows 10/11 with WSL2, or Linux | Windows 11 with WSL2 | Windows 11 Pro, WSL2 |
| CPU | 4 cores, virtualization on (VT-x / AMD-V) | 8 cores / 16 threads | AMD Ryzen 7 2700X |
| RAM | 16 GB (WSL given 10 GB) | 32 GB (WSL given 24 GB) for the real-device lab | 32 GB, WSL 24 GB |
| GPU | NVIDIA, 4 GB VRAM, CUDA 12.8 (driver R570 or newer) | NVIDIA, 8–16 GB VRAM | RTX 5060 Ti 16 GB; GTX 1650 4 GB |
| Disk | 60 GB free | 100 GB free, SSD | NVMe SSD |
| Network | internet once, for downloads | — | runs fully offline after setup |

- **Without an NVIDIA GPU** the demo still runs with team-written proposals instead of the model
  (`ULPF_DEMO_PROVIDER=fixture`, or `ULPF_PROVIDER=fixture` in containers). The page says so.
- **Software:** WSL2 with an Ubuntu 24.04 distro, Docker Desktop (WSL integration and GPU support), Git. For the
  real-device lab also: a second WSL distro (Debian) with Docker Engine, Containerlab and vrnetlab, nested
  virtualization enabled, and a free Fortinet account for the FortiGate VM evaluation licence. All covered in
  [SETUP.md](SETUP.md).
- **Container deployment:** a Linux Docker Engine (not Docker Desktop) for ULPF's containers, because published ports
  rewrite the sender's address and ULPF identifies devices by address.

## Running the demo

After the one-time setup in [SETUP.md](SETUP.md). Run these in PowerShell. The paths assume the repository is cloned at
`C:\ulpf` (`/mnt/c/ulpf` in WSL); change them if yours is elsewhere.

1. **Start the lab.** Only needed if the PC or WSL was restarted since the last run; it is safe to run again anyway. It
   uses `docker start` only, so the licence is safe. Wait until it prints `License Status: Valid`.
   ```powershell
   wsl -d Containerlab -- bash /mnt/c/ulpf/demo/devices/fortigate/start.sh
   ```
2. **Start the model** (about 10 s):
   ```powershell
   wsl -d Ubuntu --cd /mnt/c/ulpf -- env ULPF_LLAMA_NGL=99 bash demo/llama-server.sh start
   ```
3. **Stop any running ULPF stack.** The device pre-flight in step 4 needs port 6515 free.
   ```powershell
   wsl -d Containerlab --cd /mnt/c/ulpf -- bash deploy/ulpf.sh down
   ```
4. **Device pre-flight.** It must end with `DEVICE PRE-FLIGHT: PASS`. If the licence isn't Valid, stop there: never
   redeploy the lab.
   ```powershell
   wsl -d Ubuntu --cd /mnt/c/ulpf -- python3 demo/devices/preflight.py
   ```
5. **Start the lab agent,** which lets the System page's device buttons control the lab. It should print
   `lab agent up: fgt_License_Status=Valid`.
   ```powershell
   wsl -d Containerlab -- bash /mnt/c/ulpf/demo/devices/agent/start.sh
   ```
6. **Start ULPF in containers.** It takes about 1–2 minutes and ends with `up. System http://127.0.0.1:8765/ …`. The
   model folder and lab agent address come from `deploy/.env`.
   ```powershell
   wsl -d Containerlab --cd /mnt/c/ulpf -- bash deploy/ulpf.sh up devices
   ```
   If the code has changed since the last build, run `bash deploy/ulpf.sh build` first, the same way.
7. **Open three browser tabs:**
   - System: http://127.0.0.1:8765/
   - Data lake: http://127.0.0.1:8765/lake
   - SIEM: http://127.0.0.1:5601/app/dashboards#/view/ulpf-real-devices

**Afterwards:**
```powershell
wsl -d Containerlab --cd /mnt/c/ulpf -- bash deploy/ulpf.sh down
wsl -d Ubuntu --cd /mnt/c/ulpf -- bash demo/llama-server.sh stop
```

What to press and say on stage: [docs/demo-runbook.md](docs/demo-runbook.md).

## Throughput

Measured on one desktop (Ryzen 7 2700X, 8 cores), evidence log on, exactly-once checked in every run
([docs/throughput.md](docs/throughput.md)):

| What | Events per second |
|---|---|
| Parse and normalize, 1 process | ~10,400 (62,289 with 8 processes) |
| With the durable evidence log, 1 process | 5,232 (27× faster than one write per event) |
| 1 / 2 / 4 / 6 processes | 5.4k / 9.5k / 13.9k / 15.8k |
| Billion-a-day rate (11,574/s) | held by 4 processes: 13.6k–14.0k |

## Project structure

```
.
├── README.md, SETUP.md            this file; step-by-step setup
├── ulpf-implementation-plan.md    the design: stack, eight invariants, contracts, decision log (§11)
├── runtime/                       Go runtime: ingest, evidence, routing, parsing, egress (no model)
├── learning/                      Python learning plane: onboarding, certificates, healing
├── contracts/                     frozen JSON schemas + golden test vectors
├── deploy/                        container deployment (Docker Compose, scaler, init)
├── demo/                          demo apps (System, Generator, Data lake pages), real-device lab, SIEM setup
├── adapters/lake/                 the Parquet data lake writer
├── library/                       vendor field tables and the discriminator library
├── ocsf/                          pinned OCSF 1.3.0 class tables
├── corpus/                        catalogue of public test logs (fetched, never committed)
├── acceptance/                    acceptance policy for promoting a parser
├── models/                        model manifest (weights fetched, never committed)
├── keys/                          trust store: public keys only
├── drafts/                        hand-drafted specs used to freeze the parser language
├── spike/                         model comparison results (which model, which settings)
├── metrics/                       replay mix used for coverage figures
├── scripts/                       bootstrap, phase checks, the gate, benchmarks, release packs
└── docs/                          reports, runbook, throughput, design notes
```

### `runtime/` — the Go runtime

| Path | What it does |
|---|---|
| `cmd/ulpf-runtime` | the main binary: `run` (live ingest), `parse`, `compile`, `verify-pack`, `export`, `derive`, `reconstruct`, `renormalize`, `forward`, `lake` |
| `cmd/ulpf-committer` | signs Merkle checkpoints over sealed evidence and ships segments to the archive; `keygen` |
| `cmd/ulpf-verify` | standalone verifier for evidence bundles and Proof-of-Derivation bundles (public key only) |
| `cmd/ulpf-tlog` | the parser transparency log: append, prove, verify, list, cosign |
| `cmd/ulpf-witness` | the witness that cosigns consistent log checkpoints |
| `cmd/ulpf-bench` | benchmark helper |
| `internal/frame` | framing: newline, RFC 6587 octet counting, UDP, HTTP, multiline, syslog/CEF/LEEF envelopes |
| `internal/evidence` | append-only evidence store, group commit, kernel immutable flag |
| `internal/merkle`, `internal/checkpoint`, `internal/keys` | Merkle trees, signed checkpoints, Ed25519 keys |
| `internal/archive` | shipping to the evidence archive; the bounded local buffer and its deletion rules |
| `internal/route` | routing by structural signature; per-device routing (bindings) |
| `internal/dsl`, `internal/spec`, `internal/spanmap` | the closed parser language, its compiler and byte-exact span maps |
| `internal/pack` | loading parser packs: signature, transparency-log proof, contract and time checks |
| `internal/normalize` | OCSF events with the lineage block |
| `internal/pipeline` | the whole path, hot reload (SIGHUP), quarantine, drift signals |
| `internal/egress` | bounded spool, one cursor per destination, OpenSearch bulk, HTTP, syslog |
| `internal/gap`, `internal/lake`, `internal/mlfeat`, `internal/derivation` | gap records (silences, outages, refusals), the versioned store of corrections, ML feature record, Proof of Derivation |
| `Dockerfile` | images: `runtime`, `committer`, `verify`, `witness`, `binaries`, `test` |

### `learning/` — the learning plane (Python)

| Path | What it does |
|---|---|
| `ulpf_learn/cli.py`, `__main__.py` | `python -m ulpf_learn onboard / onboard-spec / respond / promote / merge / seed-propagation` |
| `ulpf_learn/session.py` | an onboarding session: samples → structure → proposals → certificates → pack |
| `ulpf_learn/induce.py`, `surface.py`, `envelope.py`, `anchors.py`, `draft.py` | structure induction for positional, CSV, key=value, JSON, XML and envelopes |
| `ulpf_learn/model/`, `provider.py` | the local model client (llama.cpp, grammar-constrained) and the fixture provider |
| `ulpf_learn/enumerate_.py`, `analyze.py`, `predict.py` | the validator: candidate attributes from the OCSF tables |
| `ulpf_learn/discriminators.py`, `library.py` | ambiguity certificates and discriminators; operator assertions |
| `ulpf_learn/acceptance.py` | what may be promoted (no mandatory field on a proposal alone; time must be a timestamp) |
| `ulpf_learn/propagation.py` | answers carried over by field name between formats of the same device |
| `ulpf_learn/emit.py`, `signing.py`, `sourcepack.py` | emit, sign and log parser packs; vendor packs |
| `ulpf_learn/dslexec.py`, `plan.py` | Python twin of the parser language; the field plan |
| `ulpf_contracts/` | contract validation shared by the tests |
| `tools/` | `models.py` (fetch/verify weights), `drift.py`, `autoheal.py`, `effort.py`, `coverage_curve.py`, `discover.py` |
| `tests/` | the Python suite |
| `Dockerfile`, `requirements.txt` | the learning image (model bundled); Python dependencies |

### `deploy/` — containers

| File | What it does |
|---|---|
| `ulpf.sh` | one command: `build`, `up generator\|devices`, `scale add\|remove`, `status`, `down`, `purge`, `export`, `import` |
| `compose.yaml` | init, witness, scaler, OpenSearch, Dashboards, SIEM setup, console, generator, optional model |
| `Dockerfile` | the `ulpf-app` image (console, learning plane, lake writer) and the `ulpf-scaler` image |
| `scaler.py` | the only container with Docker access; starts runtime, committer and lake writer per process from a fixed template |
| `init.sh`, `console.sh`, `siem-setup.sh` | first-start keys and shipped packs; console start; OpenSearch setup |
| `destinations.json`, `env.example` | delivery targets; settings template (copy to `deploy/.env`) |
| `check.sh`, `check.py` | end-to-end check of the container deployment (the gate's lane C) |

### `demo/`

| Path | What it does |
|---|---|
| `start-demo.sh` | starts the host-process demo (`devices` for the real devices); `stop` |
| `apps/system.py` | the System console: sources, runtime processes, onboarding and drift jobs, Prove it, APIs |
| `apps/generator.py` | a log-generating application (six formats, drift, attack bursts) |
| `apps/trace.py`, `apps/certificate.py` | the Prove-it round trip; the draft BSA §63(4) certificate |
| `apps/devices.py`, `apps/inventory.json` | real-device controls; which device sits behind which address |
| `ui/` | the pages: `system.html`, `lake.html`, `generator.html`, `theme.css` |
| `devices/fortigate/` | FortiGate lab: `start.sh`, `fortigate-base.conf`, `patch-vrnetlab.py`, `teardown.ps1`, traffic |
| `devices/suricata/` | Suricata IDS on the FortiGate's wire: Dockerfile, offline rules, rsyslog forwarder, `start.sh` |
| `devices/lab.sh`, `devices/agent/` | device actions (connect, format switch, attack); the lab agent for containers |
| `devices/preflight.py`, `devices/final_demo.py` | device pre-flight checks; the final demo driven end to end |
| `siem/` | `siem.sh` (OpenSearch up/down), `setup.py` (templates, rules, dashboards), test stand-in and contract check |
| `llama-server.sh`, `lib.sh` | start/stop the model server; shared settings |
| `reset.sh`, `preflight.sh` | clean state, keys and vendor packs; 17 pre-flight checks |
| `run.sh`, `steps/`, `live/`, `twice.sh` | the scripted six-step and live sequences (used by the gate) |
| `apps-check.sh` | headless check of the demo against a real SIEM |

### `scripts/`

| Script | What it does |
|---|---|
| `wsl-bootstrap.sh`, `wsl-run.sh` | install Go and the Python venv; run a command with the environment |
| `keys-bootstrap.sh` | build the Go binaries, create development keys, sign the golden pack |
| `gate.sh` | the full test gate in parallel lanes (`--laptop` drops the 33-layer lane) |
| `p1-check.sh` … `p8-check.sh` | each build phase's exit checks |
| `release-packs.sh` | sign the shipped parser packs with the release key (release machine only) |
| `p6-build-packs.sh` | build the vendor packs from the corpus |
| `bench/` | throughput and capacity benchmarks |

## Documentation

| Document | About |
|---|---|
| [SETUP.md](SETUP.md) | installation, one step at a time |
| [docs/demo-runbook.md](docs/demo-runbook.md) | what to press and say in the demo; what to do when something hangs |
| [docs/container-deployment.md](docs/container-deployment.md) | the container deployment and process scaling |
| [docs/throughput.md](docs/throughput.md) | every throughput measurement |
| [docs/transparency-and-derivation.md](docs/transparency-and-derivation.md) | parser transparency log and Proof of Derivation |
| [docs/evidence-archive-design.md](docs/evidence-archive-design.md) | the bounded evidence buffer and the archive |
| [docs/real-device-fortigate.md](docs/real-device-fortigate.md), [docs/real-device-suricata.md](docs/real-device-suricata.md) | the real-device lab and what it found |
| [docs/demo-machine-setup.md](docs/demo-machine-setup.md) | GPU, driver, WSL memory and model details |
| [docs/laptop-branch.md](docs/laptop-branch.md) | change history since 2026-09-21 |
| [ulpf-implementation-plan.md](ulpf-implementation-plan.md), `docs/p1-report.md` … `p8-report.md` | the design and each phase's report |
