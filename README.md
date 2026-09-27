# ULPF — Universal Log Pre-processing Framework

Smart India Hackathon 2026, problem statement 26156 (NTRO).

Logs from any perimeter device go in; one standard schema (OCSF 1.3.0) comes out; the raw bytes are
preserved and provably unaltered; new sources are onboarded without anyone hand-writing a parser.

It is a two-plane parser compiler. An offline **learning plane** (Python) turns a handful of sample
lines into a signed *parser pack*: it induces the structure deterministically, asks a small local model
only what the fields *mean*, refuses any meaning it cannot evidence, and when a mandatory field is
ambiguous it issues a certificate naming the rivals and asks the operator for one specific piece of
evidence (a device's `logformat` line, a vendor field-order table) rather than guessing. An always-on
**runtime** (Go, one static binary, no model, no network) loads the packs, writes every received byte to
an append-only evidence store *before* interpreting it, routes each event to its family without ever
trying parsers, normalises it, and commits the evidence under signed Merkle checkpoints that an outside
witness can verify with nothing but a public key. Absence is evidence too: a silenced source or a
sequence gap becomes a signed leaf like any event.

Eight invariants govern it, each enforced by a test (plan §2). Seven build phases are complete; the
eighth (automatic drift healing, metrics, polish) is designed and deliberately not built. Everything
here was built one phase at a time, each phase ending in a report that records what was decided, what
was tried and rejected, and what the next phase inherits.

## Three ways in

**The gate, one command:** `bash scripts/gate.sh` — every check, the demo check with the real SIEM, and six steps + the live
sequence twice on both model configurations, in parallel lanes: 12.7 min on the desktop (`--laptop` on the laptop).

### 1. The demo with pages — three applications, everything a button (laptop branch)

```bash
bash demo/llama-server.sh start       # the 4B on the GPU (skip it with ULPF_DEMO_PROVIDER=fixture — the page then says "fallback, not the model")
bash demo/start-demo.sh               # 1 Generator :8780 · 2 System :8765 · 3 Data lake :8765/lake · 4 SIEM (OpenSearch Dashboards) :5601
                                      # stop: bash demo/start-demo.sh stop · fallbacks: ULPF_SIEM_DASHBOARDS=0, ULPF_SIEM=fake
```

What to press and what each page shows: [docs/laptop-branch.md](docs/laptop-branch.md) §5. The six-step page, the earlier
live pages, the standalone log inspector and the recorded-replay bundle (`demo/replay/`) were REMOVED on this branch —
they are on `main`; the six steps and the scripted live sequence still run, in the terminal, and remain the repeatable gate.

### 2. I want to run the live demo — a few hours the first time on a fresh machine, 30 minutes after

Everything runs locally: a 4B model on the GPU labels the fields, the runtime ingests over TCP, a
container plays the external witness. Needs:

| Requirement | Why |
|---|---|
| Linux or WSL2, Docker with GPU access | the model server and the witness are containers |
| NVIDIA GPU with **≥ 4 GB** VRAM and a **driver ≥ R570** (CUDA 12.8) | the 4B in 4 GB with 20 layers offloaded; older drivers refuse the CUDA 12.8 image outright |
| Go, Python 3.12 venv (`scripts/wsl-bootstrap.sh`) | the runtime and the learning plane |
| the corpus cache (`corpus/tools/fetch_corpus.py`, needs network once) | the three vendor packs are onboarded from it at reset |
| one model: Qwen3.5-4B-Q4, 2.7 GB (`learning/tools/models.py fetch --id qwen3.5-4b-q4_k_m`) | digest-verified against `models/manifest.json` |
| ~12 GB disk for the llama.cpp CUDA image, weights and caches | |

Read, in this order:

1. **[docs/demo-machine-setup.md](docs/demo-machine-setup.md)** — what must be true on the machine, in
   the order the problems bite, with everything the first laptop run cost hours to learn: the driver
   check; WSL2 at `memory=10GB` (not 12 — Windows needs the rest); **weights on the WSL ext4 disk, never
   under `/mnt/c`** (the model server stalls for good otherwise); port 8080 may already be taken (it was,
   by Jenkins); `--ngl 20 --ctx 8192` for the 8B or it is slower than CPU; the upstream llama.cpp image
   instead of a 75-minute local CUDA build; the measured timings for both candidate models.
2. **[docs/demo-runbook.md](docs/demo-runbook.md)** — the six steps, what to say and click, the
   pre-flight list, the one-flag fallback per step, and the twice-consecutive timings.

Then:

```bash
bash demo/llama-server.sh start                    # the 4B on the GPU, port 8081
bash demo/reset.sh && bash demo/preflight.sh       # clean state; 15 checks that fail loudly and early
bash demo/run.sh                                   # the six steps (~2 min 40 s; step 2 is the model)
```

### 3. I want to develop on it — a day to read, an hour to build

```bash
bash scripts/wsl-bootstrap.sh                                 # Go under ~/sdk, venv under ~/.venvs/ulpf, env file ~/.ulpf-env
bash scripts/wsl-run.sh python corpus/tools/fetch_corpus.py   # pinned fixtures into the git-ignored cache
bash scripts/wsl-run.sh python ocsf/tools/fetch_ocsf.py       # OCSF 1.3.0 export + source
bash scripts/p1-check.sh                                      # then p2 … p7: each phase's exit criteria, runnable
```

Start with **[ulpf-implementation-plan.md](ulpf-implementation-plan.md)** (v1.6): §1 the settled stack,
§2 the eight invariants and the test that enforces each, §3 the six frozen contracts, §4 the decisions
register, §11 the divergence log — every place the build departed from the plan, with the report that
carries the reasoning. Then the **[phase reports](docs/README.md)** P1–P8 (P8 is the closing account, with the [test-coverage audit](docs/p8-test-audit.md)): each ends with "what was
tried and rejected" and "what the next phase inherits"; they are the project's memory.

| If you want to change… | Read | Then run |
|---|---|---|
| a contract (schema) | [contracts/README.md](contracts/README.md) — every version bump and why | `scripts/p1-check.sh` (golden vectors, both stacks) |
| the parser DSL or executor | plan §4, P2/P4 reports (the op-coverage matrix) | `scripts/p2-check.sh`, `scripts/p4-check.sh` |
| onboarding, certificates, the model provider | P3/P4 reports; `learning/ulpf_learn/` | `scripts/p3-check.sh`, `scripts/p4-check.sh`; `scripts/p4-spike.sh` to measure a model |
| evidence, checkpoints, signing, the witness | P5 report; `runtime/internal/{evidence,checkpoint,merkle}` | `scripts/p5-check.sh` (needs Docker for the capability boundary) |
| routing, families, propagation, ML tuple | P6 report; `runtime/internal/route`, `library/` | `scripts/p6-check.sh` (four-vendor build needs the corpus cache) |
| transports, framing, envelopes, gap records | P7 report; `runtime/internal/{frame,gap}` | `scripts/p7-check.sh` (invariant 7 under load, sized to the machine) |
| versioned corrections (invariant 8), the audit, effort figures | P8 report; `runtime/internal/lake`, `pipeline/renormalize.go`, `learning/tools/effort.py` | `scripts/p8-check.sh` (needs corpus + Docker; zero skips; named tests by name; goldens checked, never regenerated); `bash demo/run.sh 7 7` (correction), `bash demo/run.sh 8 8` (drift healing) |
| the **live sequence**: two generator apps over two ingress connectors → quarantine until a human says *onboard this* → live onboarding (certificates, operator assertion) → hot-loaded pack → two egress connectors → a consumer app's SQLite with its own page; a killed consumer as an evidence leaf and a catch-up from the cursor; format drift healing itself with an alert (and asking about what it has no evidence for); backfill from the evidence log; whitespace drift, the case nothing heals | [live-demo-report.md](docs/live-demo-report.md); `demo/live/` | `bash demo/live/run-live.sh` (screen `5`; `ULPF_LIVE_INTERACTIVE=1` for the dropdowns), `bash demo/live/twice-live.sh`, `bash demo/live/parse-drop-check.sh` |
| coverage under the **declared** replay mix (four stated assumptions), evidence requests per coverage band, candidate-set distribution | P8 report §13; `metrics/replay-mix.json`, `learning/tools/coverage_curve.py`, `docs/metrics/coverage.{json,svg}` | `bash scripts/p8-coverage.sh` (regenerates and compares; `--write` to regenerate; needs the corpus cache) |
| connectors: six ingress paths, three egress sinks, a sink outage as an evidence leaf | P8 report §9; `runtime/internal/egress` | `scripts/p8-connectors-smoke.sh`; `ulpf-runtime run --forward syslog+tcp://host:port --forward https://… --out FILE`, `ulpf-runtime forward` |

The contracts are frozen: a change is a version bump, a same-commit golden-vector update and green
suites on both stacks, recorded in `contracts/README.md`. Anything that touches an invariant or a settled
decision is *raised* in the phase report, not absorbed.

## Layout

| Path | What |
|---|---|
| `contracts/` | The six frozen data contracts (JSON Schema 2020-12), golden vectors, the README of every version bump |
| `learning/` | Python learning plane: contract validation, induction, enumerator, acceptance engine, certificates, discriminators, model provider (llama-server), pack emission and signing, the review CLI, the spike and discovery tools |
| `runtime/` | Go runtime: DSL compiler/executor, framing (newline, RFC 6587, UDP, TCP, HTTP, directory pull, multiline, de-batching, envelope chains), evidence store, routing DAG, normaliser, gap accounting, committer, verifier, Dockerfile |
| `ocsf/` | Pinned OCSF 1.3.0 class tables, cross-checked against the schema source |
| `library/`, `acceptance/` | Discriminator library, vendor tables, crosswalk; per-class acceptance policy |
| `corpus/` | Corpus catalogue (pinned commits and hashes), licence verdict, fetch tools — content is cached locally, never committed |
| `drafts/sufficiency/` | Hand-drafted vendor specs used to check the DSL's sufficiency |
| `models/` | `manifest.json` pins every model by source and sha256; weights are fetched into a git-ignored cache |
| `keys/` | Trust-store layout; dev key pairs are generated locally by `scripts/keys-bootstrap.sh`, never committed |
| `spike/` | The P4 model spike: cases with team-authored ground truth, results per machine |
| `demo/` | The live demo (steps, reset, pre-flight, UI) and the replay-bundle builder |
| `docs/` | Phase reports P1–P8, the test-coverage audit, the demo machine setup, the presenter's runbook |
| `scripts/` | Bootstrap and the `pN-check.sh` scripts — each phase's exit criteria as a command |

## Fixtures and licences

The reference corpus (Elastic Beats module test fixtures, Elastic License 2.0; logstash-patterns-core
specs, Apache-2.0) is **fetched at build time** from commits and content hashes pinned in
`corpus/catalogue.json` into the git-ignored `corpus/cache/`. It is fine to run tests against and not
something to embed in a repository that may become public — git history is permanent. The same rule
covers everything derived from it: the demo state, the replay capture and the replay zip live outside
the tree and are ignored. `corpus/README.md` has the licence verdict and the attribution text; the replay
bundle carries Elastic's licence and a `NOTICE.md` because it does embed fixture lines, for a direct send
only.

Model weights, the OCSF caches and the dev signing keys are likewise reproduced locally and never
committed.

## Reference: commands by phase

<details>
<summary>Onboarding (P3/P4), the model provider, packs</summary>

```bash
cd learning
python -m ulpf_learn onboard --samples ../contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session /tmp/s
python -m ulpf_learn certificates --session /tmp/s      # the ambiguity certificates, incl. the unresolved one
python -m ulpf_learn respond --session /tmp/s --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt"
python -m ulpf_learn promote --session /tmp/s --out /tmp/pack --pack-id squid-native-emitted
python -m ulpf_learn onboard --provider model --model-id qwen3.5-4b-q4_k_m --server http://127.0.0.1:8081 --mode whole ...
python -m ulpf_learn onboard-spec --samples S --spec ../drafts/sufficiency/asa-302013.json --vendor cisco-asa --family-id asa-302013 --unwrap-envelope --provider recorded --recording ../spike/results/... ...
bash ../scripts/fetch-models.sh                          # every manifest model, ~27 GB; or --id for one
bash ../scripts/p4-spike.sh <machine> gpu|cpu            # measure every model on THIS machine
```
</details>

<details>
<summary>Runtime, evidence, verification (P2/P5/P6/P7)</summary>

```bash
runtime/bin/ulpf-runtime verify-pack --pack contracts/golden/squid-native
runtime/bin/ulpf-runtime run --pack A --pack B --source-id relay-01 --input mixed.log --evidence EV --out out.jsonl --quarantine q.jsonl --ml-out ml.jsonl
runtime/bin/ulpf-runtime run --pack P --listen tcp::6514 --silence-after 30s --evidence EV --out -     # RFC 6587, gap records
runtime/bin/ulpf-runtime run --pack P --listen http::8514 --evidence EV --out -                          # POST bodies, JSON arrays de-batched
runtime/bin/ulpf-runtime run --pack P --pull-dir /drop --evidence EV --out -                            # directory-drop collector
runtime/bin/ulpf-runtime reconstruct --evidence EV --out stream.log                                     # byte-exact original stream
runtime/bin/ulpf-committer commit --evidence EV --key keys/dev/ulpf-committer-dev.json
runtime/bin/ulpf-committer daily  --evidence EV --key keys/dev/ulpf-committer-dev.json
runtime/bin/ulpf-runtime export --evidence EV --event-id ev_... --out bundle/
runtime/bin/ulpf-verify evidence --evidence EV --trust keys/trust        # recompute every root, check chain + signatures
runtime/bin/ulpf-verify bundle --bundle bundle/ --trust keys/trust        # the external witness's command
runtime/bin/ulpf-verify gaps --evidence EV --trust keys/trust            # every gap record with its checkpoint and verdict
python learning/tools/discover.py capture.log                            # family discovery, ranked by volume
bash scripts/p5-boundary-test.sh                                         # kernel immutable flag vs an unprivileged committer (Docker)
bash scripts/p5-witness-test.sh                                          # a fresh container verifies an exported bundle
```
</details>

<details>
<summary>Images</summary>

```bash
docker build -f runtime/Dockerfile --target runtime -t ulpf-runtime .     # 2.6 MB, no model, no Python (invariant 2)
bash scripts/build-llama-image.sh                                          # llama-server, CUDA 12.8, sm_75+sm_120 (~75 min); or use ghcr.io/ggml-org/llama.cpp:server-cuda
DOCKER_BUILDKIT=1 docker build -f learning/Dockerfile --target learning --build-arg MODEL=qwen3.5-4b-q4_k_m --build-context models=models/cache -t ulpf-learning:qwen3.5-4b .
```
</details>

From Windows, run any script as `wsl -d Ubuntu -- bash /mnt/c/<path-to-repo>/scripts/<script>.sh`
(from Git Bash, prefix `MSYS_NO_PATHCONV=1`).
