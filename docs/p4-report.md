# P4 report — model integration: the model proposes, the machinery decides

**Status: P4 exit criteria met on the development machine; stopped for verification before P5. Demo-laptop
measurements are outstanding and are the numbers that matter — §4 says exactly which figures come from
which machine, and no latency figure in this report is a demo figure.** Headline from the desktop run: the
model proposes, the machinery decides — six models, five sources, 100% type-compatible labels after the
builder/verifier loop, 0 reasoning leaks, byte-identical repeats; Granite 4.1 8B and Qwen3.5-9B tie on
agreement (0.66) with Granite 4× faster; every model fails exactly where the certificates live (the
unlabelled counters), which is the fixture path's job on the day. Nothing from P5 was built: the
evidence log was not needed to finish P4. Reproduce with `scripts/p4-check.sh` (no model needed) and
`scripts/p4-spike.sh <machine> gpu|cpu` (needs `ulpf-llama` and `models/cache`).

## 1. Demonstrable outcome

Six unseen Squid lines in → structure induced (P3, unchanged) → **a locally served model labels the
slots under a token-level grammar** → the validator refutes what is type-incompatible and the model
answers again (bounded) → the library names the rivals (P3 boundary rule) → the same certificates, the
same one request, the same logformat resolution → pack emitted with `model_hash` = the verified digest
of the weights → loaded fail-closed by the Go engine. The fixture path runs unchanged beside it
(`--provider fixture`, the default): the fallback is a switch.

| Check | Result |
|---|---|
| Stage 6 by the model | the provider returns a `Proposal` shaped exactly like the fixture's (ranked candidates per slot, `proposed_by: model`, `model_hash`); the session, analyzer, acceptance engine and emitter are untouched. **Live, scripted** (`scripts/p4-model-smoke.sh`, Granite 4.1 8B-Q4 on the desktop GPU): six Squid lines → the model proposes → certificates `pos_1` (`temporal_role`, `time` ranked first of six, `proposed_by: model`) and `pos_3` (`endpoint_orientation`, `src_endpoint.ip` (model) > `dst_endpoint.ip` (enumeration)) → blocked by invariant 4 → one `device_logformat_configuration` request → logformat → promoted → `verify-pack` green in Go → pack `model_hash` = `sha256:ed902ac9…` (the Granite digest from the manifest, verified from the file) — **14.9 s wall-clock for the whole session, desktop GPU, not a demo figure**. The bytes-counter certificate the fixture produces is absent because the model left `pos_5` unlabelled (§4.1); the request covered it anyway |
| **Invariant 1** | every model output validates against the emission schema before it is read (by check); the grammar makes the structure and every label a member of the closed sets (by construction); the label must also survive the enumerator, or it is refuted and retried, then abandoned to review — never repaired, never guessed. The parser-spec contract's conditionals (`if/then`, `not`, `propertyNames`, `uniqueItems`) cannot be expressed by llama.cpp's or LLGuidance's grammar converters, so **"schema-invalid output is mechanically impossible" is not a claim this project makes**: emission is by construction for structure, by check for the conditionals |
| **Invariant 2** | `scripts/invariant2-check.sh`: the shipped Go binary (CGO off, static) has two module dependencies (the JSON Schema library and `golang.org/x/text`), no inference/weights strings; the 2.5 MB runtime image has 1496 files, none of them weights, inference libraries or Python — verified by build inspection, not assertion |
| **Invariant 4** | a model proposal alone never promotes: `test_model_proposal_yields_the_same_certificates_as_the_fixture` ends `promotable: False` until the logformat arrives |
| **Invariant 5** | a provider ranking that no library class covers is still an unresolved certificate (the 4B did this on `pos_5` in per-slot mode: `http_response.code` with alternatives → `unresolved`, no guess) |
| Fixture path unchanged | `scripts/p4-check.sh` runs the P3 scripted session through `--provider fixture` after the model path is in: promoted, `verify-pack` green |
| Weights | never in git; `models/manifest.json` (six entries, Hugging Face LFS digests) + git-ignored `models/cache/`; `learning/tools/models.py` verifies at fetch, at image build (`install`) and at container start (`serve` refuses on mismatch) |
| Cross-stack | the op-coverage matrix (§3.3): 45 micro-vectors covering every enum value of the parser-spec contract, both executors byte-identical on every input — after it found two real bugs |
| Contract suites | 22/22 vectors both stacks; 45 learning-plane tests (7 model-provider, 4 op-matrix, 1 zero-certificate request); runtime suite green |

## 2. Deliverables

- `learning/ulpf_learn/model/` — `client.py` (llama-server, greedy/seeded/prompt-cache-off decoding fixed and recorded), `emission.py` (the three emission schemas; `project_for_grammar` for the measurement in §3.1), `prompt.py` (prompt from the induced structure and the onboarding samples only; hashed into provenance), `provider.py` (`ModelProvider`: class step, `whole` and `per-slot` modes, builder/verifier loop, `Trace`, provenance record), `structure_from_spec.py` (a `Structure` from an executed draft spec, so csv/kv/regex sources reach the provider before P6 induces those shapes).
- `SlotObservation.name` (vendor field name when the format carries one); `session.plan_from_proposal`; `--provider model --model-id --server --mode --backend` on the CLI; `proposal_provenance` stored in the session.
- `models/manifest.json`, `learning/tools/models.py` (`list/fetch/verify/install/serve`), `learning/tools/hf_tree.py`, `scripts/fetch-models.sh`.
- `learning/Dockerfile` — `llama-build` (llama.cpp `b10819`, CUDA 12.8.1, `CMAKE_CUDA_ARCHITECTURES=75-real;120-real`), `llama` (server image, 5.8 GB), `learning` (Python + llama-server + one digest-verified model from a bind-mounted cache, verified again at start). `scripts/build-llama-image.sh`.
- Spike: `spike/cases/*.json` (five cases with team-authored ground truth and expected certificate classes), `learning/tools/spike.py` (`run`, `grammar`, `wholespec`, `cases`, `summarize`; starts one container per model, records machine, offload split, VRAM delta, digest, decoding, per-slot judgements), `scripts/p4-spike.sh`, results under `spike/results/<machine>/`.
- `scripts/invariant2-check.sh`, `scripts/p4-check.sh`, `scripts/llama-logprobe.sh`, `docs/demo-laptop-runbook.md`.
- Executor alignment: `learning/tests/op_matrix.py` + `test_op_matrix.py` (§3.3), `learning/tools/op_matrix_diff.py`.
- Analyzer: a request with no certificate when nothing is ambiguous but mandatory fields rest on the provider alone (§5.1).

## 3. Findings that changed something

### 3.1 Grammar coverage — measured, and it changes a claim

Against a running server (`spike.py grammar`): the class schema, the whole-proposal schema (4002, 10 slots,
~1,000-way label enum) and the per-slot schema all compile; the **projected** parser-spec contract compiles;
the **raw** contract does not (`failed to parse grammar`, HTTP 400). The projection drops, by JSON pointer:
`if` ×7, `then` ×8, `not` ×5 (all inside the conditionals), `propertyNames` ×2, `uniqueItems` ×3, plus
`format`/`description`/`default`. Consequence, stated everywhere from now on: **invariant 1 holds by
construction for structure and by check for the conditionals**; nothing unvalidated crosses the boundary
because the full contract validator runs on every output (`jsonschema` in the provider, the Go loader on
the pack). The plan's P4 text and §1 table already carry this phrasing (v1.3); this report and anything
that reaches a slide use it too.

A second, more consequential finding: **the model does not need to emit parser specs at all.** Induction
(P3) already fixes the structure deterministically; what Stage 6 needs from the model is the semantics —
event class and per-slot labels — and that is what the provider asks for. The emission schemas are small,
conditional-free and fully grammar-expressible; the label enum is drawn from the pinned class table (whole
mode) or from the validator's survivors (per-slot mode), so a label the validator cannot judge cannot be
emitted. Whole-spec emission was still measured (§4.5), as the plan's literal deliverable.

### 3.2 Environment — the two machines

- **One CUDA build for both cards.** CUDA 13 dropped Maxwell, Pascal and Volta and made Turing (`sm_75`)
  the minimum; either 12.8 or 13 covers `sm_75` and `sm_120`. The image uses **CUDA 12.8.1** because it
  needs a host driver ≥ R570 where 13 needs ≥ R580 — the laptop's driver is unknown. Build time on the
  desktop: ~75 min (CUDA compile for two real architectures).
- **…and for a host with no GPU driver at all — after a second build.** The first image linked the CUDA
  backend statically; the learning image's start check showed `llama-server` failing on `libcuda.so.1`
  when started without `--gpus all`, i.e. it would not have run on a machine without an NVIDIA driver even
  for CPU inference. Rebuilt with `GGML_BACKEND_DL` (backends as shared libraries loaded at run time) plus
  `GGML_CPU_ALL_VARIANTS` (CPU kernels chosen for the host CPU at run time — the two machines' CPUs differ):
  verified to serve with no GPU attached (2B: CPU-mapped 1.2 GB, 891 MiB projected host memory) **and** to
  load `libggml-cuda` and offload 25/25 layers when a GPU is present. The shipped `ulpf-llama` is this
  build (5.7 GB); the desktop GPU spike ran on the static build (same llama.cpp commit, same kernels),
  retained as `ulpf-llama-static`. The demo laptop has a GPU, so this matters for the P8 packaging claim
  ("runs anywhere in the air-gapped network"), not for the demo itself.
- **Offload is a knob whose effect is recorded, not a guess.** `--n-gpu-layers auto` (llama.cpp's `-fit on`)
  sizes the split to free VRAM; the spike starts the server with `--verbose` (the load summary is only
  logged at that level in this build), captures the log at readiness, and records `offloaded N/M layers`,
  the CUDA/CPU model buffer sizes, the fit projection and the `nvidia-smi` VRAM delta in every result file.
  Silent misconfiguration therefore shows in the data; the explicit override is `--ngl N` / `ULPF_NGL`.
- **WSL2 memory on the 16 GB laptop is the day-of risk**: the default cap is ~8 GB, which does not hold a
  9B (5.6 GB mmapped, the non-offloaded part resident) plus Docker. `.wslconfig` with `memory=12GB` is
  documented with a check in `docs/demo-laptop-runbook.md`; the 4B does not need it.
- **CPU-only floor** is the same image with `--device none`; measured on the desktop in §4.3; the laptop
  run is in the runbook as step 5 and must be done before the GPU numbers.
- The Windows→WSL path mangling that bit the shell in P1–P3 bit Docker volume paths too (`/models` became
  `C:/Program Files/Git/models`); every Docker invocation now lives in a script run under WSL.

### 3.3 Executor alignment — the op-coverage matrix, and what it found on day one

Policy (P3 report §5, now implemented): `learning/tests/op_matrix.py` enumerates the parser-spec contract's
own enums — the ten ops, twelve token classes, ten coerce targets, nine timestamp kinds, three timezone
modes, six decode encodings, `on_failure`, every csv/kv/positional/quoted policy value, both schema versions,
spec- and cell-level `null_values` — and pairs each with a micro-vector (a contract-valid spec plus inputs that
must parse and inputs that must fail). `test_op_matrix.py` fails when an enum value has no vector, when a
vector is not contract-valid, when the reference executor disagrees with the expectation, and when the
reference executor and the Go engine differ on any input (failure `reason` text excepted: wording is not
contract; offset and step are). 45 vectors, ~110 inputs. On the first run it found:

| # | Executor | Bug | Effect | Fix |
|---|---|---|---|---|
| 1 | **Go** | `n*1000/div` overflowed int64 for nanosecond epochs | a 2024 FortiGate `eventtime` in ns became `573947194` ms — **wrong `time` on every FortiOS 6.2+ event**; the P2 replay parsed those lines but never compared the coerced value | `toMillis` divides first |
| 2 | Python | `urllib.parse.unquote` kept an invalid `%zz` escape | Python accepted what Go rejects | strict percent-decoding |
| 3 | Python | regex group names come back as `bytes` from google-re2 | **every regex op failed to compile** in the reference executor — the Squid golden has no regex op, so P3's differential never exercised it | decode names |
| 4 | enumerator | every enumerated attribute excluded for non-integer slots | `http_request.http_method` (a string enum) refuted for a GET/CONNECT slot | membership check for all enums |
| 5 | enumerator | `text`/`word` accepted only `string_t` | the correct label `time` on a PAN-OS/FortiGate textual timestamp cell would be refuted | `timestamp_t`/`datetime_t` accepted for text/word (windowing stays numeric-only) |
| 6 | emission | object paths (`http_request.url`) offered as labels | the 4B chose it for the URL slot three times and was abandoned | objects filtered from the label enum |
| 7 | enumerator | `epoch_auto` window check required one common window for all samples | FortiGate `eventtime` (mixed s/ns across FortiOS versions) refuted the correct `time` for three models in the spike | per-value window membership, as the coercion itself selects |
| 8 | adapter | draft cells carried their *declared* class (`text` for ASA hosts that may be names) | the correct `src_endpoint.ip` was refuted on every iteration for every model | observed class from the values, as induction computes it |
| 9 | enumerator | numeric tokens could not map to `string_t` | `connection_info.uid` / `device.uid` for numeric ids refuted | integer/float accept `string_t`; ip/mac/url stay strict |

Bug 1 is the finding of the phase outside the model: the corpus differential ran 100 Squid lines and
never a nanosecond epoch through both executors. The matrix is now part of `p4-check.sh`; a construct
cannot enter the schema without a vector both stacks must pass.

### 3.4 Thinking, templates and `<think>` leakage

The provider sends `chat_template_kwargs: {"enable_thinking": false}` (llama-server honours it; the
`llama-cli` bug does not apply) and counts any `<think>`/`<|think|>` bytes in an output as a failure
(`think_leak` in every result). §4 reports the count; the small Qwen3.5 series ships with reasoning off and
Granite has no reasoning mode; Gemma 4's is opt-in via a system-prompt token the provider never emits.
Under the grammar the first emitted token is `{` in any case.

## 4. The spike — per model, per machine

Ground truth is team-authored (`spike/cases/*.json`, labelled as such in each file): Squid from the
logformat as resolved in P3; ASA, PAN-OS and FortiGate from the vendors' field references, with
NAT-mapped pairs, hashes, ICMP type/code and management-plane fields expected unmapped. A truth entry may
accept several attributes (`connection_info.uid` or `connection_info.session.uid`) or `null` (unmapped is
correct). Metrics: **type-compatible rate** (rank-1 ∈ validator survivors; by construction 1.0 in per-slot
mode), **agreement** (label ∈ accepted set, over scored slots), **certificate shape** (the expected library
class fires on the expected slot), **out-of-class rate** (the anchored rule's residual: truth is in a
library class, rank-1 is in none of the classes holding the truth), **iterations**, **wall-clock**,
**byte-identity** across two repeats in one server lifetime, **think leak**. `spike.py summarize`
regenerates the tables from the result files.

### 4.1 Development desktop — RTX 5060 Ti 16 GB, Ryzen 7 2700X, 48 GB (NOT the demo machine)

Every model fit entirely in VRAM (`offloaded N/N layers`: 33/33 for the Qwen 9B and 4B, 25/25 for the 2B,
41/41 Granite, 49/49 Gemma), so **these wall-clocks are the "GPU is free" case and say nothing about a 4 GB
card.** 12 lines per case (6 for Squid), 2 repeats. Slot-weighted agreement is correct labels over all
scored slots of the five cases (160); "cert shape" counts the 12 expected (slot, class) certificate pairs.
Regenerate with `scripts/p4-spike-report.sh`.

| model | mode | slot-weighted agreement | type-compat after retries | over-mapped slots | cert shape hits /12 | out-of-class / in-class-truth (59) | abandoned slots | mean iters | mean wall s (GPU, desktop) |
|---|---|---|---|---|---|---|---|---|---|
| qwen3.5-9b-q4_k_m | whole | **0.66** | 65/65 | 10 | 9 | 7 = 0.12 | 16 | 2.4 | 57 |
| qwen3.5-9b-q4_k_m | per-slot | **0.65** | 88/88 | 19 | 6 | 11 = 0.19 | 0 | 1.0 | 112 |
| granite-4.1-8b-q4_k_m | whole | **0.66** | 41/41 | **5** | 9 | **0 = 0.00** | **0** | **1.2** | **14** |
| granite-4.1-8b-q4_k_m | per-slot | 0.49 | 67/67 | 21 | 4 | 4 = 0.07 | 0 | 1.0 | 51 |
| gemma-4-12b-q4_0 (comparison only) | whole | 0.64 | 61/61 | 12 | **11** | 2 = 0.03 | 3 | 2.6 | 47 |
| gemma-4-12b-q4_0 (comparison only) | per-slot | 0.62 | 77/77 | 16 | 9 | 12 = 0.20 | 0 | 1.0 | 110 |
| qwen3.5-4b-q8_0 | whole | 0.62 | 55/55 | 8 | 10 | 2 = 0.03 | 0 | 1.6 | 26 |
| qwen3.5-4b-q8_0 | per-slot | 0.49 | 103/103 | 32 | 7 | 7 = 0.12 | 0 | 1.0 | 99 |
| qwen3.5-4b-q4_k_m | whole | 0.47 | 72/72 | 26 | 10 | 3 = 0.05 | 3 | 2.4 | 28 |
| qwen3.5-4b-q4_k_m | per-slot | 0.44 | 131/131 | 43 | 8 | 13 = 0.22 | 0 | 1.0 | 100 |
| qwen3.5-2b-q4_k_m | whole | 0.10 | 136/136 | 61 | 5 | 38 = 0.64 | 5 | 2.0 | 20 |
| qwen3.5-2b-q4_k_m | per-slot | 0.53 | 64/64 | 17 | 7 | 3 = 0.05 | 0 | 1.0 | 72 |

(FortiGate rows re-run under the corrected `epoch_auto` window rule, §3.3 #7, on the dynamic-backend image;
the other four cases ran on the static build of the same llama.cpp commit.) Event class: 60/60 correct (every
model, every case, both modes). Think leaks: 0/60. Byte-identical across the two in-run repeats: 60/60.
Schema-invalid outputs: 1/60 (a 9B whole-mode answer truncated at the token budget while pretty-printing
alternatives; the retry recovered; budget raised afterwards, §7). Type compatibility after the builder/verifier
loop: 100% in every configuration — the loop does its job — at the price of abandoned slots in whole mode (the
9B abandoned 16 across the five cases, mostly URL slots it insisted on labelling with a string attribute).

**What the numbers say, and do not say.**

- *Agreement is a ranking, not a certification* (§6.6). At equal footprint the **9B-Q4 and Granite 4.1 8B-Q4
  tie at 0.66** in whole mode; Granite gets there in **1.2 iterations and 14 s** against the 9B's 2.4 and 57 s,
  with **zero out-of-class rank-1 labels, zero abandoned slots and the fewest over-mapped slots (5)**. The 4B-Q8
  (4.5 GB) at 0.62 is close behind and 2× faster than the 9B; the 4B-Q4 (2.7 GB, the laptop-fit candidate) drops
  to 0.47 with 26 over-mapped slots; the 2B is unusable in whole mode (0.10, 61 over-mapped) but oddly competent
  per slot (0.53). Gemma 4 12B, above band, does not beat the 9B or Granite on agreement, is the slowest, and has
  the best certificate-shape score (11/12) because it labels the ambiguous counters instead of leaving them
  unmapped. **Recommendation for the laptop run:** measure Granite 4.1 8B-Q4 (5.35 GB, partial offload) and
  Qwen3.5-4B-Q8 (4.5 GB) first; the 4B-Q4 is the only one that fits 4 GB whole and is measurably weaker.
- *Whole mode beats per-slot mode for every model but the 2B*, and is 2–4× faster. Per-slot's grammar makes
  type compatibility a given, but a survivor enum of 700–1,000 attributes invites plausible-sounding wrong
  labels (`http_response.code` for a duration); whole mode's single view of all slots keeps the labels
  coherent. The risk ladder's second rung is therefore the wrong default; it stays as the fallback.
- *Where every model fails is exactly where the certificates live* (`spike.py slots --case squid-native`):
  all six get Squid's timestamp, client IP, URL and the constant `-` column; **none gets the duration or
  the bytes counter** (`unmapped`, `http_response.code`, `status_code`), none gets the method (they choose
  `http_request.version`), and only Gemma recognises the two `/`-compounds. On ASA the NAT-mapped pairs are
  over-mapped by every Qwen (`src_endpoint.ip` for the mapped address) and correctly left unmapped by Gemma
  and Granite; interfaces, direction and protocol are mostly left unmapped.
- *Consequence for the anchored rule and the demo.* When a model labels the bytes slot `unmapped` there is no
  anchor, so no `volume_direction` certificate: the field is still pending and still covered by the
  configuration request (nothing is lost for safety or for the workflow), but the trace's Stage 8 shows
  **two** certificates the fixture produces and the models mostly do not. Certificate shape hits are 8–10
  of 12 for the ≥4B models in whole mode: `endpoint_orientation` fires on every IP slot for every model,
  `temporal_role` fires wherever `time` is proposed, `volume_direction` almost never. **The out-of-class
  residual is rare for the models that matter** (0–12% of in-class-truth slots in whole mode; 64% only for
  the 2B), so per the boundary instruction it is recorded and not fixed.
- *Type-compatibility refutation catches real mistakes — and it caught one of ours.* The refuted labels
  (all recorded in the result files) are overwhelmingly genuine type errors: `src_endpoint.port` for
  interface names, zones and countries (9B, 4B-Q8, Gemma), `dst_endpoint.ip` for an interface, `traffic.packets`
  for FortiGate's `type`/`action`/`service` (the 4B, thirteen slots in one answer), `device.name` for IP
  addresses (2B). Every model labels Squid's URL slot `http_request.url.path` (a string attribute) at least
  once, is refuted, and mostly does not take the feedback naming `http_request.url.url_string` — the 9B
  abandoned that slot. **One refutation was the validator's fault:** FortiGate's `eventtime` mixes seconds
  (FortiOS < 6.2) and nanoseconds (6.2+) in the same file, and the enumerator demanded that every sample fall
  in *one* `epoch_auto` window, refuting the correct `time` for Granite, the 4B and the 9B. `epoch_auto`
  selects precision per value, so the enumerator now does too (§3.3 #7); the FortiGate configurations were
  re-run under the corrected rule (§4.1 shows the re-run).

### 4.2 Demo laptop — GTX 1650 4 GB, 16 GB RAM

**Not measured in this phase**: the laptop was not available to this session. `docs/demo-laptop-runbook.md`
is the procedure; `bash scripts/p4-spike.sh laptop-1650 gpu` writes `spike/results/laptop-1650/` and
`spike.py summarize` merges both machines into one table. Until that run exists, **no onboarding latency
figure is quotable anywhere.** The desktop numbers in §4.1 bound the answer from above only for VRAM fit
(what fits in 16 GB says nothing about 4 GB) and are not transferable for time.

### 4.3 CPU-only floor (desktop Ryzen 7 2700X, 16 threads; the laptop's CPU is different and slower)

The shipped image with `--device none`, no GPU attached. Squid (10 slots) and ASA deny (11 slots), 2 repeats.
Part of this run overlapped with the FortiGate GPU re-run on the same machine, so treat the times as upper
bounds by a small margin.

| model | mode | case | wall s (CPU, desktop) | iters | agreement |
|---|---|---|---|---|---|
| qwen3.5-4b-q4_k_m | whole | squid-native | 266 | 3 | 0.60 |
| qwen3.5-4b-q4_k_m | whole | asa-106023 | 222 | 2 | 0.27 |
| qwen3.5-4b-q4_k_m | per-slot | squid-native | 520 | 1 | 0.50 |
| qwen3.5-4b-q4_k_m | per-slot | asa-106023 | 486 | 1 | 0.73 |
| qwen3.5-2b-q4_k_m | whole | squid-native | 101 | 2 | 0.40 |
| qwen3.5-2b-q4_k_m | whole | asa-106023 | 58 | 1 | 0.36 |
| qwen3.5-2b-q4_k_m | per-slot | squid-native | 198 | 1 | 0.20 |
| qwen3.5-2b-q4_k_m | per-slot | asa-106023 | 215 | 1 | 0.64 |

The floor works: the 4B labels a 10-slot source in **4–5 minutes per proposal on this CPU** in whole mode,
roughly 10× the GPU figure; per-slot mode roughly doubles that. Onboarding is once per source and offline, so
minutes are acceptable as a floor; the laptop's CPU will be slower than this one, which is why the runbook
makes the CPU run the first thing to do there.

### 4.4 Determinism — measured, and the claim is scoped accordingly

- **Within a backend, byte-identical.** 60/60 GPU configurations and 8/8 CPU configurations produced identical
  raw outputs across two repeats in one server lifetime (greedy, seed 0, prompt cache off, one slot).
- **Across a cold restart, identical.** The 4B whole-mode Squid answer from the smoke run (separate container,
  hours earlier) is byte-identical to the full run's.
- **Across backends, not identical.** For the same prompts, the 4B and 2B first whole-mode label answers differ
  between GPU and CPU in **all four** case pairs (class answers agree; per-slot answers agree on 37 of 46 slots).
  Agreement moves both ways (Squid 0.50 → 0.60, ASA 0.36 → 0.27 for the 4B). This is the batch-invariance
  effect the P3 boundary predicted, now observed. **The reproducibility claim is therefore: a proposal is
  reproducible on the recorded backend and decoding configuration.** Recorded and golden proposals are produced
  on CPU, which reproduces on both machines and in CI; the GPU is for exploration and for the interactive demo.
  The backend is part of the provenance record (§5.2) — one more reason it belongs in the pack.
- **MTP not evaluated**: baseline byte-identity across backends does not hold, so the condition for adopting it
  ("byte-identity survives it") has no baseline to be measured against on GPU; on CPU there is no MTP gain to
  chase. Deferred with that reason.

### 4.5 Whole-spec emission (the plan's literal deliverable), as an experiment

With the projected parser-spec grammar (§3.1), the 9B and the 4B were asked to write the parser spec for the
six Squid lines. **Both produced a document that passed the full contract (conditionals included), compiled in
the reference executor and parsed 6/6 lines** — 472 tokens, 14 s (9B) and 9 s (4B) on the desktop GPU. What
they produced is the positional structure induction already computes deterministically, with model-chosen field
names: `timestamp, request_length, client_ip, request_status, response_length, request_method, request_url,
request_protocol, parent_ip, …` — "request_length" for the duration, "parent_ip" for the hierarchy/upstream
compound. That is the §3.1 argument in one artifact: whole-spec emission reproduces what we already have and adds
names that are semantics without OCSF grounding — a label the validator cannot judge. It stays a research note.

## 5. The three items inherited from P3 (plan §5)

1. **A request with no certificate — built.** When no slot is ambiguous but mandatory fields rest on the
   provider alone, the analyzer now issues a request over every pending field for the same free-tier
   evidence a certificate would select (configuration, else vendor documentation), with
   `certificates: []` and `kind: unevidenced_mandatory`; the session enters `awaiting_evidence` instead
   of `blocked`; the same `respond` path resolves it. It is a request kind, not a certificate kind: no
   competing set is fabricated (`test_request_without_certificate_when_nothing_is_ambiguous`). Not a contract
   change (requests are session state).
2. **Proposal provenance beyond `model_hash` — deferred, with a reason.** The pack contract carries
   `model_hash` (`^sha256:…|none:fixture|none:hand-authored$`). The provider records the full provenance —
   model id and digest, llama.cpp build, decoding configuration, grammar hashes, prompt-template hash,
   backend, mode, iterations — in the session (`proposal_provenance`) and in `Proposal.notes`. Putting it in
   the pack is a parser-pack bump (1.2.0: a `proposal_provenance` object); §4.4 says what actually varied,
   and the bump is proposed at this boundary rather than absorbed mid-phase.
3. **Executor alignment — built** (§3.3).

## 6. Raised, not absorbed

1. **Invariant 1 wording** (§3.1) — by construction for structure, by check for the conditionals; the
   "mechanically impossible" phrasing is retired everywhere.
2. **The model labels, it does not write specs** (§3.1). The plan's P4 deliverable said "constrained
   decoding targeting the parser-spec contract"; the architecture's Stage 6 is "the model proposes
   semantics for the induced structure", which is what was built. Whole-spec emission is measured in §4.5
   as the experiment it is; if it is kept at all it is as a research note, not a path.
3. **Go nanosecond-epoch overflow** (§3.3 #1) — a runtime correctness bug fixed in P4 under the
   alignment policy; no contract change, but the P2 report's replay counts were parse counts, not value
   checks, and the P8 measurements must compare values.
4. **Enumerator acceptance widened** (§3.3 #4, #5): string enums judged by membership; `text`/`word`
   accept `timestamp_t`/`datetime_t`. Policy, recorded in `acceptance/policy-v1.json` (enumeration notes);
   the P3 golden session's certificates are unchanged (`pos_1/2/3/5`), its `pos_6`/`pos_10` survivor counts
   grow.
5. **Parser-pack 1.2.0 proposed** (§5.2) — `proposal_provenance`; decide at the boundary.
6. **Ground truth is team-authored and provisional** — the P8 agreement measurement against the Beats
   reference parser via the P6 crosswalk is the real one; the spike's agreement numbers rank models against
   each other, they do not certify any of them.

## 7. What was tried and rejected

- **Whole-spec emission as the provider's output** — see §3.1/§4.5; it works (both models produced a
  contract-valid, compiling spec that parsed every line) and is still the wrong path: the model duplicates
  deterministic induction and adds field names the validator cannot judge.
- **A 8k context** — FortiGate's 72 keys and 600-byte lines overflowed it and one traceback ended the first
  full run; 16k context, fewer shown lines for wide structures, and per-case error isolation with `--resume`.
- **Judging the draft cells by their declared class** and **one common `epoch_auto` window for all samples**
  (§3.3 #7, #8): both refuted correct labels in the first 9B results; both fixed and the affected results
  re-run.
- **A static CUDA link** for the serving binary (§3.2): fails without a GPU driver; dynamic backends instead.
- **`argparse.REMAINDER` for pass-through server arguments** in `models.py` — swallowed `--all`; the first
  fetch silently downloaded nothing. `parse_known_args` instead. (Noted because it cost an hour of a
  download window.)
- **Running Docker from Git Bash** — path mangling; scripts under WSL only.
- **Comparing failure `reason` strings across executors** — wording differs (`'B'` vs `"B"`), and is not
  contract; offset and step are compared, reason is not.

## 8. What the next phase inherits

- **P5:** nothing from P4 blocks it; the evidence log was not needed here. The learning-plane image
  (`learning` target) is built but not yet exercised end to end in a container — P5/P8 packaging.
- **Laptop measurements** (§4.2) — owed before any latency claim; the runbook is the procedure.
- **Parser-pack 1.2.0** (`proposal_provenance`) — boundary decision.
- **P6:** vendor field names are now first-class in the structure (`SlotObservation.name`); the
  per-slot mode with names resolves most csv/kv slots without a request — which is exactly where P6's
  vendor tables and propagation take over; the `structure_from_spec` adapter is P6's interim induction for
  csv/kv until real induction exists.
- **P8:** compare coerced values, not parse counts, in the replay measurements (§3.3 #1).
