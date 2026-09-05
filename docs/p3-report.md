# P3 report — learning plane, deterministic half: certificates without a model

**Status: P3 accepted 2026-09-05; two boundary items settled before P4 (§6).** The model provider
stayed a fixture throughout; nothing from P4 was built. Reproduce with `scripts/p3-check.sh` (WSL2;
needs the runtime binary it builds) and `scripts/p2-check.sh` for the container regression. §6 records
the boundary work: the ambiguity trigger moved from the provider to the library (implemented; the
numbers in §1 reflect it), and the model and serving runtime for P4 were validated and decided.

## 1. Demonstrable outcome — the demo that matters, fixture-powered

Six unseen Squid lines in → structure induced (10-slot positional, one family) → fixture proposes
semantics → acceptance blocks promotion (every mandatory attribute rests on a proposal alone) → the
analyzer emits the trace's certificates (plus the timestamp's, §6.1) → one request → operator supplies the `logformat`
line → all ten fields resolve with device-configuration provenance → promoted → pack emitted →
**loaded by the Go engine fail-closed and six live lines flow through it** (6 emitted, 6 usable,
2 declared nulls). Scripted in `scripts/p3-check.sh`; interactive as `python -m ulpf_learn review`.

| Check | Result |
|---|---|
| Stage 8 — certificates | `pos_3` ambiguous, class `endpoint_orientation`, ranked `src_endpoint.ip > dst_endpoint.ip`; `pos_5` ambiguous, class `volume_direction`, ranked `bytes_out > bytes_in > bytes` then the class's surviving `packets*` rivals (§6.1); `pos_1` ambiguous, class `temporal_role`, `time` ranked first of six (§6.1 — a shift from the trace's three certificates); `pos_2` **unresolved**, `no_library_discriminator` (duration vs latency), no request, no guess — §8.3 demo step 3 / **invariant 5** |
| Stage 9 — request | rank-1 `device_logformat_configuration` (free_if_available) for every ambiguous certificate, **one sufficiency group**, resolving all ten pending fields; alternatives for `pos_3`/`pos_5` ranked `vendor_schema_field_order` (2), `operator_labelled_session` (3), `paired_flow_telemetry` (4) — the trace's table exactly; `pos_1` adds `relay_header_timestamp` |
| **Invariant 4** | promotion blocked with seven blockers, five of them "rests on a model_proposal only (invariant 4)"; `promote` raises |
| Enumeration | over the complete pinned 4002 table, never over the proposal: `pos_3` 20 candidates / 10 survivors; `pos_5` 259 / 125; `pos_2` 259 / 134; sets stored in every certificate; **no structural determination fired** (as P1 predicted) |
| Stage 10–11 — resolution | logformat rewrites every slot with `vendor_schema_or_device_configuration` provenance (`%>a`, `%<a`, `%<st`, `%rm`, `%ru`, `%Ss` with the `action_id` lookup, `%ts.%03tu` as one epoch token, `%Ss/%03>Hs` and `%Sh/%<a` as `/`-split slots); the three certificates resolve (including `pos_2` → `duration`, settled by the same evidence); `severity_id` asserted as a constant with the operator's provenance; `null_values ["-"]` from the vendor table |
| Stage 12 — pack | validates against the contract in Python; `verify-pack` in Go (dsl_hash, parser_hash recompiled, table_hash) |
| **Differential (the exit criterion)** | Python reference executor == Go engine span maps on all 6 samples **and on the 100 real Beats Squid lines**; Python-predicted normalized output == Go pipeline output (OCSF attributes, unmapped, base attributes) with `_lineage.absent` matching; the emitted pack runs live |
| Cooperative operator absent | `operator_labelled_session` on one line resolves `pos_3` only (`validated_discriminator`); `pos_5` stays ambiguous, its certificate retained; not promotable — the trace's "what this does not show" #2, executed |
| Effort instrumentation | session timeline from the first step; `evidence_requests: 1`, `operator_responses: 1`, wall-clock per step; §8.4's curve can be built from it |
| Contract suites | 22/22 vectors both stacks; 30 learning-plane tests; runtime suite green |

## 2. Deliverables

- `learning/ulpf_learn/dslexec.py` — reference executor mirroring `runtime/internal/dsl` op for op (the sandboxed verifier); the differential test proves byte-level agreement.
- `induce.py` — deterministic structure induction (tokenise, single-arity family, per-slot class widening, structural literals, candidate spec, L4 sketch); other arities are reported as other families, never merged.
- `enumerate_.py` — candidate enumerator over the pinned tables (scalars, depth ≤ 2, type families, port/epoch/enum constraints); every enumeration is recorded.
- `provider.py` + `fixtures/squid-native-proposals.json` — the pluggable provider; the fixture mirrors trace Stage 6 and adds the out-of-library ambiguity on slot 2.
- `acceptance.py` — the engine: coverage from executed span maps, held-out split, six provenance categories, structural determination only over the enumerator with the set stored, blockers with reasons.
- `analyze.py` — certificates, direct library lookup, deterministic ranking, sufficiency grouping, one consolidated request.
- `library.py`, `discriminators.py`, `library/vendor-tables/squid-logformat.yaml` — library loader/ranker; appliers for `device_logformat_configuration` (directive lexer + vendor table → plan rewrite), `operator_assertion`, `operator_labelled_session`.
- `plan.py`, `session.py`, `emit.py`, `predict.py`, `cli.py` — plan model, session state + instrumentation, pack emission (shells out to the runtime for `parser_hash`, validates before writing), normalized-output prediction, the review surface.
- Contracts 1.1.0 (see §3), runtime support for declared nulls / constants / base attributes, `parse` CLI for the differential test, `scripts/p3-check.sh`.

## 3. Raised, not absorbed

1. **`null_values` design** (validated and implemented as the one boundary bump): spec-level default,
   per-cell override with `[]` opt-out; `declared_null` is a **third** absence cause (pack-declared
   evidence ≠ structural ≠ uncoercible); precedence null → class → coerce → `on_failure`; represented as
   a semantic span flagged `declared_null` (the three span kinds stay architectural). The golden
   samples now report **2 declared nulls, 0 uncoercible** — the denied requests read as correct
   behaviour, not parser failure.
2. **`severity_id` is pack-declared** via a `constant` mapping entry with `operator_assertion`
   provenance; `category_uid`/`type_uid`/`metadata` derived mechanically. The pinned index now carries
   `category_uid`; table hashes changed and the cross-check still agrees on all four classes.
3. **Certificates only for competing proposals** — *as delivered*; **superseded at the boundary by §3.8**.
   When the provider ranked a single candidate that was not structurally determined, the field was
   recorded as *unevidenced* and covered by the request; no competing set was fabricated from the
   enumeration (tried and rejected, §4). The rule was provider-dependent, and P4's model most likely
   ranks nothing — see §6.1 for the replacement.
4. **Certificates are keyed to slots, not field names**, because evidence rewrites names (`pos_3` →
   `client_ip`); a certificate resolves only to an attribute in its own enumerated survivors.
5. **Mandatory policy drives the trace's "mandatory" count**: `traffic.bytes_*` is not mandatory for
   4002 under policy-v1, so the request says "2 fields cannot be resolved (1 mandatory)"; the trace's
   prose treated bytes as mandatory. Policy, not contract — noting the divergence.
6. **Only three discriminators have appliers** (`device_logformat_configuration`, `operator_assertion`,
   `operator_labelled_session`). The other six are ranked and offered as alternatives; applying one
   raises "no applier in v1" rather than pretending. P6's vendors decide which come next.
7. **Enumeration depth ≤ 2 and scalars-only** recorded in `acceptance/policy-v1.json` as P3 policy
   (the certificate contract records `table_hash`, not depth).
8. **The library decides ambiguity, anchored on the proposal** (boundary decision, implemented; §6.1).
   For the provider's rank-1 attribute, every ambiguity class it belongs to names its rivals — the
   class's members that survive the validator enumeration, with `pair_of` classes holding the leaf
   fixed and varying the role prefix. Two or more rivals → certificate, whatever the provider ranked;
   the provider's ranking is an ordering hint inside the certificate. A provider ranking ≥ 2 survivors
   that no class covers still yields the **unresolved** certificate (invariant 5). Not a contract change:
   `ranked_candidates ⊆ survivors` and the subset-match class lookup hold by construction. A library
   data change in meaning only: `pair_of` is now load-bearing (header comment updated). Also fixed in
   passing: the enumerator's `timestamp_t` survivor test now applies `epoch_auto`'s four disjoint
   windows to integer and fractional samples alike (P3 checked milliseconds only, so an epoch in
   seconds had no `timestamp_t` survivor and a fractional epoch skipped the check) — policy, not contract.

## 4. What was tried and rejected

- **Filling a single proposal's competing set from the enumeration.** Produced `device.location.lat`
  as the "rival" of an epoch timestamp and `action` as the rival of a MIME type — spurious certificates
  that would have inflated the unresolved count and misled the request. Rejected. (The P3 conclusion
  "a lone proposal is unevidenced, not ambiguous" was itself superseded at the boundary — §6.1 — by
  letting the *library* name the rivals; the enumeration alone never does.)
- **Bare `survivors ∩ class.candidates` as the ambiguity trigger** (boundary, §6.1). Measured on the
  golden session: every word/text slot (`pos_4, 6, 8, 9, 10`) intersects `action_outcome` with 3
  (`action`, `disposition`, `status` are all `string_t`), every integer slot intersects
  `volume_direction` with 6 (`pos_2`, the duration, would have become a byte counter),
  `request_response_role` catches `pos_2` with 5 and `pos_5` with 4, and the `.*` wildcards give
  `pos_3` 4 rivals under `endpoint_orientation` (adding `dst_endpoint.proxy_endpoint.ip`) and 5 under
  `client_server_role`, with no rule to choose between the two classes. Type compatibility is not
  semantic rivalry. Rejected for the proposal-anchored rule.
- **A `min_slots` knob on `temporal_role`** to suppress the certificate on a lone timestamp and keep
  the trace's count of three. Rejected: it reintroduces a structural heuristic over a library-declared
  ambiguity, and it would leave a source whose only unevidenced mandatory field is `time` blocked with
  no certificate and therefore no request. The shift (four certificates, still one request) is accepted
  and recorded instead.
- **Resolving certificates by field name.** Broke as soon as the logformat renamed the fields.
  Rejected for slot-keyed resolution (the propagation key is structural anyway).
- **Treating `-` as a coercion failure** (the P2 state). Correct mechanics, wrong semantics for the
  metric: it labelled every denied request as parser failure. Rejected for declared nulls.
- **Deriving `severity_id`.** ASA carries it in the message id, Squid carries nothing; a default is a
  judgement. Rejected for pack declaration with provenance.

## 5. What the next phase inherits

- **P4:** the `Provider` interface (`propose(structure) -> Proposal` with ranked candidates per slot,
  `proposed_by`, `model_hash`) is the seam; the fixture path stays as the fallback switch. The
  acceptance engine and analyzer treat model output exactly as they treat the fixture — and after
  §6.1 a single-candidate proposal per slot produces the same certificates as the fixture's rankings
  (tested). Model and serving decision: §6.2 and plan §4.11; measure what §6.2 says to measure first.
- **P4, raised not built — a request with no certificate.** A request is only issued from an ambiguous
  certificate. A session whose unevidenced mandatory fields belong to no library class would sit
  `blocked` with `pending_request: None`. With §6.1, every timestamp slot yields a `temporal_role`
  certificate and every IP slot an `endpoint_orientation` one, so in practice the configuration request
  fires and covers the unevidenced fields too; the code path with zero certificates and blockers still
  has no request. P4 decides whether an "unevidenced mandatory fields" request (free-tier
  configuration/documentation) is a certificate-less request or a certificate of a new kind.
- **P4 report obligation — executor alignment.** `dslexec.py` and `runtime/internal/dsl` are two
  implementations of one closed op set; `predict.py` already lacks `compose_datetime`, and the
  differential test only exercises what the corpus exercises, so drift lands first in the newest
  paths. Intended policy (to be stated in the P4 report): an **op-coverage matrix** — every op, class,
  coerce kind, and `on_failure` branch enumerated *from the schema's own enums* gets a paired
  micro-vector executed by both executors, so a new construct cannot enter the schema without a vector
  both stacks must pass; the corpus differential stays as the integration check on top.
- **P5/P7:** envelope unwrap replaces the test-scaffolding header stripping still used by the replay
  tests; the emitted pack has `declared_envelope: raw` and no anchors.
- **P6:** vendor tables for ASA/PAN-OS/FortiGate (the Squid table is the pattern); csv/kv induction
  (P3 induces whitespace positional only); appliers for the remaining discriminators as the vendors
  need them; the routing sketch the session emits (`l3_structural_literals`, `l4_sketch`) feeds the
  DAG; ML feature tuple.
- **P8:** the session timeline is the raw material for §8.4's coverage curve; `normalization_version`
  is in the envelope for corrections.
- **Open, not blocking:** the emitted pack's family description/vendor fields are Squid-specific in
  `emit.py` (vendor/product come from the vendor table in P6); `predict.py` does not model
  `compose_datetime` (unused until FortiGate); the P1 hand-authored golden certificates and the
  emitted ones agree on class, request and resolution but differ in `created_at` and ids, and after
  §6.1 the emitted `pos_5` certificate lists six candidates where the trace-derived golden lists three
  (both valid; the golden stays as the trace wrote it), and `pos_1` has no golden.

## 6. P3→P4 boundary items (settled 2026-09-05)

### 6.1 Ambiguity detection is library-decided, not provider-decided

**Problem raised.** A field was ambiguous only when the provider ranked two or more candidates. A
grammar-constrained 7–9B model most likely emits one attribute per slot, so P4 would have produced no
certificates at all — the artifact the novelty claim rests on would vanish exactly when the model
arrived, and the model would be the thing deciding what the system does not know.

**Proposal validated: "intersect the enumerated survivors with each class's candidates; ≥ 2 → ambiguous."**
Measured with `learning/tools/probe_ambiguity_rules.py` on the golden session before changing anything:

| Slot | Bare intersection (proposal as sketched) | Anchored on the rank-1 proposal, `pair_of` leaf held fixed |
|---|---|---|
| `pos_1` float epoch | `temporal_role` 6; also `endpoint_orientation` 4 and `client_server_role` 6 via `*.location.lat/long` | `temporal_role` 6 (`time, start_time, end_time, metadata.{logged,processed,modified}_time`) |
| `pos_2` integer (duration) | `volume_direction` 6, `request_response_role` 5, `endpoint_orientation` 28, `client_server_role` 40 | `duration` in no class → provider's two ranked survivors, no covering class → **unresolved** (unchanged) |
| `pos_3` ipv4 | `endpoint_orientation` **4** (`dst_endpoint.proxy_endpoint.ip` joins), `client_server_role` 5 — two classes, no rule between them | `endpoint_orientation` **2** (most specific; `client_server_role` 3 is the alternative) — the trace |
| `pos_5` integer (bytes) | `volume_direction` 6, `request_response_role` 4, plus 24/35 endpoint noise | `volume_direction` 6 — the trace's three plus `traffic.packets{,_in,_out}` |
| `pos_4, 6, 8, 9, 10` word/text | `action_outcome` 3 (`action`, `disposition`, `status`), `request_response_role` 18, endpoint wildcards 136/192 | `pos_6` method: `http_response.http_method` does not exist → 0 rivals → unevidenced; `pos_7` url and `pos_10` MIME: 1 → unevidenced |

Answers to the four questions:

1. *Does the intersection reproduce P3's three outcomes?* The bare intersection does not: it turns
   every integer slot into a byte counter and every string slot into an `action_outcome`, and gives
   `pos_3` four rivals under two classes. The anchored variant reproduces `pos_3` exactly and `pos_2`
   exactly, and shifts `pos_5` from three candidates to six (packets are members of the class the
   library itself declares; the model's "bytes" judgement was never evidence).
2. *Does anything become ambiguous that was not?* Yes: the lone timestamp becomes a `temporal_role`
   ambiguity with six candidates. Judged **correct behaviour**, not noise: the rivals are a
   library-declared class, `time` versus `start_time`/`end_time` is a genuine role assignment for a
   transaction log (Squid's `%ts` is the completion time), the request is unchanged (same free-tier
   evidence, same sufficiency group, still exactly one request), and it makes the mandatory `time`
   field certificate-driven on every source — which closes the "no certificate, no request" gap in
   practice. A `min_slots` knob to suppress it was considered and rejected (§4).
3. *Intersection ≥ 2 but the provider's proposal is not in it?* Three distinct cases, none a
   certificate over a set nobody has evidence for: (a) **refuted** — nothing proposed is type-compatible
   with the slot: unevidenced with reason `refuted`, the request covers it; (b) the rank-1 proposal is
   in no class but *some* class intersects the survivors (the `pos_2`/`volume_direction` case): that
   intersection is type compatibility, not evidence that the slot is a counter — unevidenced, not a
   certificate; (c) the provider ranks an in-class attribute plus an out-of-class one
   (`src_endpoint.ip`, `device.ip`): the class decides the set, the extra is dropped and recorded in the
   certificate's structural note. Under the anchored rule the case "evidence says Y or Z, model said X"
   therefore reduces to (a) or (b): the validator refutes, the library stays silent, the acceptance gate
   blocks, the request covers.
4. *Is `ranked_candidates ⊆ survivors` still satisfiable?* By construction in every branch: rivals are
   drawn from the survivors, provider-ranked ones first (`proposed_by: fixture|model`), the rest in
   pinned-table order (`proposed_by: enumeration`). The subset-match class lookup is likewise satisfied
   because every rival is a member of the chosen class. No contract change.

**Rule as implemented** (`analyze._decide`, `Library.rivals`): (1) provider ranked ≥ 2 survivors and one
class covers them all → that class, provider order, then the class's remaining rivals (the P3 rule,
still honoured); (2) otherwise the library, anchored on rank-1: the class with the fewest rivals ≥ 2 —
the most specific claim, ties by library order — provider-ranked rivals first; (3) otherwise provider
ranked ≥ 2 survivors no class covers → unresolved (invariant 5); (4) otherwise unevidenced. Certificates
on the golden session: `pos_1, pos_2, pos_3, pos_5`; unevidenced `pos_6, pos_7, pos_10`; still one
request; the logformat resolves all four. **Certificates survive a single-proposal model:** a test
provider emitting one attribute per slot and no ranking yields the same `pos_1/3/5` certificates with
the same classes and the same resolution (`test_library_decides_ambiguity_not_the_provider`). What the
model can still suppress is a certificate on a slot whose truth is in a class but whose proposal is
not (proposing `device.ip` for a client address): that field is unevidenced, blocked by invariant 4,
and covered by the request — the workflow holds, the certificate for that slot does not exist. Recorded
as the residual limit; the fix, if wanted later, is more library knowledge, never the enumeration.

### 6.2 Model and serving runtime for P4 — validated and decided

Everything below is from documentation and measurement of this machine; **no weights were downloaded
and nothing was run**, so every claim about model behaviour is a hypothesis P4's first-week spike must
measure. The decision itself is recorded in the plan (§1 table, §4.11); this section is the evidence.

**Serving: llama.cpp directly — confirmed.** Grammar constraint at the token level (GBNF, with a
JSON-Schema-to-GBNF converter built in) works offline with no daemon and no registry; MIT licence;
`model_hash = sha256(GGUF)`; the grammar and prompt template are files we hash too. Ollama exposes only
a `format` parameter and pulls from a registry by default; vLLM is GPU-first and impractical here.
Two findings qualify the "invariant 1 by construction" claim:

- **Grammar coverage is partial for the parser-spec contract as written.** The schema uses `if/then`
  ×7, `not` ×5, `propertyNames` ×2, `uniqueItems` ×3, `oneOf` ×9, `allOf` ×3 and 43 `$ref`s including
  the recursive `step`. llama.cpp's converter documents `not`, `if/then/else`, `uniqueItems`,
  `contains` as "hard and/or too slow to support with stateless grammars"; `patternProperties` is
  unsupported; `properties` cannot be combined with `anyOf/oneOf` in one type; nested `$ref`s are
  fragile; numeric bounds are integer-only. **LLGuidance** (build flag `LLAMA_LLGUIDANCE`, needs a Rust
  toolchain) covers `allOf/anyOf`, `patternProperties`, `prefixItems`, `format` and `minProperties`
  far better — but its documentation lists no support for `if/then/else`, `not`, `propertyNames` or
  `uniqueItems` either, so it does not close the gap that matters. **Consequence for P4:** the model
  emits against an *emission grammar* derived mechanically from the contract — the closed op set,
  every enum, every shape and bound kept; the conditionals dropped — and the full contract validator
  (both stacks, already in place) runs on every output; schema-invalid output is rejected and retried,
  never repaired (unchanged exit criterion). Invariant 1 is by construction for structure and by check
  for the conditionals; the report will say so. LLGuidance is the escalation if the projection has to
  drop too much, not the default. The per-slot fallback (plan risk ladder step 2 — one attribute per
  slot from an enum grammar over the validator's survivors) needs no converter at all and is the
  cheaper first experiment; §6.1 makes its output certificate-complete.
- **Thinking mode.** Qwen3.5's chat template inserts an empty `<think>\n\n</think>` block when
  `enable_thinking=false`, and the 0.8B/2B/4B/9B series ships with reasoning **disabled by default**
  (the maintainers' toggle threads are about enabling it). The reported llama.cpp failures concern
  `llama-cli` ignoring `--chat-template-kwargs` (issues #20182/#20409) and PowerShell quoting;
  `llama-server` honours the kwarg and the OpenAI-style `chat_template_kwargs` request field. We do
  not depend on any of that: the provider renders the prompt itself, including the empty think block,
  and the grammar forces the first token to `{` — a reasoning trace has no tokens it can legally emit.
  Confirm on the running model (first-day check): any `<think>` bytes in output = failure.

**Hardware — measured, not estimated (this development machine; whether it is the demo machine is
for you to confirm):** AMD Ryzen 7 2700X (8C/16T, DDR4), 48 GB RAM (WSL2 allotted 23 GB), **NVIDIA
GeForce RTX 5060 Ti 16 GB** (15.1 GB free, driver 595.79, compute capability 12.0 = Blackwell
`sm_120`), 418 GB free on C:. The GPU is visible inside WSL2 (`nvidia-smi`) and inside Docker Desktop
(`docker run --gpus all … nvidia-smi -L` lists it; the `nvidia` runtime is registered). WSL's `nvcc`
is 12.0, which cannot target `sm_120` — CUDA ≥ 12.8 is required; the upstream
`ghcr.io/ggml-org/llama.cpp:server-cuda13` image is built for it (tested upstream on an RTX 5090;
one open issue about bundled compat libraries overriding a newer host driver, #23111 — check on our
595 driver). CPU-only is the fallback and must stay viable: 9B Q4 on this CPU is estimated in the
single-digit tokens/s range, minutes per whole-spec emission — measure. **9B is viable on this GPU** at
Q8_0 (9.5 GB) with room for context; Q4_K_M (5.6 GB) with room to spare.

**Model — assessed independently; Qwen3.5-9B confirmed as primary, the experiment reframed.**
Constraints applied: Apache-2.0 or equivalent; ≤ ~10 GB quantized; maintained GGUFs; 2025-Q4 or newer;
behaviour under token-level constraint; determinism under greedy decoding.

| Candidate | Licence | Released | Notes | Verdict |
|---|---|---|---|---|
| **Qwen3.5-9B / 4B / 2B / 0.8B** | Apache 2.0 | 2 Mar 2026 | Newest dense ≤ 9B (Qwen3.6/3.8 open weights start at 27B); natively vision-language with the projector in a **separate `mmproj` GGUF** — text-only inference loads only the text GGUF; reasoning off by default in this series; GGUFs from lmstudio-community/unsloth/bartowski (9B Q4_K_M 5.63 GB, Q8_0 9.53 GB; 4B Q4_K_M 2.74 GB, Q8_0 4.48 GB); **MTP GGUFs exist** (9B Q4_K_M 5.87 GB); hybrid Gated-DeltaNet attention — recent llama.cpp support, and recurrent state interacts with prompt caching (determinism check must cover it) | **primary**, with 4B and 2B as in-family comparators |
| **IBM Granite 4.1 8B / 3B** | Apache 2.0 | 29 Apr 2026 | Dense decoder-only, **no reasoning mode at all**, built for instruction following and structured JSON/tool output, 512K context, GGUFs published; the design closest to "constrained labelling, predictable output" | **cross-family comparator** — add to the spike |
| Ministral 3 8B / 3B | Apache 2.0 | 2 Dec 2025 | Official Mistral GGUFs; older than the two above | reserve |
| **Gemma 4 12B** | Apache 2.0 (changed from Gemma Terms) | 2026 | The licence objection no longer applies; 12B dense is slightly above the band; official GGUFs incl. Google's QAT Q4_0 (~7–8 GB at Q4); thinking is opt-in via a `<|think|>` token in the system prompt, so it is off unless we add it; no blocker found | **cross-family comparator, Q4 only, comparison not candidate** — admitted above band by decision |
| Llama 3.x, Phi-4, Qwen3-4B-2507 | community / MIT / Apache | 2024–mid 2025 | Licence (Llama) or recency (all) | rejected |

*Judgement.* For this task — label 6–15 slots with OCSF attributes given token classes and sample
values, emit a closed-op-set JSON spec — 9B is likely more than enough and 4B may be; the honest
statement is that we do not know, and the spike is where we find out. Two corrections to the framing:
(1) compare **at equal footprint** as well as within the family — 9B-Q4_K_M (5.6 GB) versus 4B-Q8_0
(4.5 GB) is the fair question "is a bigger model at lower precision better than a smaller one at high
precision for labelling", and 2B-Q8_0 (~2.3 GB) is the floor; (2) add **cross-family**
comparators (Granite 4.1 8B; Gemma 4 12B at Q4, above band, for comparison only) because Qwen and Granite differ in exactly the dimension that matters
here — Granite is non-reasoning by design. Metrics, in order: (a) **type-compatible rate** — rank-1 ∈
validator survivors per slot — the only "schema validity" that is not already 100% by construction;
(b) **agreement with ground truth** on Squid (the logformat) and the nine sufficiency drafts;
(c) **certificate-shape preservation** — rank-1 lands in the right library class so §6.1 fires;
(d) wall-clock per emission, GPU and CPU; (e) **byte-identity across runs** (below). Grammar
dead-ends and max-token exhaustion inside the grammar are counted as failures. Whole-spec emission and
per-slot enum emission are both measured; the ladder order stays as planned.

**Determinism — the reproducibility claim needs qualifying now, before anything is measured.** CPU
inference is deterministic for a fixed thread count. CUDA inference in llama.cpp is *not*
batch-invariant by default: kernel reduction order changes with batch size and slot state, which can
flip an argmax even at temperature 0; the upstream deterministic-kernels PR (#16016,
`GGML_DETERMINISTIC`) was still a draft when last seen. Practical recipe to test first: one slot
(`--parallel 1`), prompt cache off, fixed `n_batch`/`n_ubatch`, greedy (`top_k 1`, `temperature 0`),
fixed seed, identical prompt bytes; then N = 20 runs plus a cold restart, byte-compared. If GPU output
is not byte-identical, the recorded proposal is produced on CPU (deterministic, slower) and the GPU is
used only for exploration — the claim becomes "reproducible on the recorded backend and decoding
configuration", and that configuration is hashed into provenance alongside `model_hash`. **MTP:**
`--spec-type draft-mtp --spec-draft-n-max N`; under greedy decoding the drafted tokens are verified
against the target's argmax, so the sequence is identical in exact arithmetic, but batched verification
changes the numerics — evaluate only after baseline byte-identity is established, adopt only if the
byte-identity test still passes with it on; MTP GGUFs are text-only (no `mmproj`), which suits us.

**Image size.** Learning-plane base (Python + `llama-server`) ~1–2 GB plus one GGUF: ~4 GB with
4B-Q4, ~7.5 GB with 9B-Q4, ~11 GB with 9B-Q8. Weights are **never in the git tree or the build
context**: a `models/manifest.json` (name, source, sha256) is committed, the GGUF is fetched once into
a git-ignored `models/cache/` (the corpus pattern), bind-mounted into the build, verified against the
manifest at build and again at container start — that verified digest *is* `model_hash`. Registry
layers stay under 10 GB with Q4; Q8 9B does not fit one layer comfortably and would need splitting.
Docker Desktop's WSL2 disk grows by roughly twice the image during a build; 418 GB free is fine.

**Band.** "7–8B quantized" is widened to **"≤ 9B dense, Apache-2.0, ≤ ~10 GB on disk"**, recorded in
the plan rather than quietly exceeded; the spike may land on 4B, and smaller is preferred if it labels
as well.

**Provenance question for P4's boundary (not now):** the pack contract carries `model_hash` only. A
proposal's provenance is really (model, quantization, grammar hash, prompt-template hash, decoding
configuration, backend). Whether that becomes a `proposal_provenance` object (a parser-pack bump) or
is folded into `generator_version` is decided when P4 has measured what actually varies.
