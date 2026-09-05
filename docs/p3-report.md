# P3 report — learning plane, deterministic half: certificates without a model

**Status: P3 exit criteria met; stopped for verification before P4.** The model provider stayed a
fixture throughout; nothing from P4 was built. Reproduce with `scripts/p3-check.sh` (WSL2; needs the
runtime binary it builds) and `scripts/p2-check.sh` for the container regression.

## 1. Demonstrable outcome — the demo that matters, fixture-powered

Six unseen Squid lines in → structure induced (10-slot positional, one family) → fixture proposes
semantics → acceptance blocks promotion (every mandatory attribute rests on a proposal alone) → the
analyzer emits exactly the trace's certificates → one request → operator supplies the `logformat`
line → all ten fields resolve with device-configuration provenance → promoted → pack emitted →
**loaded by the Go engine fail-closed and six live lines flow through it** (6 emitted, 6 usable,
2 declared nulls). Scripted in `scripts/p3-check.sh`; interactive as `python -m ulpf_learn review`.

| Check | Result |
|---|---|
| Stage 8 — certificates | `pos_3` ambiguous, class `endpoint_orientation`, ranked `src_endpoint.ip > dst_endpoint.ip`; `pos_5` ambiguous, class `volume_direction`, ranked `bytes_out > bytes_in > bytes`; `pos_2` **unresolved**, `no_library_discriminator` (duration vs latency), no request, no guess — §8.3 demo step 3 / **invariant 5** |
| Stage 9 — request | rank-1 `device_logformat_configuration` (free_if_available) for both certificates, **one sufficiency group**, resolving all ten pending fields; alternatives ranked `vendor_schema_field_order` (2), `operator_labelled_session` (3), `paired_flow_telemetry` (4) — the trace's table exactly |
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
3. **Certificates only for competing proposals.** When the provider ranks a single candidate that is
   not structurally determined, the field is recorded as *unevidenced* and covered by the request; no
   competing set is fabricated from the enumeration (tried and rejected, §5).
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

## 4. What was tried and rejected

- **Filling a single proposal's competing set from the enumeration.** Produced `device.location.lat`
  as the "rival" of an epoch timestamp and `action` as the rival of a MIME type — spurious certificates
  that would have inflated the unresolved count and misled the request. Rejected: an ambiguity is a
  provider presenting competing interpretations; a lone proposal is unevidenced, not ambiguous.
- **Resolving certificates by field name.** Broke as soon as the logformat renamed the fields.
  Rejected for slot-keyed resolution (the propagation key is structural anyway).
- **Treating `-` as a coercion failure** (the P2 state). Correct mechanics, wrong semantics for the
  metric: it labelled every denied request as parser failure. Rejected for declared nulls.
- **Deriving `severity_id`.** ASA carries it in the message id, Squid carries nothing; a default is a
  judgement. Rejected for pack declaration with provenance.

## 5. What the next phase inherits

- **P4:** the `Provider` interface (`propose(structure) -> Proposal` with ranked candidates per slot,
  `proposed_by`, `model_hash`) is the seam; the fixture path stays as the fallback switch. The
  acceptance engine and analyzer treat model output exactly as they treat the fixture. Measure
  schema-valid rate and iterations first (plan P4 risk ladder).
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
  emitted ones agree on candidates, class, request and resolution but differ in `created_at` and ids.
