# ULPF Implementation Plan

**v1.2 — the working reference. Supersedes v1.1.** Changes from v1.1: subset guard added to structural determination (§4.1, P1 exit); propagation-sublinearity correction noted against the architecture (§4.4); ECS→OCSF crosswalk moved to P6 and replay-mix construction to P8, with the decisions retained in P1 (§5); point of no return restated as demo-viable, not requirement-complete (§8).

Companion documents: `ulpf-architecture.md` v0.6 (the specification) and `ulpf-worked-trace.md` (corrected; the behavioural contract — where the two disagree, the trace governs). This document is self-contained: every decision recorded in the architecture's §10 is folded in here as settled fact.

**Process rule:** build proceeds one phase at a time. Each phase ends at a hard stop for verification against its exit criteria before the next begins. No code is written for a later phase while an earlier phase's exit criteria are unmet.

---

## 1. Stack and environment — settled

| Decision | Value | Reasoning (one line each) |
|---|---|---|
| Runtime engine | **Go** | Stdlib regexp is RE2 — linear-time by construction, satisfying the bounded-regex invariant without a dependency; single static binary for the air-gapped container; fastest route to correct concurrent ingest for a small team. |
| Learning plane | **Python** | Model tooling, template mining (Drain3-class), and rapid iteration live here. Two-stack is settled; not revisited. |
| Dev environment | **WSL2 as primary** | The immutability boundary is a Linux capability; it is real from day one, not simulated. The container is native. |
| Packaging | **Containerised from P2** | Requirement (k) is cheap early and expensive late; path, permission, and bundled-weight problems surface in P2/P4, not integration week. Docker/Podman, no network egress. |
| Model | 7–8B quantized, run offline via a llama.cpp-class runner, grammar/JSON-schema-constrained decoding. Weights bundled into the learning-plane image from P4; `model_hash` recorded in pack provenance. |
| Regex dialect | RE2 subset only, both stacks. Python validates every regex through an RE2 binding, so "accepted by learning plane, uncompilable at runtime" is structurally impossible. |
| Signatures | Detached signatures over exact file bytes. No canonical-JSON machinery anywhere. File-based keys, documented as demo-grade. |
| Output targets | OCSF JSON to a JSONL "lake" directory; ML feature tuple `(template_id, parameter_vector, timestamp, entity_ids)` emitted alongside (requirement h, in scope — built in P6). Parquet not required for the demo. |

---

## 2. The eight invariants and how each is tested

These came out of adversarial review; each closes a specific hole. Every one has a test that exists by the phase named, runs in CI thereafter, and is part of that phase's exit criteria.

| # | Invariant | Enforced by | Test | First tested |
|---|---|---|---|---|
| 1 | Model emits a declarative JSON spec, never executable code; our compiler builds the parser | Spec schema validation at the boundary; Go independently re-verifies the static invariants (no overlapping spans, no uncovered bytes unless opaque, bounded regex/nesting/field count/event size, deterministic execution); the closed op set has no eval path | Adversarial specs (overlapping spans, unbounded constructs, non-RE2 regex) rejected at compile, not at parse | P2 |
| 2 | Model never touches a live log; zero inference at runtime | Runtime binary and runtime image have no model dependency | CI build inspection of the Go binary; runtime image inspected for weights/inference libraries; re-verified on the final image in P8 | P4 |
| 3 | Raw bytes hashed and stored before any parsing | Pipeline ordering: framing → raw write → everything else | Kill-test — terminate the process after raw write, before parse; event recoverable from the segment | P2 |
| 4 | A mandatory field backed only by a model proposal is never promoted; provenance recorded per field | Acceptance policy with six provenance categories (§4 below); structural determination computed over the **validator-enumerated** candidate set, never over model proposals | Unit tests: model-only → blocked; one enumerated survivor → promoted as structural determination with the enumerated set recorded; ≥2 survivors → certificate, always | P3 |
| 5 | No applicable discriminator → field marked unresolved; never guess | Discriminator selection is direct lookup; no fallback mapping path exists | Fixture ambiguity outside the six library classes yields an unresolved certificate naming its candidates; no code path assigns a mapping without a provenance record | P3 |
| 6 | Routing resolves to ≤ K=4 candidates then one parser; never try every parser | Compiled decision DAG with hard cap; per-pack declared tiebreaker; then quarantine | Static check that no try-all path exists (from P2, even the interim router is match-or-quarantine); adversarial anchor-defeating event lands in quarantine; candidate-set sizes logged | P2 / P6 |
| 7 | No unbounded buffers in framing or reassembly | Per-connection byte cap + idle timeout; multiline max lines/bytes/wait; overflow emits truncation-flagged events, retained as evidence | Memory held under cap during connection-flood, giant-line, and idle-connection tests; truncated/malformed frames present in the evidence store afterwards | P2 (built mechanisms) / P7 (under load) |
| 8 | Historical normalization immutable; corrections emit a new version | Corrections emit `normalization@v2` with `derived_from`; no write path to prior versions | After a correction, v1 is byte-identical and retrievable; v2 carries `derived_from`; write-to-v1 attempt fails | P8 |

---

## 3. The four data contracts

Frozen at P1 exit. Each is a JSON Schema in a shared `contracts/` location; every instance carries `schema_version` (semver). Post-freeze changes require a version bump, a same-commit golden-vector update, and green tests on both stacks. The Go loader refuses unknown versions — fail closed, same posture as pack signatures. Golden vectors are derived from the corrected worked trace.

**3.1 Parser spec (the DSL).** Closed op set: `literal, regex, csv, kv, positional, quoted, optional, repeated, decode, coerce`. The full schema is drafted in P1 for team review (no prior draft exists), including: whitespace-run handling for positional formats (runs are literal spans, per the trace's `[18:22] "    "`), the RE2-only regex dialect, and explicit bounds (nesting, field count, event size). Freeze is gated by the **sufficiency check**: hand-draft specs for all four vendor families against the op set before freezing; a missing op is fixed pre-freeze or not at all.

**3.2 Span map.** Byte spans over the original raw buffer; three kinds (`semantic`, `literal`, `opaque`); invariant `union == [0, len(raw))`, no gaps/overlaps/out-of-bounds; encoded fields carry both representations (`value`, `raw_span`, `encoding`); byte indexing with `decode_status` for invalid UTF-8.

**3.3 Ambiguity certificate.** Field reference; **the validator-enumerated candidate set** plus the model's ranking over it; itemized evidence status (vendor metadata / structural / held-out / type validity / discriminator availability); status; the matched ambiguity class and selected request; the resolution record when resolved (evidence supplied, provenance category, operator id, timestamp). **No numeric confidence anywhere.**

**3.4 Parser pack.** The §3.9 superset — the trace's Stage 12 is one valid, abbreviated instance:
per-source pack containing per-family parser entries; routing signatures (L0–L4) per family; anchors with `expected_value_domain`, `observed_cardinality`, `anchor_status`; **per-pack declared tiebreaker field** (the secondary discriminator at the K cap); OCSF version + event-class subset pinned; mapping revision; test corpus reference + `corpus_hash`; sample provenance (tier, recorded operator id, sample count); all ambiguity certificates and their resolutions (every resolved field listed — the trace records positions 2, 3, 4, 5, 9); validation scores; `source_timezone` + `timezone_confidence` (promotion is allowed with `timezone_confidence: unresolved`, recorded and surfaced); content hashes — `parser_hash`, `dsl_hash`, `mapping_hash`, `corpus_hash`, `generator_version`, `validator_version`, `model_hash`; `schema_version`; detached signature over the exact file bytes.

---

## 4. Settled decisions register

Recorded here as facts; the plan builds on them without revisiting.

1. **Provenance categories (acceptance policy).** Sufficient for a mandatory field: vendor schema or device configuration; validated discriminator; resolved ambiguity certificate; explicit operator assertion (recorded); **structural determination**. Insufficient: model proposal alone. Structural determination means deterministic validation leaves *exactly one* viable OCSF attribute for a value of this shape/position/enum membership — the evidence is the validator, not the model; the same mapping would be accepted from any source. **Binding interpretation:** the survivor count is computed over a deterministic candidate enumeration per event class over the pinned OCSF subset (a P3 component), never over the model's proposals; the enumerated set is stored in the acceptance record. Guard: two or more survivors always route through a certificate — two bare IPv4 slots are never structurally determined. **Subset guard, binding:** the pinned subset is the **full attribute set of each chosen event class as OCSF defines it** — pinning selects classes, never attributes within a class. Widening the class set can turn a determined field ambiguous (correct behaviour); the inverse is the hazard this guard closes: omitting attributes (e.g. `proxy.ip`, `device.ip` from HTTP Activity) would let an IPv4 value enumerate to one survivor and pass as structurally determined by scope choice rather than evidence.
2. **Discriminator selection is direct lookup:** candidate attribute set → ambiguity class → ranked discriminator list → sufficiency grouping (one request may resolve several ambiguities, as in the trace's Stage 9). No constraint solving.
3. **OCSF validation depth:** pinned subset — the event classes the four vendors map to, each carried **complete** per the §4.1 subset guard (classes pinned, never attributes within a class). Structural determination is relative to this subset; the subset is pinned per pack, so determinations are reproducible.
4. **Resolution propagation key:** same `source_id` + identical L1–L3 signature + same slot index + same token class. Deliberately conservative. **Accepted consequence:** for anchored vendors the family anchor lives in L3, so propagation never crosses e.g. ASA family boundaries; cross-family propagation applies to anchor-sparse structures (Squid). The P6 propagation demo uses Squid accordingly, and external claims about propagation must match this scope. **Pending architecture correction (tracked here so the documents don't drift):** §3.1 currently attributes effort-curve sublinearity to propagation; under this key that attribution is wrong for anchored vendors, where sublinearity rests on template-group clustering, vendor schema, and structural determination. The architecture will be corrected to say so; this plan already builds on the corrected basis.
5. **Checkpoint ladder:** minute + daily. External witness = exported daily root verified on a second machine that has never run ULPF.
6. **Tier 1 authentication:** recorded operator id only.
7. **Quarantine surface:** a listing is sufficient; acting on quarantined events is optional.
8. **Family discovery** (§8.1 item 5a): template clustering plus volume counting over a capture, ranked descending — mining built in P3, ranking surfaced in P6, demoed as the P8 opening.
9. **Certificate review interface is a P3 deliverable** — the demo's face exists from the phase where certificates first exist, and is polished (not introduced) in P8.

---

## 5. Corpus and measurement methodology

**Source: parser test fixtures from open-source log shippers** (Elastic Beats module corpora for ASA, FortiGate, Squid, PAN-OS; Logstash fixtures for additional ASA families), with their `-expected.json` companions as labelled reference output. Real-shaped, multi-family, community-validated. Synthetic generation only if a gap appears, clearly labelled.

Three qualifications, adopted as method:

1. **Licensing gate (P1).** Beats x-pack fixtures are Elastic License 2.0 — not open source. Fixtures are fetched and cached locally, catalogued by hash, and **never committed to the repository or redistributed** in any submission bundle until the license check clears it; Apache-2.0-licensed fixture sources are the identified fallback. Corpus source is attributed in the submission either way.
2. **Agreement, not accuracy** (decision recorded in P1; tooling built in P6). The `-expected.json` files are one production parser's interpretation, expressed in ECS. Results are reported as **agreement with a mature reference parser**; disagreements are hand-adjudicated against vendor documentation and reported. The **ECS→OCSF crosswalk** needed for comparison is itself semantic labelling — it is built and team-reviewed in **P6**, alongside vendor onboarding where the mapping knowledge is in hand, so its errors cannot silently masquerade as parser errors. It has no consumer before the P8 measurements.
3. **Declared replay mix** (decision recorded in P1; constructed in P8). Fixtures carry no traffic-volume distribution, and the headline coverage curve's x-axis is "percentage of live traffic." Replay streams are constructed in **P8** with a **declared, documented volume mix** — a stated assumption, labelled as such wherever the curve is reported. Its only consumer is P8's metrics assembly.

Both measurement items are deliberately kept out of P1, which gates both tracks and must carry only what genuinely blocks other phases.

Effort instrumentation (timestamps on onboarding sessions, evidence-request counts, candidate-set size distributions) records from P3 onward — the coverage curve cannot be reconstructed retroactively.

---

## 6. The cross-language boundary

The main cost of the two-stack decision, handled structurally:

- **Single source of truth:** the four contract schemas in `contracts/`, frozen at P1 exit under the version discipline in §3.
- **What crosses:** the pack file, and only the pack file. Python emits it; Go validates it against the schema **and independently re-verifies the §2.7 static invariants** — the runtime never trusts the learning plane's validation.
- **Testing both sides:** golden vectors consumed by both suites, plus a **differential conformance test in CI** — a Python-emitted pack is loaded by the Go engine, run over the same samples, and the engine's span maps and OCSF output are compared against Python's predictions. Runs on every change to either stack.
- **Regex dialect:** RE2 subset both sides, enforced by an RE2 binding in the Python validator (§1).
- **Fail closed:** unknown `schema_version`, invalid signature, or failed static invariants → the pack does not load.

---

## 7. Phases

### P1 — Contracts, corpus, and the dual-stack harness

- **Goal:** Pin the four contracts and the measurement methodology, and prove both stacks validate them, before anything depends on either.
- **Deliverable:** The four JSON Schemas with golden vectors from the corrected trace; Python and Go validation suites; the DSL schema draft reviewed by the team and frozen after the sufficiency check (hand-drafted specs for all four vendor families against the op set); discriminator library v1 (the six classes, as data); pinned OCSF subset attribute tables for the four vendors' event classes (the raw material of the P3 candidate enumerator); corpus fetched, cached, catalogued by family with the license check complete. Measurement methodology decisions (agreement-not-accuracy, declared replay mix) are recorded here; their tooling is built in P6 and P8 respectively (§5).
- **Demonstrable outcome:** Every golden vector validates in both stacks; a corrupted vector fails in both; a version-bumped vector is refused by the Go loader. The corpus catalogue lists which families each fixture file covers.
- **Exit criteria:** Contract freeze declared under the §3 discipline; DSL sufficiency check passed (any missing op fixed pre-freeze); license verdict recorded with fallback identified if adverse; **subset-guard check** — each pinned subset table verified complete against the OCSF class definition (classes pinned, no attribute omitted within a class, per §4.1).
- **Depends on:** nothing.
- **Deferred to later:** nothing — this phase exists so nothing contract-shaped is deferred.
- **Risk:** Corpus gaps or an adverse license verdict. *Detect:* time-boxed fetch-and-catalogue in the first days. *Fallback:* Apache-2.0 fixture sources; labelled synthetic generation only for genuinely missing families.

### P2 — Runtime vertical slice on a hand-authored pack (Track A)

- **Goal:** Live bytes flow end to end through the containerised Go engine under a hand-written Squid pack, with raw evidence written before any parsing.
- **Deliverable:** File-tail ingest; newline framing with framing metadata; raw evidence write (event_id, SHA-256, append-only segments, OPEN→SEALED→IMMUTABLE lifecycle — Merkle commitment deferred); pack loader (schema + static-invariant verification; signature verification wired to activate in P5); DSL compiler for the closed op set; span parser and span-invariant checker; OCSF JSON emit with the full lineage block; **container build from the first commit** — all exit tests run inside the container under WSL2. The Squid spec is hand-authored, so the §8.1 fallback path exists from the first week.
- **Demonstrable outcome:** The trace's 20 lines produce Stage 7's span map and Stage 13's output JSON (modulo generated ids); byte conservation 100% on every event — inside the container.
- **Exit criteria:** Invariant 1 tests (adversarial specs rejected at compile); invariant 3 kill-test; invariant 7 tests for the built mechanisms; interim router is match-or-quarantine with no try-all path (invariant 6 discipline); golden output matches the trace; container image builds reproducibly.
- **Depends on:** P1.
- **Deferred to later:** syslog/TCP/HTTP/pull ingest, multiline, de-batching → P5/P7; envelope unwrap → P5/P7; Merkle and signing → P5; routing DAG → P6; ML tuple emission → P6.
- **Risk:** Span bookkeeping through `decode`/`quoted` (dual raw/decoded representation) is the fiddliest engine work. *Detect:* adversarial encoding tests in this phase. *Fallback:* restrict v1 `decode` to the encodings the four vendors need.

### P3 — Learning plane, deterministic half: certificates without a model (Track B)

- **Goal:** Reproduce trace Stages 4–12 end to end with a fixture standing in for the model, proving the centrepiece machinery before gambling on inference.
- **Deliverable:** Structure induction (template mining/clustering, token classification, positional templates — the substrate of family discovery); held-out validation; the acceptance policy engine with all six provenance categories, including **the deterministic candidate enumerator** over the pinned OCSF subset (structural determination per §4.1, enumerated set stored in the acceptance record); the ambiguity analyzer; discriminator library loading, class lookup, cost ranking, sufficiency grouping; evidence-request emission and resolution recording; spec and pack emission; a **pluggable candidate-provider interface**, implemented here by a fixture and by hand entry; **the certificate review interface** — a real, working surface (list certificates, show competing candidates and evidence, present the request, accept the response, show re-evaluation), minimal in polish but complete in function.
- **Demonstrable outcome:** The core demo, fixture-powered: 20 unseen lines in → Stage 8's two certificates → rank-1 discriminator selected → operator supplies the logformat directive through the review interface → both ambiguities resolve with `device_logformat_configuration` provenance, propagation recorded → pack emitted → **loaded by the P2 engine, live lines flowing through it**. Also: `http_request.url` and `http_method` promoted via structural determination with their enumerated sets recorded, matching the corrected trace.
- **Exit criteria:** Invariant 4 unit tests (all three branches per §2); invariant 5 test (out-of-library ambiguity → unresolved certificate — this fixture is also §8.3 demo step 3); differential test — the Python-emitted pack validates, loads in Go, and span maps match Python's predictions; effort instrumentation live.
- **Depends on:** P1; P2 for the differential test.
- **Deferred to later:** model provider → P4; propagation across families and discovery ranking → P6; retroactive re-normalization → P8.
- **Risk:** **Known open risk 2 — the discriminator library as built.** *Detect:* run class lookup over fixture certificates for all six classes in the first days of the phase. *Fallback:* narrow v1 to the classes the demo exercises (`endpoint_orientation`, `volume_direction`) and state so — the architecture's honesty posture permits exactly this.

### P4 — Model integration (Track B)

- **Goal:** Replace the fixture with a locally-run 7–8B model emitting schema-valid candidate specs, offline.
- **Deliverable:** Offline runner with grammar/JSON-schema-constrained decoding targeting the parser-spec contract; builder/verifier loop (bounded iterations, abandon-to-review on exhaustion); `model_hash` in pack provenance; prompt assembly from induced structure and onboarding samples only; **weights bundled into the learning-plane container image** (surface size/path problems now, not in integration week).
- **Demonstrable outcome:** Stage 6 produced by the model for Squid and one structured vendor; iteration counts and wall-clock logged on the demo hardware.
- **Exit criteria:** No model output crosses the boundary unvalidated — schema-invalid output is rejected and retried, never repaired downstream (invariant 1); invariant 2 CI check (Go binary and runtime image free of model dependencies); the fixture path still runs unchanged (fallback is a switch, not a rewrite); onboarding wall-clock measured before any latency claim is made anywhere.
- **Depends on:** P3.
- **Deferred to later:** nothing new.
- **Risk:** **Known open risk 1 — model reliability offline.** *Detect:* first-week spike measuring schema-valid rate under constrained decoding and iterations-to-acceptance on Squid. *Fallback ladder:* richer few-shot context (offline) → per-field labelling instead of whole-spec emission → the P3 path: hand-authored specs through identical validation, provenance, and signing. Under full fallback the demo narrative shifts from "model proposes" to "operator authors, system verifies and interrogates" — reduced but honest, and §8.1 already states it.

### P5 — Evidence log completion: Merkle, signing, verification, export (Track A — parallel with P3/P4)

- **Goal:** Turn the P2 segment store into the tamper-evident structure the architecture describes, and make packs actually signed.
- **Deliverable:** Merkle build over sealed segments with the canonical leaf (`H(domain_separator || segment_id || offset || length || raw_event_hash)`); signed checkpoints, minute + daily; commitment strictly post-IMMUTABLE; the privilege boundary as separate processes/containers (evidence store vs committer), **real under WSL2/Linux — append-only/immutable filesystem attributes, no simulation**; standalone verification tool; one-command evidence export (raw bytes + lineage + inclusion proof); pack signing live, fail-closed verification on load; basic syslog UDP ingest with RFC3164/5424 envelope unwrap (so P6's vendors arrive realistically).
- **Demonstrable outcome:** Tamper one byte in a sealed segment → verification names the exact leaf; an export bundle verifies on a machine that has never run ULPF (the declared external-witness pattern); an unsigned or tampered pack is refused at load.
- **Exit criteria:** Ordering test — no Merkle root is ever computed over a writable segment; detached signature over exact file bytes; envelope precedence tests; the committer process demonstrably cannot modify sealed evidence (boundary test, not a flag check).
- **Depends on:** P2 only — runs concurrently with P3/P4 on Track A.
- **Deferred to later:** gap accounting → P7 (its records become leaves here); demo witness ceremony → P8.
- **Risk:** Low technical risk, high scope-creep risk (key ceremony, HSM temptations). *Detect:* any key-management work beyond file-based keys. *Fallback discipline:* file-based keys, documented as demo-grade — the architecture explicitly authorizes this scale.

### P6 — Multi-vendor routing: the DAG, families, propagation, ML emission (joint)

- **Goal:** Route a mixed live stream of four vendors at event-family granularity within the K=4 bound, with resolutions propagating and family discovery ranked.
- **Deliverable:** Full L0–L4 signature construction over unwrapped payloads; anchor admission per the architecture (declared value domain or measured discriminative utility — sample cardinality alone never qualifies); the compiled decision DAG, hard cap K=4, **per-pack declared tiebreaker**, then quarantine; per-source packs with per-family entries; **resolution propagation under the §4.4 key**; **family discovery ranking** (cluster a capture, rank by volume, onboard descending); onboarding of ASA (message-ID anchors), PAN-OS (CSV escaping, enumerated discriminator), FortiGate (KV, arity buckets) through the P3/P4 path; domain-violation → drift-signal quarantine (input for P8); **ML feature emission** — `(template_id, parameter_vector, timestamp, entity_ids)` alongside OCSF JSONL; the **ECS→OCSF crosswalk**, built and team-reviewed here while the vendor mapping knowledge is in hand (§5.2).
- **Demonstrable outcome:** A mixed stream routes every event to the right family parser with candidate-set sizes logged ≤ 4; an unknown source quarantines rather than guessing; onboarding a second Squid-structured family triggers **no repeat evidence request** — propagation shown live; family discovery lists a capture's families ranked by volume; ML tuples appear beside the OCSF output.
- **Exit criteria:** Invariant 6 tests (no try-all path; adversarial anchor-defeating event → quarantine); anchor-admission test (low-sample-cardinality value with no declared domain refused — reintroducing cardinality-only admission is the rejected approach an implementer reaches for first); candidate-set size distribution captured for the K=4 empirical question.
- **Depends on:** P2, P3, P5 (syslog arrival); P4 helps, fixture path suffices.
- **Deferred to later:** forwarded-CEF recursion and remaining transports → P7; drift response → P8.
- **Risk:** DAG value depends on corpus family breadth (P1 risk resurfacing). *Detect:* the candidate-set distribution as families accumulate. *Fallback:* demonstrate on the families the corpus contains and report the distribution honestly — K is a resource bound, not an accuracy claim.

### P7 — Transport, envelope, and framing breadth + gap accounting (Track A leads)

- **Goal:** Everything arrives correctly framed however it arrives, and absence becomes tamper-evident.
- **Deliverable:** Syslog TCP with RFC6587 octet counting and bounded reassembly; HTTP receive; directory-drop pull collector; one multiline mechanism; JSON-array de-batching (N independently framed, independently hashed events); recursive envelope unwrap to two levels, signature over the innermost payload, relay chain recorded; per-peer continuity counters, sequence-gap detection where sequences exist, **gap records committed as evidence-log leaves**.
- **Demonstrable outcome:** The syslog-forwarded CEF stream routes to the correct pack; a batched JSON file dropped in the pull directory explodes into individually hashed events; silencing a source produces a signed gap record the verification tool displays.
- **Exit criteria:** Invariant 7 under load — connection-flood and oversized-message tests hold the memory cap; overflow emits truncation-flagged events; malformed frames retained as evidence, never dropped; envelope-ambiguity test (application text resembling a CEF header) resolves by precedence with raw bytes retained.
- **Depends on:** P2, P5 (gap leaves), P6 (forwarded-CEF routing).
- **Deferred to later:** nothing new.
- **Risk:** TCP reassembly and multiline are bug farms with low demo value per hour. *Detect:* weekly scope check. *Fallback:* cut TCP to newline-framed-only and demonstrate octet counting on a canned capture — framing provenance fields keep the reduced claim honest.

### P8 — Drift detection, versioned correction, polish, metrics, demo (joint)

- **Goal:** Close the loop: drift detected, corrections version rather than overwrite, the review interface is presentable, metrics are assembled, and the demo runs as a script.
- **Deliverable:** Drift monitors (parse-success drop + unknown-signature spike + domain violations) feeding quarantine and re-onboarding through the existing P3/P4 path — no new machinery; retroactive resolution — resolving a retained certificate emits `normalization@v2` with `derived_from`, both queryable; review-interface polish (P3 built it; this phase makes it presentable); final packaging pass on the already-containerised system (bundled weights, no egress — requirement k re-verified, invariant 2 re-checked on the final image); metrics assembly — the **replay mix constructed and documented here** (§5.3), the coverage curve under it, evidence requests per coverage, candidate-set distribution, agreement-with-reference results via the P6 crosswalk with adjudicated disagreements; the scripted demo implementing §8.3's five steps, opening with family discovery.
- **Demonstrable outcome:** The full §8.3 sequence: family discovery → the Squid evidence-request moment with propagation → an out-of-library ambiguity shown unresolved → format broken mid-run, drift detected, re-onboarded → segment tampered and a source suppressed, both surfaced by verification, with the daily root verified on a second machine.
- **Exit criteria:** Invariant 8 tests (v1 byte-identical after correction; `derived_from` on v2; no write path to v1); invariant 2 re-verified on the final image; demo script runs end to end twice consecutively without manual repair.
- **Depends on:** everything.
- **Deferred to later:** nothing — this is the end.
- **Risk:** Integration slip. *Mitigation is structural:* every prior phase ended demonstrable, so P8 assembles rather than debugs; hold a hard freeze margin before the finale in which only the demo script changes.

---

## 8. Parallelisation and the point of no return

**Two tracks.** Track A (Go): P2 → P5 → runtime halves of P6/P7. Track B (Python): P3 → P4 → learning halves of P6. P1 and P8 are joint; P6 is the merge point. P5 depends only on P2 and must run concurrently with P3/P4 — do not serialize it.

**Point of no return: P4 + P5 jointly — demo-viable, not requirement-complete.** P4 completes the demo-that-matters as specified (unseen source in → ambiguity flagged → one evidence request → supplied → promoted → live lines flow, with the model proposing). P5 completes the theme demo (the Merkle tamper proof) — the theme is Blockchain & Cybersecurity, and losing it would read as ignoring the category. Everything after P4+P5 is independently demonstrable and cuttable **as demo**, but not as scope: P6 carries the ML feature tuple (requirement (h), mandatory) and family discovery ranking, which is how the demo opens. Cutting at P4+P5 preserves a coherent demonstration while leaving requirement (h) unmet and the §8.3 opening changed — a conscious trade if forced, not a free one. P3 is the honest floor beneath P4: the same demo, fixture-powered, presented as the hand-authored fallback the architecture documents. Order all work so both tracks reach P4+P5 before anything in P6–P8 is touched.

---

## 9. Risk register — the two known open risks

| Risk | Phase | Early detection | Fallback |
|---|---|---|---|
| A 7–8B model does not reliably emit valid specs offline | P4 | First-week spike: schema-valid rate under constrained decoding; iterations-to-acceptance; wall-clock on demo hardware | Ladder: richer few-shot → per-field labelling → P3 fixture/hand-authored path through identical machinery; narrative shifts to "operator authors, system verifies and interrogates" |
| The discriminator library does not hold up when built | P3 | Class lookup over fixture certificates for all six classes, first days of P3 | Narrow v1 to the demo's two classes (`endpoint_orientation`, `volume_direction`), stated openly; out-of-library remains the honest unresolved path |

Secondary risks (corpus licensing/coverage, span-through-decode bookkeeping, DAG value vs corpus breadth, TCP reassembly scope, integration slip) are carried in their phases above, each with detection and fallback.

---

## 10. Phase-boundary protocol

At the end of each phase: run the phase's exit-criteria checks, present the demonstrable outcome, and stop for verification. The next phase does not start until the previous is confirmed. Contract changes after the P1 freeze follow the §3 version discipline regardless of phase. Anything discovered mid-phase that would alter a contract, an invariant, or a settled decision in §4 is raised at the boundary — not silently absorbed.
