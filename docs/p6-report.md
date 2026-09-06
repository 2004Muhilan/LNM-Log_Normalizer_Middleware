# P6 report — multi-vendor routing: the DAG, families, propagation, ML emission

**Status: P6 exit criteria met; stopped for verification before P7.** Nothing from P7 was built. Both
tracks: the Go router became the decision DAG and the pipeline runs every onboarded pack at once; the
learning plane onboards the three anchored vendors through the P3/P4 path. Reproduce with
`scripts/p6-check.sh` (WSL2; the four-vendor build needs the git-ignored corpus cache and writes its
packs under `/tmp` because they contain corpus lines). **One exit item is owed, not met: the ECS→OCSF
crosswalk is built but not yet team-reviewed** (§5.8).

## 1. Demonstrable outcome

**One runtime, four packs, a mixed relay stream.** 98 syslog-wrapped lines — Cisco ASA (four message
families), PAN-OS TRAFFIC, FortiGate traffic, and Squid's two positional families — arrive through one
`ulpf-runtime run --pack … --pack … --source-id relay-01`. The decision DAG routes 95 to their own family
parser: L1 envelope, L2 surface class (json / kv / csv / tokens, read from leading bytes and delimiter
counts), L3 anchors located by the packs' declared locators (ASA's message id by pattern, PAN-OS's log
type by CSV cell 4, FortiGate's `type`/`subtype` by key), L4 arity bucket or token-class sketch. No parser
runs until one family remains. The three adversarial lines quarantine without a parser being touched:
`%ASA-6-999999` and a PAN-OS `WEIRD` log type as **drift signals** (anchor located, value outside its
declared domain); `%ASA-6-302015`, a message id inside the declared domain that no family owns, as
**family-discovery input**. The candidate-set distribution after L4 is `{1: 95, 0: 3}` — no event needed
the K cap, no event reached a tiebreaker.

Every emitted event validates against normalized-event 1.2.0; every event also produced an ML feature
record `(template_id, parameter_vector, timestamp, entity_ids)` that validates against the draft
`ml-feature 0.1.0` contract. The family discovery tool clusters the same 98 lines with no pack and no
parser into 12 clusters ranked by volume, the top five being exactly the five anchored families, with the
drift line ranked last and labelled as drift.

**Propagation, live.** The 10-slot Squid family is onboarded and resolved by its `logformat` (one request,
one response). An 11-slot Squid family of the same source — the same format plus `%>st` — is then onboarded
with the propagation store: all ten shared slots come back resolved under the §4.4 key (`source_id` +
L1–L3 + slot index + token class), compound slots included (`TCP_MISS/200` → `cache_result` and
`status_code`), with their original device-configuration provenance and a note naming the family they came
from. The only question left concerns the new 11th slot; it is not mandatory, so the family promotes with
**zero operator responses**, that certificate retained for P8's retroactive resolution. Both families then
route side by side in the mixed stream (arity separates them at L4).

| Exit criterion | Result |
|---|---|
| **Invariant 6 — no try-all path** | `TestStaticNoTryAllPath`: `router.go` references no parser program and never calls `Parse`; `pipeline.go` calls `Program.Parse` exactly once, on the family the router chose, after `Route`; no loop over packs or families reaches a `Parse`. Checked on every run by `p6-check.sh` |
| **Invariant 6 — adversarial anchor-defeating event → quarantine** | `TestAnchorDefeatingEventsQuarantine`: an ASA id outside the domain, a PAN-OS type outside its enum, a FortiGate `type` outside its enum → `routing_drift`; in-domain values no family owns → `routing` naming the discovery input; an ASA-shaped payload with no anchor → unknown signature; a FortiGate line with the right anchor but a pair count outside the arity bucket → unknown. Reproduced live in the mixed stream (3 quarantined, 2 drift signals) |
| **Anchor admission — cardinality alone never admits** | `learning/ulpf_learn/anchors.py` + `tests/test_anchors.py`: a constant hostname in a 12-line sample and a two-valued `vd` key are refused by name ("sample cardinality alone never admits an anchor"); a declared domain admits and records `observed_cardinality`; a declared domain contradicted by observation is **a drift signal, not an admission**; measured utility admits only a perfect partition over ≥2 families, on probation |
| **Candidate-set distribution captured** | `Stats.candidate_set_sizes` per run (`{"0": 3, "1": 95}` on the mixed stream; `{1: 2, 0: 2}` in the unit test); `TestCapAndTiebreaker` drives 5 same-signature families to `routing_cap` and 2 to `routing_ambiguous` |
| **Propagation demonstrated live, no repeat evidence request** | `p6-build-packs.sh` propagation section and `test_propagation_resolves_a_second_family_without_a_repeat_request`: slots 0–9 propagated, blockers none, pending request resolves only `pos_11`, `operator_responses = 0`, promoted; a different `source_id` receives nothing |
| **ML feature emission (requirement h)** | `--ml-out`: 95 records for 95 events, 0 invalid against `ml-feature 0.1.0`; the ASA tuple names `cisco-asa-fw-01/asa-302013@sha256:…`, the header timestamp, `{device, dst_ip, session, src_ip}`, and a 14-entry parameter vector with the optional user groups as null |
| **ECS→OCSF crosswalk team-reviewed** | **Built, not reviewed.** `library/crosswalk/ecs-ocsf.yaml` (64 rows, every semantic gap annotated) and `learning/tools/agreement.py`; run on ASA 302013: 208 comparable pairs, 100 % agreement after adjudication, 32 known-mismatch-class pairs (timezone and severity semantics), 32 reference-only, 16 ULPF-only. Review is the team's, recorded as owed in §5.8 |
| Onboarding ASA / PAN-OS / FortiGate through the P3/P4 path | Six families (302013, 302014+302016, 106023, 305011+305012, PAN-OS TRAFFIC, FortiGate traffic), each: given draft spec → recorded model proposals → one evidence request → the vendor's field-order documentation as the resolving evidence → promoted, signed, verified by the runtime; merged into three source packs |
| Domain-violation → drift-signal quarantine | `routing_drift` stage and `Stats.drift_signals`, kept apart from unknown signatures (P8's monitor input) |
| Family discovery ranking | `learning/tools/discover.py`: clusters by the router's own surface reading, ranked by volume with cumulative share; drift and in-domain-unowned values reported per cluster |
| Contracts | parser-pack **1.3.0** (additive), normalized-event unchanged at 1.2.0, `ml-feature 0.1.0` draft; 22/22 golden vectors on both stacks (the golden Squid pack is now emitted as 1.3.0); 55 learning tests; runtime suite green; invariant 2 green |

## 2. Deliverables

- **Runtime.** `runtime/internal/route/router.go` — the DAG (`New(packs…)`, `Route(payload, envelope)`,
  `Decision{Pack, Family, Signature, Candidates, Stage, Reason, Drift}`, `K = 4`); surface readers
  (`detectL2`, `csvCells`, `kvPairs`, `classify`), anchor locators (pattern / slot / key /
  envelope_header) scoped to the surface class their pack's families live in; `tiebreak` (reports, does
  not apply — §5.3). `runtime/internal/pipeline` — `Options.Packs`, `Options.SourceID`, `Options.ML`;
  stats `candidate_set_sizes`, `drift_signals`, `ml_records`, `emitted_by_family`; quarantine stages
  `routing | routing_ambiguous | routing_cap | routing_drift`. `runtime/internal/mlfeat` — the tuple.
  `runtime/internal/pack` — `Anchor`, `AnchorValues`, `RoutingSignature.L3AnchorValues`, `checkAnchors`
  (fail closed), `Anchor.InDomain`. `runtime/internal/frame` — PRI-only envelopes. `normalize` — mapped
  `metadata.*` attributes are no longer overwritten by the mechanical `metadata` block (found by the
  agreement tool, §3.6). CLI: `run --pack` repeatable, `--source-id`, `--ml-out`.
- **Learning plane.** `library/vendor-tables/{cisco-asa,panos-traffic,fortigate-traffic}.yaml` — the
  vendors' field-order documentation as data: fields → attributes with transforms, per-family constants,
  declared anchors with domains, envelope-sourced fields; `discriminators.apply_vendor_schema`
  (`vendor_schema_field_order`, the fourth applier). `anchors.py` (admission). `envelope.py` and
  `surface.py` — Python twins of the runtime's unwrap and surface reading, pinned by tests to the same
  lines the Go suite pins. `session.onboard_spec` (structure given by a spec; the model labels its
  fields), `propagation.py` (`Store.record/apply`, keyed per §4.4, slot-granular), `sourcepack.merge`,
  `provider.RecordedProvider` (replays the P4 spike's Granite proposals by field name). CLI:
  `onboard-spec`, `merge`, `--provider recorded --recording`, `--propagation-store`.
  `emit.py` writes 1.3.0 (`envelope_field`, `l3_anchor_values`, source identity from the table, anchors).
- **Tools.** `learning/tools/discover.py` (family discovery ranking), `learning/tools/agreement.py` +
  `library/crosswalk/ecs-ocsf.yaml`.
- **Contracts.** `contracts/parser-pack.schema.json` 1.3.0; `contracts/ml-feature.schema.json` 0.1.0
  (draft); both validators accept 1.3.0; the Python validator accepts `ml-feature`.
- **Scripts.** `p6-check.sh`, `p6-build-packs.sh` (the whole four-vendor story; packs under `/tmp`),
  `go-test-p6.sh`, `py-test.sh`, `gofmt-w.sh`, `p6-inspect.sh`.
- **Fixtures.** `learning/fixtures/squid-native-11.log` (the trace's six lines plus `%>st`; the second
  Squid family) and its proposals in `squid-native-proposals.json` under arity 11.

## 3. Findings and decisions

1. **The router's L2 is a surface class, not the pack's `l2_structure`.** `positional`, `template` and
   `mixed` all look like whitespace tokens before parsing; only `csv`, `kv` and `json` have a leading-byte
   or delimiter signature. The DAG therefore detects four surface classes and lets L3 (anchors) and L4
   (sketch) separate the rest. Detection is ordered and deterministic — json by leading brace, kv when
   three of the first six tokens are `key=`, csv at nine or more cells outside quotes — and pinned in both
   stacks (`TestDetectL2`, `test_surface_twin_matches_the_router_reading`).
2. **Anchor locators must be scoped to their surface.** The first discovery run showed
   `panos-log-type=TCP` "drift" on every ASA line: the PAN-OS cell-4 locator was being read against
   whitespace tokens. A slot or key locator now reads only the surface class its pack's families live in
   (envelope-header locators are exempt). Both stacks.
3. **The candidate set is 1 or 0 on this corpus.** Five anchored families and two anchor-sparse positional
   families never share an L1–L4 key. K=4 was not exercised by real data; the cap and the 2..K path are
   exercised by constructed packs in the unit test. Reported as the honest answer to the plan's "K=4
   empirical question": *on the four reference vendors the DAG resolves to one family; the bound has not
   been needed yet* — the distribution is logged on every run so P8's replay mix can revisit it.
4. **Recorded proposals are the reproducible onboarding path.** The P4 spike stored the model's per-field
   outputs; `RecordedProvider` replays them by field name, so the vendor build runs identically on any
   machine, no GPU, no server — and it is the model's judgement, not a fixture: provenance names the
   recording, the model digest and the backend. The live path (`--provider model`) is unchanged.
5. **Propagation's unit is the slot, not the mapping.** The first store keyed mappings; compound slots
   (two parts under one key) overwrote each other and only 7 of 10 slots propagated. The key names a slot
   (as does a certificate's `propagation_scope`), so the store now records the slot's split, parts,
   coercions and mappings together — and an unmapped slot the evidence named (`%[un` as a vendor extension)
   counts as resolved, while an unmapped slot that merely lacks a proposal does not.
6. **A normalize bug, found by measuring agreement.** The runtime built `metadata` after applying the
   mappings and overwrote a pack-mapped `metadata.event_code`. The agreement tool reported it as
   "reference-only" on every ASA line. Fixed; a case for building the measurement tooling before P8.
7. **Vendor packs live under `/tmp`.** Their `samples/` are corpus lines (ELv2). The check script builds
   them on demand; nothing derived from the corpus is committed. The unit tests use synthetic lines and
   the trace's six.
8. **FortiGate arrives as a PRI with no header.** `<189>date=…` is not RFC 3164's header form, and P5
   classified it `none`, which would have handed `<189>` to the KV parser. RFC 3164 §4.3.3 says a PRI
   followed by no valid TIMESTAMP is content after the PRI; both unwraps now do that (§5.5).

## 4. Agreement is an effort metric, not a correctness metric

The agreement tool exists so P8 can report *how far ULPF and one production parser read the same line the
same way*. The ASA 302013 run: 16 of 46 lines have a reference document (the Beats expected file covers
100 of the fixture's 268 lines); over those, 208 comparable pairs agree after adjudication. What did **not**
agree, and why it is not a parser disagreement:

- `@timestamp` — the reference says `2018-10-10T12:34:56.000-02:00`; ULPF says 12:34:56 UTC. The line
  carries no zone; Filebeat's test harness pins one, the pack says `timezone_confidence: unresolved` and
  keeps the wall clock. A **known mismatch class** (timezone assumption), like the year assumption.
- `event.severity` vs `severity_id` — a syslog severity number against a pack-declared OCSF enum: never
  numerically comparable, declared so in the crosswalk.
- `event.code` — `302013` against `%ASA-6-302013`: the same fact at two granularities (the draft captures
  the whole tag). **Adjudicated**: compared by suffix; splitting the tag is a spec refinement, not a
  disagreement.
- Reference-only: `network.iana_number`, `event.action` — Filebeat enrichments derived from the message
  id, not in the line. ULPF-only: `action_id` — the pack declares it per family; the reference has no
  `event.outcome` on these lines.

None of this says the pack is right. It says two parsers read alike where the line carries the fact, and
disagree only where one of them added something the line does not carry. The crosswalk's own errors would
be a third source, which is why its review is separate from the parsers (§5.8).

## 5. Raised, not absorbed — including trace corrections (standing obligation)

1. **parser-pack 1.3.0 — `envelope_field` mapping source, forced by mandatory `time`.** ASA payloads carry
   no timestamp; `time` is mandatory for 4001; the syslog header is the device's clock. The pack now
   declares `envelope_field: timestamp → time` with a `timestamp` transform and vendor provenance. The
   alternative — the runtime "falling back" to the header — would be a silent derivation. Additive; both
   validators accept 1.0.0–1.3.0. **Needs approval.**
2. **parser-pack 1.3.0 — `routing_signature.l3_anchor_values`.** The 1.0.0 contract had pack anchors and
   per-family `l3_anchor_ids` but no place for *which values* route to a family; without it L3 cannot
   select. Added as an optional array, cross-checked against the anchor domain at load (fail closed).
   **Needs approval.**
3. **The per-pack tiebreaker is not evaluable before parsing.** The plan and the contract type it as a
   `field_path`, which in general only the parser can resolve, and no family declares the tiebreaker
   values it owns. Evaluating it by parsing would be the try-all path invariant 6 forbids. P6's DAG
   **reports** a declared tiebreaker and quarantines at 2..K with the candidates named; >K quarantines at
   once. **Boundary decision:** either (a) parser-pack 1.4.0 retypes the tiebreaker as an anchor-style
   locator with per-family values (it then *is* a second-tier anchor), or (b) the plan drops the
   tiebreaker and "K-cap → quarantine" stands. No pack in this phase declares one, and no real event
   reached 2..K, so nothing is blocked by the choice; I recommend (b) unless a vendor needs (a).
4. **L1 filter semantics.** A family declaring `raw` has no envelope requirement (the same payload arrives
   with or without a relay header; P5's tests already route syslog-wrapped Squid); a family declaring a
   syslog envelope requires one of either RFC form (relays rewrite 3164 as 5424). The plan's "L1
   signature" reads as exact match; this is looser and deliberate.
5. **Envelope unwrap rule added.** PRI-only lines are an rfc3164 envelope of the PRI alone (RFC 3164
   §4.3.3). The P5 test that asserted `none` for `<189>date=…` was corrected. No schema change (`kind`
   stays `rfc3164`; `priority/facility/severity` are already optional).
6. **ML feature tuple — a draft sixth contract.** `contracts/ml-feature.schema.json` 0.1.0, validated by
   the Python stack and by the vendor build, not yet by the Go loader. Requirement (h) is met by the
   emission; whether the shape is frozen as a contract (and the Go loader gains the kind) is the
   boundary's call. The vocabulary of `entity_ids` (src/dst ip and host, users, device, rule, session) is a
   projection choice worth a second pair of eyes.
7. **Evidence record `source_id` on a mixed stream.** Routing happens after the raw write (invariant 3),
   so the record cannot name the routed pack; it carries the stream's declared source (`--source-id`,
   required when more than one pack is loaded) and lineage carries the routed pack's source. The
   trace's Stage 13 assumes one source per record; a relay stream has two source notions.
8. **Crosswalk team review is owed.** `library/crosswalk/ecs-ocsf.yaml` is drafted with every semantic gap
   annotated and one row adjudicated from measurement; the exit criterion says team-reviewed. It is not.
   The review should happen before P8 consumes it; the rows to look at hardest are the two
   `set-of-known-mismatch` rows and the byte-direction rows.
9. **Trace corrections.** (a) Stage 12: the pack is 1.3.0 and, for header-timestamped sources, carries an
   `envelope_field` mapping and `l3_anchor_values`; the trace's Squid pack is unaffected except for the
   version string. (b) Stage 13: `_lineage.source_id` is the routed pack's source; on a relay stream the
   evidence record's `source_id` is the stream's (item 7). (c) §3.4 routing: the trace describes
   "signature match"; the DAG's L2 is a surface class and its output key is
   `l1|surface|anchors|arity[|classes]` — the `routing_signature` string in lineage changed shape.
10. **Plan §11 rows 30–37** record the above; plan header bumped to v1.5.

## 6. What was tried and rejected

- **A cardinality-based anchor admission** — never written; the test that refuses it by name is the
  deliverable, because it is the first thing an implementer reaches for and the architecture's revision
  notes reject it.
- **Reading a slot locator against every surface** — produced spurious drift on every ASA line; scoped to
  the pack's surface class instead.
- **Propagation keyed per mapping** — lost compound slots; keyed per slot instead.
- **Evaluating the tiebreaker by parsing the candidates** — the try-all path; refused, raised.
- **Treating `<189>date=…` as no envelope** (P5) — would hand the PRI to the parser; corrected per RFC 3164
  §4.3.3.
- **Letting the pack's samples ride into git** — corpus lines; the vendor build writes under `/tmp` and
  the unit tests use synthetic lines.
- **A test fixture that proposes nothing** for the vendor path — the session correctly sits "blocked" with
  nothing to ask (P4 design: a request needs a proposal to be about); the recorded provider is the honest
  input.

## 7. What the next phase inherits

- **P7 (transports and framing):** the DAG takes the unwrapped payload and an `*Envelope`; recursive
  unwrap and forwarded-CEF only need to hand it the innermost payload and outermost envelope. `--source-id`
  on mixed streams is a P7 question too (per-listener source ids).
- **P8:** `routing_drift` and `drift_signals` are the monitor input; unknown-signature spikes are visible as
  `quarantine_reasons.routing`; the candidate-set distribution is logged per run for the replay mix; the
  retained certificate on the Squid 11-slot family is the retroactive-resolution demo; discovery ranking
  is the demo's opening; the agreement tool and crosswalk (after review) produce the agreement results.
- **Boundary decisions owed:** parser-pack 1.3.0 approval (items 1–2); tiebreaker (item 3); ML contract
  (item 6); crosswalk review (item 8).
- **Laptop run** (P4) still owed before any latency figure; nothing in P6 measured latency.
