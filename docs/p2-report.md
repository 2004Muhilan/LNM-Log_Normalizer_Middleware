# P2 report — runtime vertical slice on a hand-authored pack

**Status: P2 exit criteria met; stopped for verification before P3.** Nothing from P3 (learning
plane) was built. Reproduce with `scripts/p2-check.sh` under WSL2 (Docker Desktop running for the
container stages).

## 1. Demonstrable outcome

The trace's 20-line scenario runs end to end through the Go engine under the hand-authored golden
Squid pack, inside the container: file-tail → newline framing → raw evidence write (hashed,
fsynced, before anything else looks at the bytes) → signature match → span parse → OCSF
normalization → JSONL with the full lineage block.

| Check | Result |
|---|---|
| Engine reproduces the golden span maps for trace line 1 (promoted and candidate) **exactly** | pass — byte offsets, classes, coerced values, literal spans all equal |
| Stage 13 output reproduced | `class_uid 4002`, `time 1734567890123`, `src_endpoint.ip 10.20.14.62`, `dst_endpoint.ip 93.184.216.34`, `activity_id 3`, `action_id 1`, lineage `offset 0 / length 124`, framing `raw_suffix "\n"` |
| Six sample lines through the pipeline | 6 emitted, 0 quarantined, 6 usable; 2 events flag `dst_endpoint.ip` absent (cause `uncoercible`: Squid's `-` upstream marker) — recorded in `_lineage.absent`, never guessed (definition settled at the boundary, §7.2) |
| **Invariant 1** — adversarial specs rejected at compile | 13 cases: backreference, lookahead, unknown op, unlisted named group, nested named groups, duplicate field, nesting over bound, repeat over bound, opaque cell with class, unknown class, non-consuming root, field count over bound, unsupported strptime token |
| **Invariant 3 kill-test** — process killed after the 3rd raw write, before parsing | evidence store reconstructs the ingested stream **byte-exactly** (`raw_prefix + raw + raw_suffix`, CRLF preserved on the line that had it), including the never-parsed third event. *(Amended 2026-09-27, laptop branch: invariant 3 is now group commit — no event parsed or delivered until the batch holding its raw bytes is durable; the kill-test dies after a committed batch and also checks the output holds only earlier batches. Plan §2 row 3, §11 row 65.)* |
| **Invariant 6** (interim) — unknown signature | quarantined at the routing stage with a reason; no parser executed |
| **Invariant 7** — bounded framing | a line over the cap is emitted in bounded pieces flagged `truncated`/`continuation`; 500 random streams reconstruct byte for byte |
| Evidence lifecycle | OPEN → SEALED → IMMUTABLE on rotation and close; a flipped byte in an immutable segment is detected on reconstruction |
| Golden pack loads fail-closed | `dsl_hash` and `parser_hash` both recompiled and compared at load |
| Contract suites | Python 22/22 vectors, 24 tests; Go 22/22 vectors (a `normalized-event` vector added to both) |
| Container | see §6 |

## 2. First test of the phase: the nine drafts, executed

P1 validated the drafts and executed only their regexes. P2 replays all nine through the compiler
over `corpus/cache` (git-ignored; tests skip without it). Header stripping in the tests is scaffolding
standing in for envelope unwrap (P5/P7), exactly as P1's checker did.

| Draft | P1 recorded | P2 executed | Notes |
|---|---|---|---|
| asa-302013 | 62/62 | **62/62** | |
| asa-302014 (+302016) | 81/81 | **81/81** | opaque free-text tail, two user encodings |
| asa-106023 | 65/66 | **65/66** | the miss is the fixture line with a stray trailing quote |
| asa-305011 (+305012) | 93/93 | **93/93** | |
| asa-106100 | 27/27 | **27/27** | |
| asa-733100 | 5/5 | **5/5** | |
| panos-traffic | structure only | **301/301 TRAFFIC lines** across 46-, 65-, 75- and 105-cell layouts; extra non-empty cells counted exactly against a quoted-aware split; 0/76 THREAT lines parse (type enum rejects them — a separate family, not a silent misparse) | RFC 3339 timestamps on the 10.x line take the second entry of the `formats` list |
| fortigate-traffic | structure only | **13/13**, no `unknown.*` span; `epoch_auto` selected `s` and `ns` within the same file | |
| squid-custom-logformat | 97/100 | **97/100**, 3 failed = the shorter family | |
| golden Squid native spec over the real Beats corpus | — | **100/100** | |
| **synthetic** PAN-OS doubled-quote line (labelled, never counted) | — | parses; `rule_name` decodes to `rule "quoted" name, with comma` with `csv-quoted` encoding | |

**What execution found that validation could not:** two token-class annotations were wrong — ASA
`msg_id` was `word` but `%` is not a word character (all six ASA drafts), and PAN-OS `action` was
`word` but the corpus has `drop ICMP`. Both are now `text`. Under the runtime a wrong class is a
parse failure and a quarantine, never a mis-typed value, so 0/334 ASA lines parsed until fixed —
which is the behaviour the design wants, and the reason executing is the check that counts.

## 3. Deliverables

- `runtime/internal/spec` — typed mirror of the parser-spec contract (adopted; it was present untracked at P2 start and is a faithful mirror of the schema).
- `runtime/internal/dsl` — compiler (static invariants, RE2-only, named-group nesting check, bounds, `ParserHash`) and executor for all ten ops; token classes; coercions (int/float/bool/ip/mac/enum/timestamp with `formats`, `epoch_auto` window rule, strptime subset with 1–2 digit numeric fields); decoders (base64/hex/url/json-string/c-escape/cef-extension) with derived buffers.
- `runtime/internal/spanmap` — contract types + tiling invariant, checked on every emitted event.
- `runtime/internal/frame` — bounded newline framer with structured framing (`raw_prefix`/`raw_suffix`).
- `runtime/internal/evidence` — append-only segments with fsynced sidecar index, lifecycle, `Reconstruct`.
- `runtime/internal/route` — interim match-or-quarantine router (L1/L2/L4 signature; positional families).
- `runtime/internal/normalize` — mapping to nested OCSF, transforms (`lookup` with `default`, `compose_datetime`, …), `_lineage`.
- `runtime/internal/pipeline` — the §2.5 order, quarantine JSONL, kill-test hook.
- `runtime/internal/pack` — fail-closed loader (contract → compile → `dsl_hash` → `parser_hash`); signature requirement wired, disabled until P5.
- `runtime/cmd/ulpf-runtime` — `compile`, `verify-pack`, `run`, `reconstruct`.
- `runtime/Dockerfile` — multi-stage: build, `test` (runs the suite), `runtime` (distroless, non-root, static binary, contracts + pinned tables baked in).
- `contracts/normalized-event.schema.json` — fifth contract, frozen; both validators load it; golden `squid-native/normalized/line1.json` generated by the pipeline under a fixed clock.
- Golden vectors regenerated with the runtime-defined `parser_hash`; `build_vectors.py` now shells out to the compiler and runs the pipeline for the normalized golden.
- `drafts/sufficiency/synthetic/` — the labelled PAN-OS doubled-quote line and its README.
- `scripts/p2-check.sh`.

## 4. Raised, not absorbed

1. **Empty cells produce no span.** The contract forbids zero-length spans, so an empty CSV cell, an
   empty KV value, or a non-participating optional group means the declared field is *absent*, and
   `extra.<n>` opaque spans exist only for non-empty extras. Consistent with the contract as written;
   now stated in `contracts/README.md` because it affects how P3 counts coverage.
2. **`parser_hash` definition** (carried forward): sha256 of the canonical compiled node tree plus
   the compiler version; invariant under spec reformatting, changes with the compiler; verified at
   pack load. No schema bump. Golden vectors regenerated.
3. **Framing structure implemented as decided**: `framing` is an object with literal stripped bytes;
   it lives in the evidence record and `_lineage`, not in the four P1 contracts. Kill-test criterion
   is byte-exact reconstruction, which passes with a CRLF line in the stream.
4. **Normalized-event envelope frozen** (carried forward) with `_lineage.schema_version`,
   `normalization_version`/`derived_from` (for P8) and the structured framing. It validates OCSF shape
   only at the envelope level; attribute existence is enforced by the pack against the pinned table.
5. **Two draft class annotations changed** (`msg_id`, `action` → `text`), see §2. P1 artefacts
   edited in P2 because execution proved them wrong; nothing else in the drafts changed.
6. **Interim router scope**: raw-envelope positional families only; csv/kv families and anything with
   an envelope quarantine with an explicit reason until P6 (DAG) and P5/P7 (envelopes). Signature
   matching compares the event's arity and coarse token classes against declared L4 sketches — a
   bounded comparison, never a parse attempt.
7. **Timezone**: with `timezone_confidence: unresolved` the runtime interprets `source`-zoned
   timestamps as UTC and records the unresolved state in `_lineage`; nothing pretends the offset is
   known.
8. **Adopted after mechanical verification:** `runtime/internal/spec/spec.go` was already present
   (untracked) when P2 started — an interrupted P1 run. Verified against the schema by
   `mirror_test.go`; see §7.1.

## 5. What was tried and rejected

- **Sequence as an op.** Rejected: composition stays structural (a JSON array), keeping the op set
  closed at ten. The compiler treats an array as a sequence node.
- **Deriving `parser_hash` from the spec bytes.** Rejected: that is `dsl_hash`. The compiled-form hash
  is what detects a compiler change with the same spec.
- **Zero-length spans for empty cells.** Rejected by the contract (`start < end`); absence is the
  honest representation and keeps tiling trivially true.
- **Counting extras as "cells beyond 65".** Rejected in the replay test once the runtime showed the
  ietf line's trailing extras are mostly empty; the test now derives the expectation from a
  quoted-aware split, so it measures the parser, not a guess about the corpus.
- **A signature-free "try the single family" interim router.** Rejected: even with one family that is
  the try-every-parser shape invariant 6 forbids; the router matches a declared signature or quarantines.

## 6. Container

`runtime/Dockerfile` is multi-stage: `build` (golang:1.24-alpine, `CGO_ENABLED=0`, `-trimpath`),
`test` (runs `go vet` and the whole runtime suite inside the image — corpus replay skips there
because the cache is not copied in; mount it read-only to include it), and `runtime`
(distroless static, non-root, the binary plus `contracts/` and `ocsf/pinned/`). Results from
`scripts/p2-check.sh`:

- test stage: **PASS** (golden span maps, adversarial specs, framing, evidence, kill-test, routing,
  end-to-end pipeline — all inside the container);
- runtime image: **2.5 MB**;
- golden pack through the image with `--network none` as `nonroot`: **6 events emitted, 4 usable,
  0 quarantined** — identical to the host run.

No model, no inference library and no network client are present in the runtime image (invariant 2,
verified by construction: the binary's only dependency is the JSON Schema library).

## 7. Boundary addendum — two items settled before P3

### 7.1 `runtime/internal/spec/spec.go` — provenance and verification

**Origin:** an interrupted P1 run (the user stopped a response mid-write and re-ran it); the partial
write left the file untracked, and P2 found it in place. **Verified against the contract, not the
story:** `runtime/internal/spec/mirror_test.go` walks `contracts/parser-spec.schema.json` with
reflection and asserts, for the root object and every `$defs` object the mirror types (`bounds`,
`timestamp_format`, `coerce`, `decode`, `cell`, and the ten `op_*` definitions), that the property
sets are identical (nothing missing, nothing extra), that optionality matches (`required` ⇔ not
`omitempty`, with pointer/slice/map fields allowed to be nullable), that enum-bearing properties are
Go strings and integer/boolean properties are Go ints/bools, and that every schema object is closed.
It also checks the `delimiter` alternatives against the `Delim` fields, that `step.oneOf` references
exactly the ten mirrored ops, that the `slot` and `csv_cell` branch discriminators are exactly
`field/token/step` and `field/parse` (and that the custom unmarshallers reject an unknown branch),
and that `Parse` refuses an unknown `schema_version`. **Result: one discrepancy found and
corrected, then pass.** Every property set matched (nothing missing, nothing extra) and every op was
present, but `allow_bare_keys` — optional in the schema with default `false` — lacked `omitempty` in
Go, so a marshalled spec would have carried an explicit `false` the schema never required. A
by-hand comparison earlier in P2 had read it as correct; the reflection test did not. The tag is fixed
and the test is kept, so contract–mirror drift is caught mechanically in every later phase rather than
by reading. Nothing else in the file was wrong; the mirror is otherwise faithful and complete.

### 7.2 "4 usable of 6" — the definition was wrong, and the runtime was collapsing two things

**Verified before changing:** the pipeline computed `missing` from the output alone, so "mapped but
absent" and "not mapped at all" were indistinguishable at runtime. "Not mapped at all" cannot reach a
running pipeline: both validators reject a pack whose acceptance snapshot lists a mandatory attribute
with no mapping (`negative/pack-mandatory-model-only` and the mandatory-coverage check), and the loader
runs that validation. So the collapse hid nothing today, but it would have encoded the wrong metric.

**Decision implemented:** mandatory is a mapping obligation. Three states, and the runtime now
distinguishes them: mapped and present → usable; mapped and absent → **usable, flagged** in
`_lineage.absent` with a cause; not mapped → unusable (`unmapped_mandatory_events`, expected 0).
Golden samples: **6 emitted, 6 usable, 2 events with an absence**, and line 2 carries
`{"attribute": "dst_endpoint.ip", "cause": "uncoercible"}` with no guessed `dst_endpoint`.

**One refinement raised, not absorbed — the absence has two causes, and the Squid case is the
second one.** The proposal described the `HIER_NONE/-` lines as "no span in the source". They are
not: Squid emits `-`, a vendor null marker, so a span exists and becomes absent only because
`coerce ip` fails and `on_failure: opaque` downgrades it. That is the same mechanical path a garbage
value (`93.184.216.abc`) would take. The runtime therefore records the cause — `structural` (no span:
empty cell, non-participating optional group) versus `uncoercible` (span present, value failed
coercion) — and both count as usable per the decision, so the headline is unbiased while data-quality
failures stay visible. To let a pack *declare* a vendor null marker instead of discovering it by
coercion failure, the DSL would need a cell-level `null_values` list (e.g. `["-"]`) that yields a
declared absence. That is a parser-spec contract change (optional property; a version bump under the
freeze rules), so it is proposed here for P3, where the coverage engine will want the distinction
between "vendor said none" and "value unusable", and not implemented now.

**Exception to the rule, already enforced:** `time` is required by OCSF's base event and by the
normalized-event contract; an event without it cannot be emitted and is quarantined at the normalize
stage. The rule "mapped-but-absent is usable" applies to every other mandatory attribute.

**Contract change at this boundary:** `_lineage.absent` (optional array of `{attribute, cause}`) added
to `normalized-event.schema.json`, whose freeze takes effect at this exit; golden vectors regenerated
(line 1 has no absence, so its vector is unchanged in content).

### 7.3 Notes carried, not blockers

- **Unresolved timezones and correlation.** Sources with `timezone_confidence: unresolved` have their
  `source`-zoned timestamps interpreted as UTC, recorded in `_lineage`. Two such sources in different
  actual zones misalign by whole hours; cross-source correlation (requirement 20) over unresolved
  sources is therefore unreliable until the offset is declared or inferred. Known limitation from P2;
  P6's multi-vendor routing is where it will first be visible.
- **Replay counts are provisional until P7.** The ASA and PAN-OS figures (333/334, 301/301) rest on
  test-scaffolding header stripping that P7's envelope unwrap replaces; quote them as P2 replay
  results, not as final coverage.
- **OCSF required base attributes.** The normalizer emits `class_uid`, `time`, `activity_id` and the
  mapped attributes; OCSF also requires `category_uid`, `type_uid`, `severity_id` and `metadata` on
  every event. These are derivable (`category_uid` from the class, `type_uid = class_uid*100 +
  activity_id`) and belong to the deterministic validator's OCSF-conformance check in P3, which is
  where output conformance is measured. Noted so P3 does not discover it.

## 8. What the next phases inherit

- **P3:** the differential test compares Python-predicted span maps and normalized events against
  the runtime's output; both contracts are frozen. `dsl.Program.Fields()` and `compile --spec` give
  P3 the field list and hashes. Expect structural determination to be rare (P1 finding); expect empty
  cells to be absent fields when computing coverage.
- **P5:** replace the interim `chattr`/chmod IMMUTABLE step with the real privilege boundary; Merkle
  commitment over sealed segments; pack signature verification behind `RequireSignature` (the hook
  refuses when set, so flipping it is the P5 change).
- **P6:** the router's `Signature` grows into the L0–L4 DAG with anchors, K=4 and the tiebreaker;
  csv/kv families become routable; ML feature tuple emission alongside the normalized event.
- **P7:** envelope unwrap replaces the test-scaffolding header stripping; `octet_count` /
  `multiline` / `batch_element` framing methods already have their enum slots in the envelope; the
  NUL-terminated FortiGate file is a framing case.
- **P8:** `normalization_version`/`derived_from` are in the envelope for versioned corrections.
- **Open, not blocking:** `compose_datetime` accepts `-0500` and `+05:30` offsets; FortiGate `tz`
  values in the corpus are `-0500` only. CEF extension decoding is implemented but unexercised until P7.
