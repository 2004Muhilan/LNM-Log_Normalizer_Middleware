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
| Six sample lines through the pipeline | 6 emitted, 0 quarantined, 4 usable (the two `HIER_NONE/-` lines have no destination address, so a mandatory attribute is absent — recorded, not guessed) |
| **Invariant 1** — adversarial specs rejected at compile | 13 cases: backreference, lookahead, unknown op, unlisted named group, nested named groups, duplicate field, nesting over bound, repeat over bound, opaque cell with class, unknown class, non-consuming root, field count over bound, unsupported strptime token |
| **Invariant 3 kill-test** — process killed after the 3rd raw write, before parsing | evidence store reconstructs the ingested stream **byte-exactly** (`raw_prefix + raw + raw_suffix`, CRLF preserved on the line that had it), including the never-parsed third event |
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
8. **Adopted, not written here:** `runtime/internal/spec/spec.go` was already present (untracked) when
   P2 started. It is a faithful typed mirror of the contract and is used as-is.

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

## 7. What the next phases inherit

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
