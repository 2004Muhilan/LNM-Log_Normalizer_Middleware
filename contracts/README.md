# ULPF contracts (frozen at P1 exit)

The six data contracts both stacks depend on (four frozen at P1 exit, the normalized event at P2 exit, the ML feature tuple at P6 exit; every later change is an additive version bump recorded below). Schemas are JSON Schema draft 2020-12; every
instance carries `schema_version`. Post-freeze changes require a version bump, a same-commit update
of `golden/`, and green suites on both sides (`scripts/p1-check.sh`). The Go loader refuses unknown
versions before doing anything else (fail closed); the Python validator does the same.

| Contract | Schema | Produced by | Consumed by |
|---|---|---|---|
| Parser spec (DSL) | `parser-spec.schema.json` | learning plane (model / fixture / hand) | runtime compiler |
| Span map | `span-map.schema.json` | runtime parser (and the learning plane's verifier) | normalizer, differential tests |
| Ambiguity certificate | `ambiguity-certificate.schema.json` | learning plane | review interface, pack |
| Parser pack | `parser-pack.schema.json` | learning plane | runtime loader |
| Normalized event (frozen at P2 exit) | `normalized-event.schema.json` | runtime | SIEM/lake consumers, P3 differential test |

`golden/index.json` lists every golden vector with its expected outcome; both suites iterate it.
Positives come from the corrected worked trace; negatives are generated from them by
`golden/tools/build_vectors.py` so they cannot drift.

## Decisions embedded in the contracts

**Sequencing is structural.** A step is either one op object or a JSON array of steps. The op set
stays closed at the ten named ops; there is no `sequence` op.

**Consuming ops vs value ops.** `literal, regex, csv, kv, positional, quoted, optional, repeated`
consume bytes and emit spans. `decode` and `coerce` never consume bytes: they hang off a field cell.
`decode` may open a *derived buffer* (`<field>#decoded`) whose spans tile that buffer; the raw
buffer's tiling is unaffected. This is what recursive envelope unwrap (P7) needs.

**Regex dialect.** RE2 only, named groups in `(?P<name>...)` syntax, no backreferences, no
lookaround. Named groups must not nest; every named group must appear in `captures`, and an
optional named group that does not participate produces no span (declared field absent). The
Python side validates through `google-re2`, the Go side through `regexp`, so a regex accepted by
the learning plane always compiles at runtime. Repeat counts above 1000 are not RE2 — use `+` with
`maxLength`. (The Go schema library rejected `{1,4096}` in a schema pattern during P1; that is the
dual-stack check working.)

**Positional slots.** Three forms: a token slot (maximal run of non-delimiter bytes), a token slot
sub-parsed by a step that must consume the token exactly (`{"token": {"parse": ...}}`), and a
direct slot (`{"step": ...}`) that consumes from the input itself and may span delimiter bytes —
quoted values and bracketed timestamps. Whitespace runs are single literal spans. Optional slots do
not exist except via `tail`; a shorter variant of a line is a different family, not an optional
middle.

**CSV.** A quoted cell's raw span includes the quotes and carries `encoding: csv-quoted`; the value
is the unescaped content. `extra_fields`/`missing_fields` policies exist because vendors append
columns across versions (PAN-OS: 46 → 65 → 105 cells in the corpus).

**KV.** Key text and separators are literal spans; a known key's value is the cell's span; an
unknown key's value is an opaque span at `unknown.<key>` (or the parse is rejected). Order is
`any` for vendors whose keys vary per line (FortiGate: 30–57 of 72 keys).

**Timestamps.** `coerce.to = timestamp` takes `format` or an ordered `formats` list (first that
parses wins; the span map records `format_selected`). Kinds include `epoch_auto` because FortiOS
switches `eventtime` precision between versions: each precision has a plausible-date window
2000-01-01..2100-01-01 in its own unit (s: 9.47e8–4.10e9, ms: ×10³, us: ×10⁶, ns: ×10⁹); the windows
are disjoint, so a value falls in exactly one or none; one → selected and recorded as
`precision_selected`, none → the coercion fails. It never guesses. All 70 FortiGate `eventtime`
values in the corpus select exactly one precision (51 ns, 19 s). `pattern` uses a fixed strptime token subset
(`%Y %y %m %d %e %H %M %S %f %b %j %z %Z %p %I`) implemented identically in both stacks; numeric
tokens accept one or two digits where the field is at most two digits (Squid custom formats emit
`:6:09:59`). `timezone: source` defers to the pack's `source_timezone`, which may be `unresolved`.

**Token classes** are structural (`integer, float, ipv4, ipv6, ip, mac, url, hostname, uuid, hex,
word, text`). `url` accepts scheme URLs and `host[:port][/path]` forms (Squid logs `CONNECT
host:443`). The worked trace's presentation names (FLOAT, IPV4, BARE_STRING, LITERAL) map onto
these; a constant literal is a `literal` op, not a class.

**Certificates.** No numeric confidence: `additionalProperties: false` everywhere plus a validator
walk rejecting any key named confidence/probability/score/likelihood. `enumeration.candidates` and
`survivors` come from the deterministic validator over the pinned class table (never from the
model); `ranked_candidates` must be a subset of survivors with at least two entries when
ambiguous/unresolved. Ambiguity-class lookup is a subset match of the ranked attribute set against
the library class's `candidates`. Cost tiers are ordinal strings. *Who decides that a field is
ambiguous* is policy, not contract: since the P3→P4 boundary the library names the rivals (anchored on
the provider's rank-1 attribute, over the validator's survivors), and the provider's ranking is an
ordering hint — `docs/p3-report.md` §6.1. Both properties above hold by construction under that rule.

**Packs.** Per source, per-family entries. OCSF pinning is by class only — there is no field in
which attributes within a class could be listed (subset guard), and `table_hash` must equal the
generated complete table in `ocsf/pinned/index.json`. `mandatory: true` with `model_proposal`
provenance is a schema error (invariant 4). `structural_determination` requires
`enumerated_survivors` of exactly one attribute equal to the mapped attribute. One span may feed
two attributes (Squid's method feeds both `http_request.http_method` and `activity_id`), so
uniqueness is per OCSF attribute, not per path. Mapped attributes must exist in the pinned class
table. The signature is detached (`pack.json.sig` over the exact bytes of `pack.json`); the schema
carries only signing metadata.

**Hashes.** `dsl_hash` = sha256 of the spec file bytes. `mapping_hash` = sha256 of the canonical
JSON of `mapping.fields` — sorted keys, no whitespace, no HTML escaping, numbers in shortest form
(Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`; Go
`json.Encoder` with `SetEscapeHTML(false)` on `json.Number` values). Pack-level `dsl_hash` and
`mapping_hash` are sha256 over the family-level values concatenated in family order.
**P2 obligation:** `parser_hash` is defined as the sha256 of the runtime's compiled representation;
until P2 defines that serialization the golden pack sets it equal to `dsl_hash`.

**Provenance categories** carry the architecture's six names. Three of the five sufficient ones
overlap (a certificate resolved by a device-configuration discriminator is all of "vendor schema or
device configuration", "validated discriminator" and "resolved ambiguity certificate"); the golden
pack records the evidence kind and links the certificate by id. Choosing the canonical category per
resolution path is P3 policy, not a contract change.

**Structural determination in practice.** The golden pack claims it for no field. Against the
complete 4002 table a URL token has 21 `url_t` survivors (including
`proxy_http_request.url.url_string`), a bare word has 203 `string_t` survivors, an IPv4 has 6, an
integer 15. Structural determination therefore fires only where a class has a genuinely unique
typed attribute; the Squid fields are all resolved by the logformat line instead. P3 should expect
effort savings to lean on device configuration and vendor tables, not on structural determination.

**Transforms.** `lookup` takes a `lookup` map and an optional `default` (Squid `%Ss` → `action_id`:
`TCP_DENIED`/`TCP_DENIED_REPLY` → 2 Denied, default 1 Allowed).

## Framing and raw bytes

The raw event excludes the framing delimiter or octet-count prefix. `raw_hash` and span offsets are
over those bytes. Framing is **not** part of any of the four contracts; it belongs to the raw
evidence record and the lineage envelope (both P2). It is a structured object, not a method name,
because a name cannot distinguish LF from CRLF:

```
framing: { method: newline | octet_count | multiline | batch_element,
           raw_prefix: <bytes stripped before the event, base64, may be empty>,
           raw_suffix: <bytes stripped after the event, base64, may be empty>,
           fragment_count, original_message_length, truncation_status, framing_confidence }
```

Reconstruction is exactly `raw_prefix + raw + raw_suffix`. **P2 obligation:** the kill-test verifies
byte-exact stream reconstruction, not mere recovery of the event.

## `parser_hash` (settled at P2)

`parser_hash` = sha256 over the canonical JSON of the **compiled program** — the compiler's typed
node tree (ops, patterns, cells, bounds) plus the compiler version string — as emitted by
`ulpf-runtime compile --spec <file>`. It is invariant under spec reformatting (whitespace, key order)
while `dsl_hash` is not, and it changes whenever the compiler changes. The runtime recompiles every
family at pack load and refuses the pack if the stored `parser_hash` differs (fail closed). Only the
runtime can compute it; the vector tool shells out to the binary. No schema bump was needed: the
field and its type already existed.

## Normalized event envelope (frozen at P2 exit)

The runtime's output is one JSON object per event: OCSF attributes nested as objects (`class_uid`,
`time`, `src_endpoint.ip` → `{"src_endpoint": {"ip": ...}}`), vendor extensions under `unmapped`,
and a mandatory `_lineage` block carrying the §4.1 fields plus the **structured framing record**
(`method`, `raw_prefix`, `raw_suffix` as base64, `fragment_count`, `original_message_length`,
`truncation_status`, `framing_confidence`), `family_id`, `routing_signature`, the pack's timezone
state, and `normalization_version` (with `derived_from` for P8 corrections). The golden vector
`golden/squid-native/normalized/line1.json` is produced by the pipeline itself under a fixed clock
and sequential ids. `_lineage.schema_version` carries the contract version.

**Usability and absence (P2 boundary decision).** *Mandatory* is a mapping obligation on the pack,
not a per-event presence requirement. At runtime a mapped mandatory attribute is either present, or
absent for a recorded cause in `_lineage.absent`: `structural` (the source carried no span for the
field) or `uncoercible` (a span exists but its value failed coercion — Squid's `-` for an upstream
address). Both leave the event **usable**. An event is unusable only when a mandatory attribute is not
mapped at all, which the acceptance gate blocks before a pack can load, so `usable == emitted` is the
expected steady state and the absence causes are the informative numbers. The single exception is
`time`: OCSF and this envelope require it on every event, so its absence quarantines the event at the
normalize stage rather than flagging it.

## 1.1.0 (P3 boundary) — one additive bump, four contracts

Every 1.1.0 change is additive; 1.0.0 documents remain valid and both validators accept both.
The golden candidate spec and its span map deliberately stay at 1.0.0 to prove that.

- **parser-spec**: `null_values` at spec level (default) and cell level (override; `[]` opts out).
  A semantic value equal to a marker is a *declared null*: checked before class validation and
  coercion, so `on_failure` never fires for it; the span is kept with `declared_null: true`, no class,
  no coercion. Markers are pack evidence (device configuration / vendor table), never inference.
- **span-map**: `declared_null` on semantic spans.
- **normalized-event**: `_lineage.absent[].cause` gains `declared_null`; `category_uid`, `type_uid`,
  `severity_id`, `metadata` are emitted — the first two and the last are mechanical (category from the
  pinned class table, `type_uid = class_uid*100 + activity_id`, metadata from the pack);
  **`severity_id` is pack-declared with provenance**, never derived.
- **parser-pack**: a mapping entry may carry `constant` instead of `path` (e.g. `severity_id: 1`
  asserted by the operator for a source that carries no severity), with the same provenance rules.
- **pinned tables** carry `category_uid` (hashes changed; cross-check still agrees on all four classes).

## normalized-event 1.5.0 (laptop branch, 2026-09-27) — `store_id`, additive (approved by the sponsor)

- **`_lineage.store_id`** (`st_` + 26 Crockford base32 characters): the evidence store holding the event's raw
  bytes — the identity of an evidence directory, created once in its `store.json`. Segment ids are unique only
  within a store (`seg_00000` exists in every directory), and with the evidence archive the local copy of a
  segment is deleted after shipping: `store_id` + `segment_id` + `offset` + `raw_hash` is the event's address
  in the archive (`<archive>/<store_id>/segments/<segment_id>.raw`). Every event the runtime emits declares
  1.5.0 and carries it; 1.5.0 includes 1.4.0's LEEF envelope. Optional in the schema: every earlier document
  remains valid. The lake (Parquet) and the SIEM template carry it as a column / keyword.

## normalized-event 1.3.0 (P7) — transport breadth, additive

- **`_lineage.relay_chain`**: every envelope removed by recursive unwrap, outermost first, when more than
  one came off — up to two syslog envelopes (a relay re-wrapping a device's RFC 3164 header as RFC 5424)
  plus one application envelope. `_lineage.envelope` is now defined as the **innermost** envelope (the
  device's own header — what routing anchors and `envelope_field` mappings read); on a single-envelope
  message nothing changes. Each envelope carries `level` (1 = outermost).
- **`kind: cef`**: the ArcSight CEF header is an application envelope, unwrapped after the transport
  envelopes only when it starts the innermost payload; its seven header fields are `device_vendor`,
  `device_product`, `device_version`, `signature_id`, `name`, `cef_severity` and `version` (0 for CEF:0 —
  `version`'s minimum drops to 0 for this reason; RFC 5424 still emits 1). The payload is the extension.
  Header-looking text anywhere else is payload: precedence is transport before application, outer
  before inner, and position decides (P7 exit criterion, tested).
- **`_lineage.batch`**: present on an event that was one element of a de-batched JSON array — the sha256
  of the whole received batch, the element's `index` and the batch `size`. The element's own bytes are
  what `raw_hash` covers; the batch reconstructs from its elements' framing records.
- **`framing.method: udp_datagram`**: the P5 UDP listener has emitted this value since P5 without the
  enum admitting it — a contract omission found when P7's tests validated listener output against the
  schema; added here.
- Gap records (P7) are **not** normalized events and do not touch this contract: they are evidence
  records (`framing.method: gap_record` in the evidence index) with a canonical JSON body
  (`gap-record 1.0.0`, `runtime/internal/gap`), committed as Merkle leaves like any event.

## 1.2.0 (P5) — two additive bumps, and signing goes live

- **parser-pack 1.2.0**: `provenance.proposal` — what produced the candidate proposals: `provider`
  (`model | fixture | hand-authored`), `model_id`, `model_hash`, `backend`, `mode`, `decoding`
  (temperature, top_k, top_p, min_p, seed, cache_prompt), `prompt_template_hash`, `grammar_hashes`,
  `runtime_build`. P4 measured that the same prompt yields different labels on GPU and CPU, so
  `model_hash` alone did not describe the provider. Reproducibility is claimed for the recorded backend
  and decoding configuration. Fixture and hand-authored packs record the provider kind only.
- **normalized-event 1.2.0**: `_lineage.envelope` — the transport envelope unwrapped before routing, one
  level (`kind: none | rfc3164 | rfc5424`, `payload_offset`, `payload_length`, and the header fields
  verbatim). The evidence record holds every received byte; `offset`/`length` address those bytes;
  span offsets are relative to the payload. Present only when an envelope was unwrapped, so
  file-collected events are unchanged. Recursive unwrap and relay chains are P7.
- **Signing is live and fail-closed.** `pack.json.sig` holds `<authority_id> <hex ed25519 signature>` over
  the exact bytes of `pack.json`; the runtime verifies those bytes against the trust store
  (`keys/trust/<authority_id>.pub.json`, `--trust`) **before parsing the document**, then validates the
  contract, then requires `signing.authority_id` to equal the signer; it refuses on a missing file,
  unknown authority or any mismatch. The learning plane signs at promotion
  (`ulpf_learn.signing`); the golden pack is signed by `build_vectors.py` with the dev authority in
  `keys/dev`. `--allow-unsigned` is development-only and loud. No schema change was needed for signing:
  the metadata block existed since 1.0.0.

Both bumps are additive; 1.0.0 and 1.1.0 documents remain valid and both validators accept all three.

## 1.3.0 (P6) — one additive bump, a deprecation, and the sixth contract (approved at the P6 boundary)

- **parser-pack 1.3.0**: `mapping.fields[].envelope_field` — a third mapping source beside `path` and
  `constant`: the value comes from the transport envelope unwrapped at ingest (`timestamp | hostname |
  app_name | proc_id | msg_id | priority | facility | severity`). Forced by ASA: the payload carries no
  timestamp, `time` is mandatory for `network_activity`, and the syslog header's clock is the device's — a
  pack-declared fact with vendor provenance, never a runtime guess. With it, `transform.kind: timestamp`
  and `transform.format` (a parser-spec `timestamp_format`) so an envelope string can be coerced the same
  way a payload cell is. Absent when the event arrived without that envelope (`_lineage.absent`, cause
  `structural`).
- **parser-pack 1.3.0**: `routing_signature.l3_anchor_values` — which values of each pack anchor route to
  THIS family (`[{anchor_id, values[]}]`). 1.0.0 had anchors at pack level and `l3_anchor_ids` per family
  but no place for the family's own values, so the L3 stage of the DAG had nothing to select on. The
  loader cross-checks every value against the anchor's `expected_value_domain` and refuses the pack
  otherwise (a family may not claim what its anchor calls a domain violation).
- **`tiebreaker_field` deprecated and dropped as a concept** (P6 boundary). A per-pack secondary
  discriminator at the K cap is either readable before parsing — then it is an anchor — or not, and
  evaluating it would mean parsing to route (invariant 6). The rule is K-cap → quarantine, with the
  candidates named. The key is no longer required and accepts only `null`, so 1.0.0–1.2.0 documents
  that carry it stay valid; 1.3.0 packs omit it.
- **ml-feature 1.0.0 — the sixth contract** (`contracts/ml-feature.schema.json`): the ML feature tuple of
  requirement (h), one record per normalized event: `template_id` (`<pack>/<family>@<parser_hash>`),
  `parameter_names`/`parameter_vector` (the spec's semantic fields in spec order; null when a field did
  not participate), `timestamp` (the OCSF `time`), `entity_ids` — things that recur across events and a
  sequence model can follow: `src_ip`, `dst_ip`, `src_host`, `dst_host`, `user`, `src_user`, `dst_user`,
  `device`, `session`, `domain` (URL host for proxies, query name for DNS, destination domain otherwise).
  A rule name is an attribute of the event, not an entity, and is not in the vocabulary. Absent entities
  are omitted, never invented. The Python validator accepts the kind; the Go runtime, which produces the
  records, validates its own output against the schema in its tests (the loader never consumes them).
- **Envelope unwrap rule added (no schema change):** a PRI followed by no valid TIMESTAMP is an RFC 3164
  envelope of the PRI alone (§4.3.3), payload everything after it. FortiGate emits exactly this form
  (`<189>date=...`); before P6 it was `kind: none` and the parser would have seen `<189>`.

1.3.0 is additive apart from the deprecation above; every earlier document remains valid and both validators accept all four versions.

## Lessons from executing the drafts (P2)

P1 validated the drafts and executed only their regexes; executing them through the compiler
surfaced two class annotations that regex matching cannot check: ASA message ids (`%ASA-6-302013`)
are not `word` (no `%` in the class), and PAN-OS `action` can be `drop ICMP` (a space). Both are
`text` now. A token class is a runtime validator, so a wrong one is a parse failure and a quarantine,
never a mis-typed value — which is why executing is the check that counts.

## Empty cells and absent fields

A zero-length span does not exist (start < end). An empty CSV cell, an empty KV value, or an
optional regex group that did not participate produces **no span**: the declared field is absent
for that event. Adjacent delimiters remain literal spans, so tiling still holds. `extra.<n>` opaque
spans therefore appear only for non-empty extra cells.
