# ULPF contracts (frozen at P1 exit)

The four data contracts both stacks depend on. Schemas are JSON Schema draft 2020-12; every
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
the library class's `candidates`. Cost tiers are ordinal strings.

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
