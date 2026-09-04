# P1 report — contracts, corpus, and the dual-stack harness

**Status: P1 exit criteria met; stopped for verification before P2.** Nothing from P2 or P3 was built.
Everything below is reproducible with `scripts/p1-check.sh`, `scripts/run-crosscheck.sh` and
`scripts/check-drafts.sh` under WSL2.

## 1. Demonstrable outcome

| Check | Python (learning plane) | Go (runtime) |
|---|---|---|
| All golden vectors validate | 10/10 valid | 10/10 valid |
| Corrupted vectors fail | 10/10 rejected with the expected reason | 10/10 rejected with the expected reason |
| Version-bumped vector refused | `unsupported schema_version` for all four kinds | `ErrUnsupportedVersion` returned **before** schema validation, for all four kinds |
| Numeric confidence anywhere in a certificate | rejected (schema + key walk) | rejected (schema + key walk) |
| Backreference in a spec regex | rejected by `google-re2` | rejected by Go `regexp` |
| Subset-guard negatives (attribute-level pinning; stale table hash) | rejected | rejected |
| Suite totals | 22 pytest cases pass | `go test ./...` passes (3 tests, 20 sub-tests) |

Both suites iterate the same `contracts/golden/index.json` (20 vectors: 10 positive from the
corrected worked trace, 10 negative generated from them by mutation).

## 2. Deliverables

- **Four contracts**: `contracts/{parser-spec,span-map,ambiguity-certificate,parser-pack}.schema.json`,
  with the embedded decisions written up in `contracts/README.md`.
- **Golden vectors**: promoted and candidate Squid specs; span maps for trace line 1 under both;
  the two ambiguous certificates (Stage 8), their resolved successors (Stage 10), an out-of-library
  unresolved certificate (§8.3 demo step 3 / invariant 5); the `squid-native` pack bundle with its
  sample corpus; ten negatives. `contracts/golden/tools/build_vectors.py` fills hashes and generates
  the negatives so they cannot drift.
- **Validation suites**: `learning/ulpf_contracts` (+ pytest) and `runtime/contracts` (+ go test),
  each doing schema validation plus the semantic invariants the schema cannot express — span
  tiling and raw-byte consistency, RE2 compilability and named-group/capture agreement, candidate
  ⊆ survivors ⊆ candidates ⊆ pinned table, pack hash composition, mandatory-vs-model-provenance,
  structural-determination single-survivor rule, subset-guard table hashes.
- **DSL schema draft** — it is the parser-spec contract itself, frozen after the sufficiency check.
- **Discriminator library v1**: `library/discriminators-v1.yaml` — six ambiguity classes, nine
  discriminators, ordinal cost tiers, the deterministic ranking rule, request templates.
- **Pinned OCSF subset**: `ocsf/pinned/{network_activity,http_activity,authentication,detection_finding}.json`
  + `index.json` (per-table sha256), generated from the OCSF 1.3.0 schema-server export and
  cross-checked against an independent compile of the schema source at tag 1.3.0.
- **Acceptance policy data** (`acceptance/policy-v1.json`): class 4002 from the trace, 4001 from
  §3.3, 3002/2004 drafts marked for P3 confirmation. Engine is P3.
- **Corpus**: 54 files fetched, cached (git-ignored), catalogued with pinned commits, hashes,
  line counts and per-vendor family inventories (`corpus/catalogue.json`); licence verdict and
  attribution text in `corpus/README.md`.
- **Toolchain**: `scripts/wsl-bootstrap.sh` (Go 1.27.1 under `~/sdk`, venv with jsonschema 4.26,
  google-re2, pyyaml, pytest); no root required.

## 3. DSL sufficiency check (detail)

Nine drafts at real depth, all in `drafts/sufficiency/`, findings in `NOTES.md` there.

**Verdict: every family drafts cleanly with the ten ops — no op is missing.** That is a clean pass,
so here is what was actually exercised, and the two capability gaps found *inside* existing ops.

*Cisco ASA* — six message families as sequences of `regex` / `literal` / `optional`, then **executed**:
each draft was composed into one anchored RE2 pattern and matched against every corpus line of its
family (334 lines across seven fixture files). The first pass missed 19 lines; the misses were real
vendor variants absent from the documentation: user tags glued to ports with no separator
(`/50120(LOCAL\domain\USER001)`), bare user tokens after endpoints, interface names containing
spaces (`NP Identity Ifc`), `protocol 47` as a two-token protocol, ICMP `type 3, code 0,` without
parentheses, and one message id with no trailing colon. After tightening: **333/334 full matches**;
the single miss is a fixture line ending in a stray `"` — malformed input a strict spec must reject.
Exercised: empty-capture regex steps, opaque captures for free-text tails (302014's teardown
reason), chained optional trailers (106023: ICMP, access-group, hash pair — each optional), an
opaque bracketed object with internal padding (733100), negative integers, `enum` coercion.

*PAN-OS TRAFFIC* — `csv` with `"` quoting, doubled-quote escape, 65 declared cells (8.1 layout)
including opaque FUTURE_USE cells, `extra_fields: opaque`, `missing_fields: allow`. Quoted-aware
cell counts across the corpus are 46 / 65 / 75 / 105 per line depending on PAN-OS version, and ten
lines carry a quoted cell containing a comma (`"Microsoft Windows 10 Pro , 64-bit"`) — the escaping
and the extra/missing policies are load-bearing, not decorative.

*FortiGate traffic* — `kv` with whitespace-run pair separator, quoted values with spaces, `order:
any`, `unknown_keys: opaque`, 73 declared keys; every one of the 519 key occurrences in the corpus is
declared; `date`/`time`/`tz` are composed by the pack mapping (`compose_datetime`).

*Squid non-default logformat* — `positional` with **direct slots** (four `quoted` slots inside a
whitespace-delimited line, one containing brackets and parentheses), a bracketed timestamp as
`literal`/`regex`/`literal`, a nested `positional` parse **inside** quoted content, and a
single-digit hour. 97/100 corpus lines match the 14-slot layout; the other 3 are a shorter
structural family of the same capture — handled by family discovery, deliberately not by optional
middle slots (the contract forbids those; the architecture's §1.3 lesson applies).

**Two gaps found and fixed pre-freeze (needs your confirmation — see §7):**
1. `coerce.formats`: an ordered list of timestamp formats. PAN-OS emits `%Y/%m/%d %H:%M:%S` on
   8.x/9.x and RFC 3339 on 10.x for the same field.
2. `epoch_auto`: magnitude-selected epoch precision. FortiOS `eventtime` is epoch seconds before
   6.2 and epoch nanoseconds after; the corpus contains both (1.55e9 and 1.59e18).

**Boundary statement:** the regex drafts were executed; the csv/kv/positional drafts were validated
against the contract and checked against corpus structure but not executed — that needs the P2
compiler. The first P2 test should replay all nine drafts over `corpus/cache`.

## 4. Subset guard (detail)

**Classes pinned (OCSF 1.3.0):** `network_activity` (4001, 58 top-level attributes),
`http_activity` (4002, 62), `authentication` (3002, 51), `detection_finding` (2004, 58). These are
the classes the four vendors map to: ASA/PAN-OS TRAFFIC/FortiGate traffic → 4001; Squid/PAN-OS
THREAT-url/FortiGate webfilter → 4002; ASA AAA (113004 etc.)/FortiGate event-user → 3002;
PAN-OS THREAT-vulnerability/FortiGate ips → 2004.

**How completeness was verified:**
1. Tables are **generated, never hand-typed**, from the schema server's compiled export
   (`https://schema.ocsf.io/1.3.0/export/schema`, sha256 pinned in `ocsf/pinned/manifest.json`).
   Each table carries every top-level attribute the export lists for the class — own, inherited via
   `extends`, and every applied profile (cloud, datetime, osint, host, network_proxy,
   security_control, load_balancer, container, linux/linux_users, data_classification) — plus a
   leaf-path expansion to depth 4 (3 143 / 3 553 / 2 837 / 4 283 typed leaf paths) with recursion
   cut and flagged, so the P3 enumerator has typed leaves to enumerate over.
2. An **independent recompile from the schema source** (`ocsf/ocsf-schema` at tag 1.3.0, Apache-2.0,
   sha256 pinned) resolves `extends` chains, `$include`d profile files and class-level `profiles`
   with code that shares nothing with OCSF's compiler or step 1. First run: **DIFF** on all four
   classes — `time_dt`, `start_time_dt`, `end_time_dt` present only in the export. Investigation:
   `profiles/datetime.json` declares *no* attributes; OCSF's compiler synthesizes a `<name>_dt`
   companion for every `timestamp_t` attribute when the datetime profile applies. The rule was
   added to the cross-check explicitly and documented; second run: **AGREE on all four classes**
   (58/58, 62/62, 51/51, 58/58).
3. **Structurally**, the pack contract has no field in which attributes within a class could be
   listed; a pack pins `{uid, name, table_hash}` only, and both validators reject a `table_hash`
   that does not equal the generated complete table's hash. Two negative vectors prove both
   directions (`pack-attribute-pinning`, `pack-subset-guard-stale-table`).
4. Profile attributes are **included** (the wider set), which is the conservative direction for
   the guard: more survivors, fewer manufactured determinations.

## 5. Licence verdict

Beats `x-pack` fixtures: **Elastic License 2.0** (root `LICENSE.txt` assigns everything under
`x-pack/` to ELv2). Local use as test data is permitted — none of ELv2's three limitations
(managed service, licence-key circumvention, notice removal) applies. Redistribution would attach
ELv2 terms to whatever contains the fixtures and ELv2 is not OSI open source, so fixtures stay in
the git-ignored cache, reproducible from the catalogue's pinned commits and hashes, and the
submission attributes the source without embedding it.
**Apache-2.0 fallback identified:** `logstash-plugins/logstash-patterns-core` specs — real ASA lines
for eight message ids with expected grok captures, plus Squid native samples; fetched and
catalogued. **Rejected:** SEKOIA `intake-formats` — no licence file at all.

## 6. Corpus catalogue (summary; full detail in `corpus/catalogue.json` and `corpus/README.md`)

| Vendor | Files | Lines | Families | Notes |
|---|---|---|---|---|
| Cisco ASA/FTD | 10 `.log` + expected | 506 | ~100 distinct message ids (`asa.log` 7, `additional_messages.log` 76, `sample.log` 26, …) | four header variants; hostnames-for-IPs; one malformed line |
| Palo Alto PAN-OS | 10 + expected | 538 | TRAFFIC (end/start/deny/drop), THREAT (url/data/file/spyware), SYSTEM, CONFIG, GLOBALPROTECT, USERID, HIPMATCH | 46/65/75/105-cell layouts; one RFC 5424 octet-counted file; one 10.x RFC 3339-nanosecond file |
| FortiGate | 4 + expected | 72 | traffic ×4, utm ×10, event ×6 subtypes | one NUL-terminated file; eventtime precision varies |
| Squid | 2 + expected (branch 7.17) | 200 | native; custom logformat (two structural families) | module removed from Beats `main` |
| logstash-patterns-core | 2 spec files | — | 8 ASA ids + Squid | Apache-2.0 fallback |

**Families the corpus does not reach:** IDS/IPS and WAF products beyond FortiGate utm/ips and
PAN-OS THREAT (no Snort/Suricata/WAF fixtures fetched; Beats' `suricata` module is available under
the same ELv2 terms if wanted); VPN gateways only as ASA/FortiGate VPN events; no IPv6 endpoints in
any ASA line; PAN-OS doubled-quote escapes and FortiGate escaped quotes are declared per vendor
convention but unexercised by any line.

## 7. Raised, not absorbed — decisions made in P1 that touch a contract or the trace

Each is applied in the artefacts so the suites run, and each is yours to veto at this boundary.

1. **`coerce.formats` (ordered list) and `epoch_auto` added to the DSL** — the two sufficiency gaps.
   Deterministic in both stacks; no new op.
2. **Raw event bytes exclude the framing delimiter / octet-count prefix**; `framing_method` records
   it so the stream is reconstructible. `raw_hash` and all span offsets are over those bytes. The
   architecture does not state this either way; it decides what the evidence hash covers.
3. **Trace erratum — span offsets.** Stage 7's numbers do not match its own line 1: the line is
   **124 bytes, not 118**; `time` is `[0:14]`, not `[0:18]`; the status pair is `[34:46]`, not
   `[38:51]`. Golden vectors use the computed values (all six lines' lengths and sha256s are in
   `contracts/golden/tools/squid_offsets.py` output). Stage 2's `length 118` needs the same fix.
4. **Trace erratum — `activity_id`.** Stage 11 maps `activity_id (disposition)` from the cache
   result slot, but in OCSF 1.3.0 `http_activity.activity_id` enumerates HTTP methods
   (Connect=1 … Trace=8). The golden pack derives `activity_id` from the **method** slot with a
   lookup transform and leaves the cache result unmapped — which is what Stage 13's output already
   shows. Consequence: one span may feed two attributes, so mapping uniqueness is per OCSF attribute,
   not per path.
5. **Ambiguity-class lookup is a subset match** of the ranked candidate set against the class's
   `candidates` (decision 3 says "candidate attribute set → class"; subset is the drafting detail
   that makes the trace's position_5 case match `volume_direction`).
6. **Derived buffers in the span map** (`<field>#decoded`) for `decode.then` — a contract gap:
   recursive envelope unwrap (P7) parses decoded JSON-string content and its offsets cannot live in
   the raw buffer. Closed now rather than at P7.
7. **`slot_index` is 0-based** (trace "position_3" → `slot_index: 2`); `url` token class accepts
   `host[:port]` (Squid `CONNECT badsite.example:443`); golden sample count is 6 (the lines the trace
   prints), not 20.
8. **`parser_hash` is a P2 obligation** — defined as sha256 of the runtime's compiled
   representation; the golden pack sets it equal to `dsl_hash` until P2 defines that serialization.
9. **Provenance overlap noted, not changed:** three of the five sufficient categories can all be
   true of one resolution; the golden pack records the evidence kind and links the certificate.
   Which category is canonical per resolution path is P3 policy.
10. **Not a contract yet:** the normalized-output envelope (OCSF JSON + `_lineage`). P3's
    differential test needs it agreed; propose freezing it at P2 exit.
11. **Golden certificate enumerations are illustrative.** Their candidates/survivors are real
    attribute paths from the pinned table (validated), but the real lists are produced by P3's
    enumerator; the vectors prove the *format* expresses the full picture (6 IP survivors, 15
    integer survivors) rather than the trace's two-line presentation.

## 8. Trace corrections needed (for the document owner)

Stage 2 `length 118` → 124; Stage 7 offsets regenerated from bytes; Stage 11 `activity_id` source
(item 4 above); header still says "Companion to v0.6" (architecture is v0.7).

## 9. P1-retained methodology decisions (build work moved to later phases)

Recorded in `corpus/README.md` ("Reference output caveat") and restated here so the report carries
them: reference `-expected.json` output is measured as **agreement with a reference parser, never
called accuracy**, via the ECS→OCSF crosswalk built in P6; and the coverage curve's traffic mix
**will be declared** — replay streams are constructed in P8 with a documented volume mix, labelled
as an assumption wherever the curve is reported.

## 10. Boundary addendum — verification of the four proposed decisions

Verified against the pinned tables and the corpus before implementing (`scripts/verify-boundary-items.sh`).

1. **`action_id` for the cache result — correct, implemented.** `action_id` is in the pinned 4002
   table via the `security_control` profile, `integer_t`, enum `{0 Unknown, 1 Allowed, 2 Denied,
   99 Other}`. Mapped from the `%Ss` slot with a lookup (`TCP_DENIED`, `TCP_DENIED_REPLY` → 2,
   default 1) and made mandatory for 4002 (policy and acceptance snapshot). Provenance
   `vendor_schema_or_device_configuration` is consistent: both the slot's meaning (`%Ss` from the
   logformat line) and the code semantics (Squid's documented result codes) are vendor evidence.
   The `default` needed for "everything else → Allowed" did not exist in the transform — added to
   the pack schema. `disposition_id` also exists in the table (27-value enum) but is the finer
   security-control disposition; `action_id` is the right home for a proxy allow/deny decision.
   The cache-hit detail stays unmapped as `unmapped.cache_result`.
2. **Framing — not a contract change.** `framing_method` appears in **none** of the four contracts;
   it lives in the raw evidence record and the lineage envelope, both P2. The structured form
   (`method`, `raw_prefix`, `raw_suffix`, plus the §4.9 provenance fields) is now specified in
   `contracts/README.md` with reconstruction defined as `raw_prefix + raw + raw_suffix`, and P2's
   kill-test criterion is byte-exact reconstruction. No version bump, no golden regeneration.
3. **`epoch_auto` window rule — verified, implemented.** With a 2000–2100 window per precision the
   four windows are disjoint (s ends at 4.10e9, ms starts at 9.47e11; each step is ×1000 against a
   ×4.3 window), so a value matches exactly one precision or none — "more than one" cannot occur.
   All 70 FortiGate `eventtime` values in the corpus select exactly one (51 ns, 19 s), none fall
   outside. Encoded in the parser-spec description and as `precision_selected` (and
   `format_selected` for ordered lists) in the span map's `coerced` object.
4. **`parser_hash` without a version bump — consistent.** The freeze rule ties version bumps to
   schema changes; the field and its type exist, only the value rule is deferred, so P2 exit
   regenerates the golden vectors. Recorded in `contracts/README.md`.

**Finding that changed the golden pack (raise, not absorb — the trace's Stage 11 needs a further
correction):** `http_request.url` is an *object* in OCSF 1.3.0; the scalar is
`http_request.url.url_string`. And the complete 4002 table has 21 `url_t` leaves — including
`proxy_http_request.url.url_string`, which is legitimately plausible for a proxy — while a bare
method word is accepted by 203 `string_t` leaves. A type-driven enumerator over the complete
(subset-guarded) table therefore never leaves one survivor for the URL or the method, so the
trace's two structural-determination rows are not reproducible. Both fields are in fact resolved by
the logformat line (`%ru`, `%rm`); the golden pack now records them as
`vendor_schema_or_device_configuration`, and `activity_id` derives from `%rm` with the enum
lookup. Structural determination stays in the contract with its single-survivor rule enforced (a new
negative vector rejects two survivors), but **no golden field claims it**. This is item 11's
concern made concrete: the subset guard plus profile twins (`proxy_*`) make structural
determination rare; P3 should plan on device configuration and vendor tables carrying the effort
savings, and the trace should stop presenting url/method as structurally determined.

## 11. Phase-boundary signals

- Executing csv/kv/positional drafts → P2 (first P2 test).
- Real candidate enumeration for certificates → P3.
- Normalized-output contract → freeze at P2 exit.
- No git repository was initialised (not asked); `.gitignore` is in place so the corpus and OCSF
  caches can never be committed once one is.
