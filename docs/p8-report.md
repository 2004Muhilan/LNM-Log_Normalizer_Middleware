# P8 report — the closing account: the audit, versioned corrections, what the numbers support

**Third pass (2026-09-20, §13): the missing metrics deliverable — coverage under the declared replay mix, evidence
requests per coverage band, candidate-set distribution — with the cost axis in counted decisions. Agreement-with-
reference stays blocked on the crosswalk review, which is the team's.**

**Status: P8 is finished — first pass (`aca113e`) accepted 2026-09-20; this revision adds the second pass of the
same day: drift healing as a demo step, the three audit findings named as next, the effort figures re-cut to
lead with the weakest case, the packaging loose ends, and egress connectors (§9–§12).** This is the last phase
report. Built and measured on the desktop (RTX 5060 Ti); the laptop has not run this commit. Reproduce:
`bash scripts/p8-check.sh` (needs the corpus cache and Docker, refuses to run without either),
`bash demo/twice.sh`, `bash demo/run.sh 7 8`, `bash scripts/p8-connectors-smoke.sh`.

**The hard gate: `twice.sh` on both configurations, after everything in this report.** `twice.sh` fails if
the two runs *show* different things, not only if one exits non-zero.

| | run 1 | run 2 | same facts shown |
|---|---|---|---|
| 20 layers (the demo; pinned by pre-flight) | 105.1 s (step 2: 89.7) | 100.1 s (82.8) | yes — pos_1 / pos_3 / pos_5 |
| 33 of 33 layers (`ULPF_DEMO_NGL_UNPINNED=1`) | 56.8 s (41.7) | 54.8 s (39.7) | yes — pos_1 / pos_3 / pos_4 |

The two configurations differ in exactly one recorded fact, the third certificate. Steps 1–8 in one run at 20
layers: 146.3 s (step 7 correction 4.1 s, step 8 healing 45.3 s). `p1-check` … `p8-check` all pass (25 / 66 / 30 /
47 / 89 / 80 / 48 / 114 s). Step 2 is 8–15 s slower than in the first pass (74–75 s, 30–32 s) while the model's own
proposal time is unchanged (59.5 s at 20 layers): the difference is outside the model — most likely the digest of
the 2.7 GB weights being re-read from `/mnt/c` after a 5 GB image build evicted it from the page cache; not profiled.

## 1. The fix pass (commit `579d9bc`, before P8)

The loader accepts normalized-event 1.3.0; every `go test` in the scripts and the Dockerfile runs with
`-count=1`; hash-bearing paths are `-text` and pre-flight fails on a CRLF working copy; the machine label in
provenance is derived; pre-flight pins the offload split at 20 layers; the replay bundle's `run-real.sh`
summary and machine-specific doc text are fixed. Two validations asked for:

- **Does `-count=1` slow the suite materially?** No: 4.6–5.5 s uncached against 2.7 s cached for
  `go test ./...`. **Are other tests exposed the same way?** Yes, most of them: eight test files in five
  packages read outside the module root (`contracts/`, `contracts/golden/`, `drafts/`, `keys/trust`,
  `ocsf/pinned`, `corpus/cache`). Applied everywhere rather than surgically.
- **Should `.gitattributes` cover more?** It covered everything (`* text=auto eol=lf`) and that was the
  problem: normalising at commit is what let a CRLF working copy stay invisible (`git status` clean, blob
  LF, file on disk CRLF). Hash-bearing paths are now `-text` — bytes, never converted — so the divergence
  shows as a modification. Verified by writing a CRLF fixture: `M` in `git status`, `w/crlf` in `--eol`.

## 2. The audit — [p8-test-audit.md](p8-test-audit.md)

Four masked tests were the prompt; the audit's first result is a fifth, and it is the worst of the five.

**The external witness failed open.** `VerifyBundle` returned findings with a nil error on three paths and
`ulpf-verify bundle` failed only on the error: a bundle with `checkpoint.json.sig` deleted printed
`FINDING checkpoint: signature file missing` and then `VERIFY: OK … signed by a trusted authority`, exit 0.
It was hidden by a negative test that could not fail — "unknown authority refused" ran on the bundle the
previous step had tampered, against a trust path that did not exist, output discarded. Fixed, with the
missing-signature and untampered-bundle cases added in Go and in the witness script. This is a defect in
the theme demo's verifier that shipped through P5, P7 and the demo; it is recorded here, not softened.

Beyond that the audit names ~100 points across 22 scripts. **Fixed in P8** (each now fails where it
passed): no demo step had `pipefail`, so every `cmd | tee | || step_fail` was dead code and step 2 could not
fail; five pre-flight checks ran `cmd | tail` in a pipefail-less subshell and could not fail, and the
completion check passed on an empty completion; step 5 asserted an accounting identity that holds with zero
events (it passed the 92/9 CRLF run) — it now asserts quarantined = 3 with the expected reasons and both
Squid families at 6; step 6 never asserted the *before* verification or which leaf; `twice.sh` compared
nothing; `p7-demo` printed a verdict computed differently from its exit status; invariant 2(b) inspected
whatever image existed and passed on an empty listing; the oversized-message heap bound was vacuous at the
default size; `gofmt -l` could never fail; Docker skips were silent; the root-without-capability boundary
test tried only append. `p8-check.sh` is written against the patterns: named tests must each print
`--- PASS` by name, zero skips in both suites, corpus and Docker required, requirement (k) checked by
value.

**Open after the first pass** — the three named as next, all three since closed (§10): (1) `build_vectors.py`
regenerates the goldens it is about to be checked against at the top of every phase check —
`normalized/line1.json` pins nothing; (2) the five corpus replay tests compare counts and status and **no
extracted value** — P4's defect, still present on the Go side; (3) the model that answered is never
compared with the digest the pack records. Also open and listed: the subset guard compares two strings and
never rehashes the table; three negative vectors are rejected by the schema before the semantic check they
were written for; `clean-clone-test.sh` cannot fail after line 52; `check-drafts.sh` exits 1 permanently;
lineage `batch` has never appeared in an emitted event in any test; `agreement.py` pairs by a lineage field
that is never emitted; the 302013 recording stands in for two other ASA families whose packs say
`proposed_by: model`; four of five uid-65532 "kernel refusals" in the boundary test are file modes.

## 3. Versioned corrections — invariant 8

**The demo** (`bash demo/run.sh 7 7` after a full run; 3.8 s; not part of the six timed steps). Step 4
promoted the 11-slot Squid family with a retained certificate: slot 11 rested on a proposal,
`http_request.length`, its rival `http_response.length` unrefuted. The operator now supplies the device's
full logformat, ending `%>st`:

1. the certificate resolves — to neither proposal: the vendor table says `%>st` is `traffic.bytes_in`, an
   integer — and the same session promotes **pack version 1.1**;
2. `ulpf-runtime renormalize` re-derives every event **from the evidence log's raw bytes** (each checked
   against its `raw_hash`) under the corrected packs, through the same unwrap → route → parse → normalize
   path, and seals the events whose content changed as **`normalization@v2`, `derived_from: 1`**: read 98,
   corrected 6 (`squid-proxy-01/positional-11`), unchanged 92, not applicable 0;
3. `normalization@v1` is byte-identical — sha256 before = after = manifest; `lake get --event-id` returns
   both versions (v1 `http_request.length: "412"`, parser 1.0 → v2 `traffic.bytes_in: 412`, parser 1.1,
   same `event_id`, `raw_hash`, segment, offset, ingest time); v2 validates against normalized-event in both
   stacks; a shell append to v1 and a runtime `--lake` re-creation of v1 are both shown refused.

Step 6 leaves a flipped byte in the evidence. **A correction derives from evidence, so step 7 first shows
it refused** — `raw bytes of ev_… do not match raw_hash — the evidence was altered` — restores the byte
from step 6's own record, re-verifies the log, and only then corrects. That refusal was not designed for the
demo; it fell out of re-deriving from raw bytes rather than from v1, and it is the better demonstration.

**Exit criteria.** `TestCorrectionEmitsV2AndNeverTouchesV1`: v1 byte-identical and retrievable; v2 carries
`derived_from`, the corrected value, the event's identity, validates; the same correction again seals
nothing (no empty v3); a correction over altered evidence is refused and seals nothing.
`TestNoWritePathToAnExistingVersion`, `TestVerifyFindsAnAlteredVersion`, `TestStaticNoRewritePath`
(`runtime/internal/lake`): the only writer is `Create`, exclusive, latest+1, naming what it derives from;
read-only and hashed into a manifest at close; `lake.go` holds exactly two `O_EXCL` opens and no rewrite
primitive, and its callers never build a lake path themselves.

## 4. What the numbers support — the spread, weakest case first

`learning/tools/effort.py` reads only the session timelines recorded since P3. **No analyst was ever timed in
this project — not on ULPF, not on a hand-written parser — so no analyst-minute figure is measured, and none is
reported as if it were.** What both paths have is counted decisions: the baseline is one mapping decision per
semantic field, by definition; ULPF is evidence responses plus certificates the operator reads.

| source (weakest first) | families | baseline decisions | ULPF: responses + certificates | ratio | break-even: one evidence response may cost up to |
|---|---|---|---|---|---|
| **asa-fw-01** | **5** | 61 | 5 + 28 = 33 | **1.85 : 1** | **6.6 mapping decisions** |
| panos-fw-01 | 1 | 53 | 1 + 10 = 11 | 4.82 : 1 | 43 |
| squid-proxy-01 | 2 | 25 | 1 + 4 = 5 | 5.0 : 1 | 21 |
| fortigate-fw-01 | 1 | 73 | 1 + 11 = 12 | 6.08 : 1 | 62 |

n = 9 families over m = 4 sources, all promoted (the ninth is the healed ASA 302015 family of §9).

**Lead with ASA, because that is where the claim is weakest.** A source of many small families pays one
evidence response and its own certificates *per family*: five families, five responses, twenty-eight
certificates, against sixty-one fields. ULPF is ahead only while finding and supplying one piece of evidence
costs less than about 6.6 hand-made mapping decisions. Under one stated assumption — 3 minutes per mapping
decision and per certificate read, 15 minutes per evidence response — that is **183 minutes by hand against 159
with ULPF: 24 minutes saved, 13 %, and the sign flips if a response takes more than 20 minutes.** (A correction
to how this was read at the P8 boundary: the first-pass figures were baseline 141, ULPF 120 — ULPF was *ahead*
by 21 minutes, not behind. The point being made stands regardless: it is a near-tie that a slower evidence
hunt turns into a loss, and it must be shown, not averaged away.) FortiGate, one 73-field family, is 219 against
48 under the same assumption and stays ahead until a response costs three hours.

**The honest claim:** the saving depends on fields per family and on how much structure families share; it is
largest exactly where hand-authoring hurts most (wide formats, 50–70 fields) and near break-even for sources
made of many small message families — unless their families share structure that propagation can carry, which
for ASA they do not: the family anchor lives in the propagation key, so nothing crosses ASA families (a settled
decision, plan §4.4). The pooled figure, 212 decisions against 61 (3.5 : 1), is dominated by the two wide formats
and is **not to be quoted without the range**; the tool prints it last, labelled so.

Caveats that travel with every figure: counted decisions, not time; certificates counted at full reading cost
even where the vendor's documentation resolves everything at once; fixtures chosen because drafts existed for
them; nothing here says any mapping is *correct*. Agreement with the reference parser stands as measured in P6,
quoted with its sample — 208 comparable pairs over 16 of 46 ASA lines — over a crosswalk that is **unreviewed**
(owed by the team, not self-reviewed). The replay mix and the coverage figures are §13 (third pass).

Machine time (desktop): model proposal 59.5 s for the Squid session and 19.1 s for the ASA 302015 family at 20
layers; 14 s for Squid at 33 layers.

## 5. Packaging pass

**Runtime plane.** Invariant 2 re-verified on a **freshly built** final image (the check used to inspect whatever
image existed): module graph and strings clean, static binary, no weights / inference library / Python, 3.8 MB,
user `nonroot`. Requirement (k): that image normalizes the golden samples with `--network none` and the output
is checked by value (6 events; line 1's client address and URL); committer, verifier and witness run
`--network none` in the P5 tests.

**Learning plane — the loose end from the first pass, closed.** `scripts/p8-learning-image-check.sh` rebuilds
`ulpf-learning:qwen3.5-4b-q4_k_m` from the current tree (317–431 s with the llama.cpp layers cached; **4.94 GB** by `docker image inspect`), starts it with `--network none` — the only interface inside is `lo` — waits
for readiness **and fails on timeout**, and runs a real onboarding *inside* the container against the bundled,
digest-verified 4B: class, labels, **3 certificates, one evidence request**, the served-model identity check
passing on the way. Two defects surfaced doing it, both of the audit's family (audit §3.10): the P4 script's
readiness wait grepped for a string the server never prints, so it always ran to its timeout and could not fail;
and `COPY keys keys` with no `.dockerignore` entry had put the dev **private** keys into the P4 image —
`keys/dev/` is now excluded from every build context and the check asserts the image holds public keys only.
Promotion does not run inside that image (it has no runtime binary to compute `parser_hash`); the check covers
what the image is for — proposing offline. It is opt-in in `p8-check.sh` (`ULPF_P8_LEARNING_IMAGE=1`, ~6 min) and
says so when not run. The demo's own model server is `ulpf-llama` with weights mounted and a published port: it
needs no egress and is not run network-isolated.

**Two stores, two protection levels — for the report and for any slide.** The **evidence log** is hash-chained,
Merkle-committed, signed, and kernel-immutable (`FS_IMMUTABLE_FL`) when the store runs privileged; in the
unprivileged demo its checkpoints say `sealed_only_dev`, inside the signature. The **normalization lake** that
corrections live in (§3) is protected by its API — exclusive create, consecutive versions, no rewrite primitive
in the package — by read-only file modes, and by a sha256 manifest that `lake verify` recomputes. **It is not
kernel-immutable and it is not signed.** "v1 is byte-identical after a correction" is a recomputed hash, not a
cryptographic commitment: root can rewrite a lake file, and `lake verify` will then name the version. Signing
lake manifests with the committer's key, or committing them as evidence leaves, is the obvious next step and
was not taken. The runbook carries the same paragraph.

## 6. Raised, not absorbed

1. **The witness failed open since P5** (§2). Fixed; the behaviour change is that any finding is a failure.
2. **Invariant 8's store is not kernel-immutable.** "No write path to v1" is enforced by the lake package's
   API (exclusive create, consecutive versions), read-only modes and a sha256 manifest that `lake verify`
   recomputes. Root can rewrite the file; `lake verify` then names the version. The P5 `FS_IMMUTABLE_FL`
   boundary is not applied to the lake, and lake manifests are neither signed nor Merkle-committed — the
   normalized plane has never been in the evidence log. Stated in the package doc; a decision for the team.
3. **No contract change.** `normalization_version` and `derived_from` were in normalized-event since 1.0.0;
   the runtime now emits `derived_from` (only when version > 1, refusing a version without it). The lake
   layout and manifest have no schema (§3.5 of the audit lists every schema-less artifact).
4. **A correction is a new pack version from the same session** (`promote --pack-version 1.1`); the pack
   contract has no `supersedes` field and none was added — the link between pack 1.0 and 1.1 is the pack id
   and the lake manifest's reason string. If pack lineage should be first-class, that is parser-pack 1.4.0.
5. **Events that no longer route or parse under corrected packs keep their prior version** and are counted
   (`events_not_applicable`); a correction never deletes. Unchanged events get no v2.
6. **The runtime has a second parser call site** (`renormalize.go`). Invariant 6's static test was extended
   to hold it to the same rule — one `Parse`, on the routed family, after `RouteChain` — and to forbid any
   other file of the package from calling a parser.
7. **Pre-flight's pin has an escape hatch** (`ULPF_DEMO_NGL_UNPINNED=1`), loud in the output, because
   measurement runs need it; without it any value but 20 fails.
8. **Trace corrections (standing obligation).** Stage 13's lineage gains `derived_from` on corrected
   events and the trace has no stage for a correction at all: resolving a retained certificate after
   promotion → pack 1.1 → re-derivation from evidence → `normalization@v2`. Stage 8's certificate list is
   offload-dependent under a live model (pos_5 at 20 layers, pos_4 at 33); the trace's fixture list is
   neither. The verifier's Stage-14 wording should say a finding is a failure.
9. **Plan §11 rows 46–50**; plan header v1.7.

## 7. Tried and rejected

- **Deriving v2 from v1's JSON** — cheaper, and wrong: a correction would inherit the interpretation it
  corrects, and would run over tampered evidence without noticing.
- **Writing v2 for every event** — 92 byte-different copies saying the same thing; only changed content
  gets a version.
- **Sealing the version file up front** — left an empty v3 when a correction changed nothing; corrected
  events are collected first and a version exists only if there is something in it.
- **`t.Skip` when the tamper set-up cannot write** — the pattern under audit; it fails instead.
- **A measured analyst-minutes figure** — there is no measurement to report; counted decisions and a
  labelled assumption instead.
- **Fixing every audit finding** — about a fifth were fixed (the ones that let a demo or a verifier pass
  wrongly); closing the golden-regeneration hole changes how every phase check starts and deserves its own
  review.

## 8. Not done, and carried

- The *automatic* drift loop (refused by design, §9) and review-interface polish: not built. The replay mix and
  the coverage figures were built in the third pass (§13).
- **Owed by the team:** the ECS→OCSF crosswalk review (not self-reviewed) — and with it the agreement-with-reference
  results with adjudicated disagreements, the one P8 metric still blocked; two audit items (schema-shadowed negative
  vectors, lineage `batch` never validated; the subset guard is half closed, §13.7).
- **Unexercised on real data:** sequence-gap detection — no corpus vendor emits RFC 5424 `meta sequenceId`;
  coverage is four synthetic lines.
- **Not built, stated in §11:** a file-tail ingress; pass-through delivery that re-derives undelivered events from
  the evidence log instead of spooling normalized output; signed or Merkle-committed lake manifests; priority
  classes for backpressure (architecture §4.4 names them; they were never built, in any phase).
- **The laptop has not run this commit.** Pre-flight will fail there on anything the desktop run found (CRLF,
  offload split, empty completion); step 2 at 20 layers is the configuration it already used; the learning image
  check needs ~5 GB and six minutes there.

## 9. Drift healing — the demonstrable path (step 8)

Healing is **semi-automatic by design**: a system that re-learns on its own from whatever arrives can be taught by
whoever controls what arrives (architecture §3.6). The machine detects; a human re-onboards. What was missing was
a way to *show* that, because the obvious demo — re-running step 2 — shows zero certificates: the propagation
store already holds that source's resolution, correctly.

`bash demo/run.sh 8 8` (45.3 s at 20 layers, the model labelling live; writes only under `step8/`; re-runnable):

1. **Detect.** `learning/tools/drift.py` reads the quarantine and stats step 5 already wrote (refusing a partial
   file) and sorts them into what a human does next: *re-onboard candidate* — an anchor value **inside** its
   declared domain that no family owns (`asa-message-id=302015`); *domain violation* — a value **outside** its
   domain (`999999`, `WEIRD`), never a candidate; *parse-success drop* and *unknown signature*, per signature. The
   step asserts exactly one candidate and exactly those two violations.
2. **Recover the bytes.** `--extract` pulls the quarantined event's raw bytes out of the evidence store by the
   quarantine record's segment, offset and length, checked against its `raw_hash`. They were retained when nothing
   could read them; that is what makes healing possible. The operator adds the device's capture of that message
   id (24 corpus lines): 25 distinct samples.
3. **Re-onboard through the same path as step 2.** A draft spec (`drafts/sufficiency/asa-302015.json`: the 302013
   draft with the id changed — 35 of 35 corpus lines parse and its extracted values are oracle-checked), the
   model's labels (19.1 s), **8 certificates, one evidence request, zero propagated slots** — asserted: 302015 is a
   new L3 anchor value, so the §4.4 key cannot pre-empt it — the vendor's field-order documentation
   (`library/vendor-tables/cisco-asa.yaml` gains one family row), promotion, a signed pack, merged into the ASA
   source pack as version 1.1 and verified by the runtime.
4. **Replay the same capture before and after**, each into its own evidence store: **quarantined 3 → 2**, emitted
   95 → 96, `cisco-asa-fw-01/asa-302015: 1`, every other family's count unchanged, and the two domain violations
   **still quarantined** — it healed what the vendor documents and kept refusing what nobody documents.

The fallback (`ULPF_DEMO_PROVIDER=fixture`) replays the recorded labels of the *sibling* family 302013 and says so
on screen — the audit's point about recordings standing in for families the model never saw applies to it.

## 10. The three audit findings named as next — closed

Details and limits in the audit (§3.1, §3.4, §3.6); in short:

- **Goldens regenerated by the checks that read them — fixed, not explained away.** `build_vectors.py --check`
  regenerates into a scratch copy and compares all 26 files with the committed ones byte for byte; every phase
  check calls it; `--write` is the deliberate act; no argument is refused. It could be fixed outright because the
  builder is deterministic — the first check found zero differences. Proven on the defect it exists for: a
  committed `line1.json` with a schema-valid wrong `type_uid` passed every suite before and fails now, with the
  diff printed.
- **Replay tests compared no extracted value — fixed.** Per vendor, an independent oracle (a regex from the
  message guide, `encoding/csv`, a separate key=value scanner, `strings.Fields`) is compared with every value
  the spec extracts: 1,650 ASA values, 14,594 PAN-OS cells, 532 FortiGate values, 1,100 Squid values; plus a
  digest pin over every extracted (path, value) per case. No corpus text is committed. One oracle was too narrow
  for one fixture line; the test failed loudly and the oracle was widened. Not covered: 106023 / 106100 / 733100.
- **The answering model never checked — fixed as far as the server allows.** The CLI refuses to request a
  proposal unless the served file's name and the four GGUF header facts the server reports match the manifest's
  for `--model-id`; unreachable `/props` is a refusal. llama-server exposes no digest, so a same-named file with
  the same header facts would pass; the on-disk digest is verified separately. Recorded in session provenance,
  not in the pack (`provenance.proposal` is a closed object; the contract was not touched).

## 11. Connectors

### 11.1 Ingress — the claim checked against the binary

| claimed | status |
|---|---|
| syslog UDP | built, working (`--listen udp:`; RFC 3164/5424 envelope unwrapped) |
| syslog TCP with octet counting | built, working (`--listen tcp:`; RFC 6587, newline fallback; bounded per connection) |
| HTTP receive | built, working (`--listen http:`; POST bodies, size-capped) |
| directory-drop pull | built, working (`--pull-dir`; name order, renamed `.done`) |
| **file tail** | **not built.** `--input FILE` reads to EOF and stops; `--input -` reads stdin. There is no follow mode. A growing file is handled today by dropping rotated files into `--pull-dir`, or `tail -F file \| ulpf-runtime run --input -` — the second works and is nowhere tested |

`scripts/p8-connectors-smoke.sh` puts the same six golden lines in through file, stdin, UDP, TCP, HTTP and the
directory drop **through the built binary** and requires the same six events out of each, compared by value.
For the middleware claim to hold on the ingress side, one thing is missing: a follow-mode file source (with
rotation handling — which is the hard part and the reason it should not be improvised).

### 11.2 Egress — design, validated before building

**Does it touch a contract?** No. What leaves is the normalized-event document byte for byte as emitted: syslog
wraps it (RFC 5424 header, the event's identity in structured data, RFC 6587 octet counting), HTTP batches it
(NDJSON), stdout prints it. Tested as byte equality between what each sink received and the runtime's own
output. Two vocabulary additions, neither under a schema (gap records have none — audit §3.5): gap kinds
`egress_stalled` and `egress_resumed`. **Raised:** the structured-data id uses enterprise number 32473, the one
reserved for documentation; a deployment needs its own.

**How do failures behave?** Delivery is a **cursor over a durable spool**, not a queue in memory. The spool is
the normalized JSONL the runtime already writes; a forwarder per sink reads complete lines from its cursor,
sends a bounded batch, and advances only when the sink accepted it; the cursor is persisted. A SIEM that stops
accepting therefore costs **no event**: its cursor stops, the lag grows on disk, ingestion carries on. And it is
**not silent**: after `--forward-stall-after` the pipeline appends an `egress_stalled` gap record to the
**evidence log** — a Merkle leaf, committed and signed like any event, printed by `ulpf-verify gaps` — and
`egress_resumed` with the count delivered late when it catches up. An interruption of delivery is
tamper-evident on the same terms as an interruption of arrival, which is what gap accounting stands for. If
input ends with delivery still owed, the run exits **3**, says how many bytes, and `ulpf-runtime forward`
resumes from the cursor. Tested: a sink that goes away while ingestion continues (400 events, none lost, 20
re-sent, stall and resume reported); a sink that accepts the connection and **stops reading** — the write times
out instead of hanging (6,000 events, none lost); an HTTP collector answering 503 three times (exactly-once, no
partial batch); a half-written last line is never sent; a replaced spool is refused rather than guessed at; the
outage as a committed evidence leaf, end to end through the binary.

**The delivery guarantee, stated at its real strength.** At-least-once. HTTP has an acknowledgement (2xx).
Syslog over TCP has none: bytes the peer's TCP stack accepted and the peer never processed are lost unknowably —
a property of RFC 6587 — so after any connection failure the last batch believed delivered is sent again, and
receivers deduplicate on `event_id`. Order is guaranteed **within a connection, not across a reconnect**: a
receiver may read the old connection's buffered tail interleaved with the resend (the first version of the test
asserted global order and failed one run in three; the assertion, not the forwarder, was wrong). **Syslog over
UDP is refused as an egress**, with the reason: it cannot tell a sink that stopped accepting from one that is
fine.

**Does it need its own backpressure, or does architecture §4.4 cover it?** §4.4 is two sentences — bounded
queues with priority classes; state what happens at capacity; silent drop is not acceptable. It sets the rule
and covers nothing specific, and **its priority classes were never built, in any phase** (raised; they still are
not). Egress needed its own answer and has one: memory is bounded at one batch per sink whatever the sink does;
the capacity that is finite is the disk, where an optional lag alarm fires and *still drops nothing*; ingestion
is never slowed by a sink. What that deliberately does not do is push back on senders when a sink is down — for
UDP senders that would mean loss at the kernel, which is the outcome the design exists to avoid.

### 11.3 Is the evidence log a third connector class? Yes as a class; pluggable, yes; disableable, no.

Framing the system as **ingress → evidence → egress** is accurate and useful: persistence becomes a named stage
with a swappable backend (local segments today; the store is already behind one package) rather than an
embarrassment for the word "middleware". But two things must be said with it.

**The evidence sink cannot be switched off without ceasing to be this system.** Raw-before-interpretation
(invariant 3), gap records as leaves (P7), corrections re-derived from raw bytes (invariant 8), the witness, and
healing's recovery of quarantined bytes (§9) all *are* the evidence log. Disabling it is also a contract
change — lineage requires `raw_hash`, segment and offset on every event. A "null evidence sink" is a different,
weaker product and would have to say so in every event it emits. **Not built; raise it as a product decision,
not a flag.**

**"Nothing is stored in between except the evidence log" is not true as built.** The normalized output is also
at rest: it is the delivery spool the cursors point into, and the lake that corrections version. A pure
pass-through is reachable — undelivered events can be re-derived from the evidence log on restart, which is
exactly what `renormalize` already does for corrections — and would make the evidence log the *only* durable
state. It is not built, and until it is, the accurate sentence is: *the evidence log is the system of record;
the normalized spool is a delivery buffer whose retention is a deployment choice.*

## 12. Raised in the second pass

1. **No file-tail ingress** (§11.1) — the ingress claim as stated overreaches by one connector.
2. **Normalized output is at rest** (§11.3) — the middleware sentence needs the qualifier above.
3. **Egress ordering and acknowledgement limits** (§11.2) — at-least-once; per-connection order; no UDP.
4. **Two new gap kinds** and an example enterprise number in the syslog structured data — vocabulary, not contract.
5. **Backpressure priority classes (architecture §4.4) were never built.**
6. **Dev private keys were in the P4 learning image**; excluded now; image never published.
7. **The P4 learning-image start check could not fail** (wrong readiness string, no failure branch).
8. **`served_meta` added to `models/manifest.json`** for the two demo models (header facts read from the running
   server); the pack contract was not extended to carry the identity result.
9. **The 302015 draft and vendor-table row are library content** added for the healing demo; the draft is a copy
   of 302013 with the id changed, checked against 35 corpus lines.
10. **The ASA effort figure was misread at the boundary** (§4): ULPF was ahead, narrowly. Corrected rather than
    adopted, because the narrowness is the point either way.
11. **Trace corrections (standing obligation).** The trace has no stage for delivery at all — after Stage 13 an
    event is "emitted"; it should say where to, and that an interrupted delivery is an evidence record. §3.6's
    healing narrative should name the monitor's three signals and that samples come back out of the evidence
    store. Stage 12's `provenance.proposal` does not record that the served model's identity was checked.
12. **Plan §11 rows 51–56**; plan header v1.8.

## 13. Third pass — coverage under the declared replay mix

The P8 deliverable that was missing: "the coverage curve under the declared replay mix, evidence requests per
coverage, candidate-set distribution" (plan §7 P8; mix construction moved to P8 by §5.3). Built with one change
agreed at the boundary: **the cost axis is counted decisions, not minutes** — nobody was timed (§4).
Reproduce: `bash scripts/p8-coverage.sh` (regenerates and compares with the committed figures; `--write` to
regenerate them). Mix: [`metrics/replay-mix.json`](../metrics/replay-mix.json). Figures:
[`docs/metrics/coverage.json`](metrics/coverage.json). Picture: [`docs/metrics/coverage.svg`](metrics/coverage.svg).

**The gate, after this pass** (desktop; servers started per configuration; `twice.sh` fails if the two runs *show*
different things):

| | run 1 | run 2 | same facts shown |
|---|---|---|---|
| 20 layers (pinned) | 97.6 s (step 2: 81.1) | 88.6 s (74.4) | yes — pos_1 / pos_3 / pos_5 |
| 33 of 33 layers (`ULPF_DEMO_NGL_UNPINNED=1`) | 44.8 s (30.5) | 47.0 s (30.4) | yes — pos_1 / pos_3 / pos_4 |

`p1-check` … `p8-check` all pass (21 / 34 / 26 / 32 / 76 / 65 s; `p8-check` includes `p7-check` and now the
coverage check); 64 Python tests, zero skips. The coverage check was proven on the defect it exists for: with one
committed figure altered (30.15 → 31.15) `p8-coverage.sh` prints the diff and exits 1. Nothing the demo reads was
changed in this pass. (My first gate attempt failed pre-flight on three checks — the model server and the UI were
down, because the previous pass ended with `reset.sh --all`. Operator state, not a regression; pre-flight did its job.)

### 13.1 The design, validated before building — and what the validation changed

**Does the mix need to be plausible, or merely declared?** Declared is all the repository can support: no traffic
capture exists here, so plausibility cannot be established from inside the project and a "plausible" mix would be
an invented one. But *merely* declared is not enough either, because **the mix is not a nuisance parameter — it is
half the curve.** The x values (decisions per family) are measured and nearly fixed; the y increments are the
weights. One declared mix lets the author draw any shape they like. So the mix is declared **four times**, from
least to most favourable, each with its assumption written beside it, and the spread between them is reported as
the result. Nothing is quoted from one mix alone.

**Coverage is measured, not credited.** The first design weighted the nine onboarded families and would have
reached 100 % by construction. Before building it, the whole four-vendor corpus (1,316 lines, 26 files) was
replayed through the runtime with every pack loaded: **397 lines usable, 30 %.** So the mix is declared over
*traffic strata* (17: message groups and fixture files, onboarded or not), a stream is constructed per mix
(2,000 frames, largest-remainder apportionment, deterministic interleave, pools cycled), and the **runtime** says
what is usable, with the packs of the first *k* families loaded, for every *k*. Nothing is attributed to a family
by label.

**In-sample replay is an upper bound, so a held-out split is run beside it.** The demo onboards a family from all
its corpus lines and replays the same lines. Here each corpus-sampled family is also onboarded from the
even-numbered lines of its stratum and replayed over the odd-numbered ones. Result: **identical coverage at every
step for the seven anchored families** (FortiGate onboarded from 7 lines routes all 6 held-out lines; it sees 72
fields instead of 73). Its limit, stated: the *draft specs* were hand-written against the whole fixture files, so
what is held out is the onboarding (labels, enumerations, certificates, routing signature), not the spec.

### 13.2 The four declared mixes (every one is an ASSUMPTION)

| mix | what is assumed | how it was chosen |
|---|---|---|
| `corpus-lines` | every corpus line weighs the same | assumes nothing beyond the corpus; known false as traffic (fixtures are test cases, ~one line per case, so rare messages are over-represented); the **least favourable** |
| `equal-sources` | four sources at 25 %; inside a source, by corpus line count | removes the accident that PAN-OS fixtures are 40 % of all corpus lines |
| `connection-heavy` | four sources at 25 %; 80 % of each source's volume is connection/traffic logging | a firewall logs every connection; **the 80 % is a round number of ours, from no capture**; the **most favourable** to ULPF because the onboarded families are connection-class |
| `demo-families` | traffic is the nine onboarded families and nothing else, in the demo stream's proportions | the stream the demo replays; two of its pools are **ours, not corpus** (the trace's Squid sample, the synthetic 11-slot Squid family); reaches 100 % by construction; **not evidence about live traffic** |

### 13.3 What came out (held-out split; in-sample is identical)

Per family — measured from the session records (recorded/fixture providers, so reproducible; the live-model
sessions of §4 differ by a certificate or two: 60 decisions here against 61 there):

| family | onboarding samples | by hand (fields) | ULPF: responses + certificates | evidence requests | certificates resolved by the response | fields given provenance by it | slots by propagation |
|---|---|---|---|---|---|---|---|
| asa-302013 | 23 | 14 | 1 + 6 = 7 | 1 | 4 | 14 | 0 |
| asa-302014 (+302016) | 34 | 11 | 1 + 4 = 5 | 1 | 4 | 11 | 0 |
| asa-106023 | 25 | 11 | 1 + 6 = 7 | 1 | 6 | 11 | 0 |
| asa-305011 (+305012) | 41 | 11 | 1 + 4 = 5 | 1 | 4 | 11 | 0 |
| asa-302015 | 12 | 14 | 1 + 6 = 7 | 1 | 4 | 14 | 0 |
| panos-traffic | 50 | 53 | 1 + 10 = 11 | 1 | 9 | 53 | 0 |
| fortigate-traffic | 7 | 72 | 1 + 11 = 12 | 1 | 7 | 72 | 0 |
| squid-10 (ours: trace sample) | 6 | 12 | 1 + 4 = 5 | 1 | 4 | 12 | 0 |
| squid-11 (ours: synthetic) | 6 | 13 | 0 + 1 = 1 | 1 (never answered; certificate retained, slot not mandatory) | 0 | 0 | **10** |

Coverage, families in descending volume under each mix (n = 9 families, m = 4 sources):

| mix (ASSUMED) | coverage after 1 / 3 / 5 / 9 families | decisions at the end: ULPF vs by hand | ≥ 25 % reached after | ≥ 50 % |
|---|---|---|---|---|
| `corpus-lines` | 7.6 / 19.0 / 26.2 / **30.2 %** | 60 vs 211 | 5 families, 35 vs 100 decisions, 5 evidence requests | never |
| `equal-sources` | 4.7 / 13.2 / 19.0 / **24.4 %** | 60 vs 211 | never | never |
| `connection-heavy` | 20.0 / 32.7 / 41.4 / **48.6 %** | 60 vs 211 | 2 families, 23 vs 125 decisions, 2 requests | never |
| `demo-families` | 19.1 / 50.5 / 69.6 / **100 %** | 60 vs 211 | 2 families, 18 vs 67, 2 requests | 3 families, 30 vs 139, 3 requests |

**Evidence requests per coverage band** (`coverage.json` → `bands`, per mix): under the three corpus-derived mixes
only the first band (≥ 25 %) is ever reached, and under `equal-sources` not even that; the full ladder exists only
under `demo-families` (25 / 50 / 75 / 90 / 100 % after 2 / 3 / 6 / 8 / 8 responses). What *is* mix-independent:
**eight operator responses resolved 42 certificates — 5.25 ambiguities per question, range 4–9 — and gave vendor
provenance to 198 fields; the ninth family needed no response at all (10 slots by propagation).** "One question
resolves many fields" is measured, at that sample.

**Candidate-set distribution under the mix** (the runtime logs it on every replay; assembled, not new work):

| mix | size 0 (no family: quarantined) | size 1 | size ≥ 2 | max at any of the 9 steps |
|---|---|---|---|---|
| `corpus-lines` | 1,385 | 615 | 0 | 1 |
| `equal-sources` | 1,501 | 499 | 0 | 1 |
| `connection-heavy` | 1,029 | 971 | 0 | 1 |
| `demo-families` | 0 | 2,000 | 0 | 1 |

The K = 4 empirical question (plan P6 risk) stays **unanswered at this corpus breadth**: with nine families the
DAG never returned two candidates, under any mix, at any step. K is a resource bound that has not been approached,
not a bound that has been shown sufficient. (Size 1 exceeds usable by the 12 long-tail ASA lines that route and
then fail to parse — quarantined at stage `parse`.)

### 13.4 Does the curve's shape survive this corpus? No — and what to report instead

The plan's curve (§7.3 of the architecture, §1.3's argument) is concave for two reasons: volume is skewed, and
**marginal cost falls** because structurally related families cost little. At this corpus size:

- **Falling marginal cost is visible exactly once**, Squid 11-slot after Squid 10-slot (5 decisions → 1, against
  13 by hand) — and that family is **our synthetic fixture with zero corpus traffic**. In ASA, five related
  families cost 7, 5, 7, 5, 7: flat. That is the settled propagation key (plan §4.4 — the anchor is in L3, so
  nothing crosses ASA families), not a defect, but it means the §1.3 effect is **not shown on real-shaped data**.
- **Any concavity in the picture comes from the declared weights**, i.e. from us. Under `corpus-lines` the steps
  are nearly linear; `connection-heavy` looks concave only because FortiGate's 13 traffic lines are given 20 % of
  the stream.
- **Family counts per source do not distort it; field counts do.** ASA's five families are 31 of ULPF's 60
  decisions and 61 of the baseline's 211; PAN-OS and FortiGate, one family apiece, are 125 of the 211. The
  horizontal gap between the two staircases is mostly those two wide formats — the same fact as §4, seen sideways.
- **The plateau, not the slope, is the finding**: 24 % to 49 % of corpus-derived traffic, a factor of two that is
  entirely the assumption, and 100 % only when traffic is defined as what was onboarded.

So what is reported is **two staircases per mix on shared axes** (ULPF and hand-authoring reach the same coverage;
the horizontal gap is the claim), as small multiples over the four mixes, dots for families, **no fitted curve, no
single headline number**; beside it the per-family table above, which is the honest scatter: nine points, four
sources. The sentence the data supports: *"for the same coverage — whatever the traffic mix — ULPF needed 60
counted decisions where hand-authoring needs 211, 8 evidence requests for 42 ambiguities; nine families make a
quarter to a half of our corpus-derived replay analytics-ready depending on an assumed mix; the coverage-curve
shape the architecture predicts is not demonstrated at four sources."*

### 13.5 What the whole-corpus replay found (raised, not fixed)

| stratum | corpus lines | usable | why not |
|---|---|---|---|
| the 7 onboarded corpus strata (5 ASA, PAN-OS traffic, FortiGate traffic) | 381 | 381 (100 %) | — |
| **squid-native (Elastic's `access1.log`)** | 100 | **15 (15 %)** | the 10-slot family was learned from the trace's 6 lines, where the user field is always `-`: it became a structural literal, and the L4 class sketch expects `text` where these lines carry a `word`. 85 lines with a real user name are *unknown signature* — quarantined, not guessed |
| squid-custom-logformat | 100 | 0 | a draft spec exists; never onboarded |
| panos-traffic-other-layouts | 201 | 0 | other PAN-OS versions' column layouts: the type anchor's column holds `start`/`end` → drift signal (101), or RFC 5424 framing → unknown (100) |
| panos-threat / panos-other | 237 | 0 | never onboarded |
| fortigate-utm / fortigate-event | 59 | 0 | never onboarded |
| asa-long-tail (9 files, ~90 message ids) | 238 | 1 | never onboarded; 12 route and fail to parse (non-canonical headers) |

The Squid row matters for what is said on stage: **"Squid onboarded" is an in-sample statement.** Six samples in
which a field never varies produce a family that refuses real traffic where it does. The system behaves as
designed (quarantine → drift monitor → re-onboard with a wider capture), and that is a better healing demo than it
is a coverage claim. Not fixed here: re-onboarding Squid from a wider sample changes the golden pack the whole
demo stands on.

### 13.6 Tried and rejected

- **Weights over the onboarded families only** — 100 % by construction; kept only as the labelled `demo-families`.
- **One "plausible" mix** — nothing here can establish plausibility; a single mix is a free parameter.
- **Coverage computed as Σ weight × per-stratum usable rate** — exact and needs no stream, but §5.3 says replay
  streams are *constructed*, and a real replay per step is what catches a family stealing another's traffic (none did).
- **Absolute-minute axis** — not measured (§4). A relative axis (% of hand-authoring cost) hides that both totals are small.
- **A fitted or smoothed curve** — nine points.
- **Work directory on disk** — the evidence store fsynced every raw write (invariant 3 as it then was; group commit since
  2026-09-27); ~90 replays took 9 min 19 s on ext4 and 1 min 37 s on tmpfs. The script uses `/dev/shm`.
- **Naming the tool `coverage.py`** — shadows the `coverage` package under pytest; it is `coverage_curve.py`.

### 13.7 Optional audit items — one half-closed, two left owed

- **Subset guard (§3.2): Python side closed.** `learning/tests/test_pinned_tables.py` recomputes every pinned
  table's hash from its file (the generator's definition) and compares it with the file's own claim and the index;
  a table with one leaf path removed no longer matches. **The Go loader still compares two strings**: the hash is
  over Python's canonical JSON, and reproducing that in Go is the canonical-JSON machinery plan §1 rules out;
  redefining it over file bytes changes every pack hash and golden. A decision for the team, not absorbed.
- **Schema-shadowed negative vectors (§3.3): not quick, left owed.** It needs three new vectors that pass the
  schema and fail only the semantic check, i.e. a `build_vectors.py --write` and a review of the golden diff.
- **Lineage `batch` (§3.5): not quick, left owed.** De-batched elements are raw JSON values; no onboarded family
  has a JSON surface, so every element quarantines and no emitted event can carry `batch`. Closing it needs a
  JSON-surface pack (a hand-authored spec and golden pack), not a test.

### 13.8 Raised in the third pass

1. **Coverage of corpus-derived traffic is 24–49 %, not "four vendors covered"** (§13.3) — wording for any slide.
2. **The §1.3 marginal-cost effect is shown only on a synthetic family** (§13.4).
3. **Squid native: 15 % out-of-sample** (§13.5); the golden Squid pack was not touched.
4. **K = 4 is unexercised**: no replay ever produced two candidates (§13.3).
5. **Held-out does not hold out the draft specs** (§13.1).
6. **Agreement-with-reference with adjudicated disagreements** — the fourth P8 metric — **remains blocked** on the
   crosswalk review, which is the team's and was not self-reviewed. The P6 figure stands as measured, quoted with
   its sample: 208 comparable pairs over 16 of 46 ASA lines.
7. **Trace corrections (standing obligation):** none from this pass — nothing here changes behaviour.
8. **Plan §11 rows 57–58**; plan header v1.9. No contract, invariant or settled decision was touched: the new code
   is a learning-plane tool, a mix file, a script, two test files and a check in `p8-check.sh`.

### 13.9 Read against the plan, deliverable by deliverable — what is still missing

Checked against plan §7 P1–P8, §2 and §5 after this pass. Everything not listed here is built and has a check.
**The implementation is not "fully finished" against the plan as written; these are the differences.**

*Not built, or built as something narrower than the plan's words:*

1. **P8 — agreement-with-reference results with adjudicated disagreements.** Measured once, in P6, on one ASA
   family: 208 comparable pairs over 16 of 46 lines, one row adjudicated. Never run for PAN-OS, FortiGate or
   Squid, and blocked from being reported by item 2.
2. **P1 exit criterion — "crosswalk review complete".** `library/crosswalk/ecs-ocsf.yaml` is built and
   **unreviewed**. The team's; not self-reviewed. It has been open since P1's exit.
3. **P2 — "file-tail ingest".** `--input` reads a file to EOF and stops; nothing follows a growing file. The P2
   report calls it file-tail; it is file-read. A rotated-file drop (`--pull-dir`) is the working substitute (§11.1).
4. **P8 — "review-interface polish" / P3 — "accept the response" through the interface.** The working surface is
   the CLI (`certificates`, `respond`); the demo UI's certificate screen is a **read-only viewer** of the same
   session files. Nothing in the browser accepts evidence.
5. *(Built after this report: [live-demo-report.md](live-demo-report.md) — a generator changes format mid-run, the monitor fires,
   the stream is re-onboarded through the same path.)* **P8 demo, §8.3 step 4 — "format broken mid-run, drift detected, re-onboarded".** Step 8 heals an in-domain
   message id no family owned, from the previous step's quarantine, by a human (semi-automatic by design, §9). No
   step breaks a format *mid-run*; the parse-success-drop monitor exists and has never fired in a demo.
6. **P8 demo, §8.3 step 5 — "the daily root verified on a second machine".** Step 6's witness is a container that
   has never run ULPF and holds only the public key, **on the same machine**. No bundle has been carried to the
   other machine and verified there.
7. **Coverage-curve shape** (§13.4): the deliverable exists; the shape the architecture predicts is not
   demonstrated at four sources.

*Built, never exercised on real data:* sequence-gap detection (four synthetic lines; no corpus vendor emits an
RFC 5424 sequence id); K = 4 (max candidate set 1, §13.3); PAN-OS doubled-quote escapes and FortiGate escaped
quotes (no fixture has them, P1); lineage `batch` on an emitted event (§13.7).

*Changed by a recorded decision, so not missing:* the per-pack tiebreaker (dropped, row 32); the 7–8B model (the
demo serves the 4B, row 23; Granite 8B proposals are replayed as recordings); analyst-minutes (counted decisions,
row 48); the automatic drift loop (refused, row 51).

*Owed outside the code:* the worked-trace corrections listed in every report since P5 have not been applied to
the trace (it is not in this repository); the laptop has run no commit from `579d9bc` on; two audit items and the Go
half of the subset guard (§13.7); architecture §4.4's priority classes (§11.2).
