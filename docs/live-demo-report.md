# Live demo sequence — generator in, consumer out, onboarding and drift in between

**Second pass (2026-09-20, §8): the sequence was rebuilt around nine requirements — quarantine-first with a human decision, an egress outage, a view on the database, two connectors on each side, the four on-stage hazards decided (three fixed in the pipeline, one replaced by hot reload), and automatic healing with a policy split and an alert. §1–§7 describe the first pass; where §8 contradicts them, §8 is current** (in particular: the pipeline *was* changed in the second pass, §5 items 2, 3, 5 and 6 are closed, and the v2 format is different).

**Status (2026-09-20): built, additive, gated.** A parallel sequence (`demo/live/`, screen `5`) beside the six rehearsed
steps, which were not touched. Built around the three selling points: **live onboarding**, **the ambiguity
certificate**, **drift detection**. Nothing in the pipeline changed: no Go, no `ulpf_learn`, no contract. What did
change outside it: two new apps, a sequence script, the drift **tool** (`learning/tools/drift.py`: a live mode and
extraction by signature), the UI (one new screen, one write endpoint), `reset.sh` (stops the new apps).
Reproduce: `bash demo/live/run-live.sh`, `bash demo/live/twice-live.sh`; narration: [demo-runbook.md](demo-runbook.md).

**The gate** (desktop, servers started per configuration; both twice-runners fail if the two runs *show* different things):

| | six steps, run 1 / run 2 | live sequence, run 1 / run 2 | same facts shown |
|---|---|---|---|
| 20 layers (pinned) | 90.8 s / 91.1 s | 151 s / 126 s | yes / yes |
| 33 of 33 layers (`ULPF_DEMO_NGL_UNPINNED=1`) | 45.5 s / 47.4 s | 115 s / 98 s | yes / yes |

After the last edits (the whitespace-drift check) the live sequence was run twice more at 20 layers — 143 s / 179 s, same
facts — with the fixture fallback (41 s) and `parse-drop-check.sh` (PASS). 68 Python tests pass (4 new). The interactive path was exercised once end to end: one assertion clicked in the browser,
the rest sent through the same endpoint, a malformed choice refused with 400. **The laptop has not run this.**

## 1. Step 1 — the format validated before anything was built

The intended format went through induction, the enumerator and the analyzer first with a stand-in proposal, then with
the **live 4B at both offload splits**, in three column orders. Chosen (`flowtap` v1, 9 whitespace columns):

```
1758350000.324 1 tcp 203.0.113.167 34350 10.4.3.103 443 6235241 78320482
epoch.ms  verdict proto  address port  address port  counter counter        (both directions occur: no column is "the private one")
```

| what fires | with a competent stand-in proposal | with the live 4B (20 and 33 layers, 7 runs of this column order) |
|---|---|---|
| `endpoint_orientation` on both **addresses** (the one to build around) | yes | **yes, every run** |
| `endpoint_orientation` on the two ports | yes | usually (one or both; varies run to run) |
| `temporal_role` on the bare timestamp — the second class | yes (6 rivals) | **yes, every run** |
| `volume_direction` on the two counters | yes | **no** — the 4B never labels the counters `traffic.*` in this column order (it says `connection_info.direction` or nothing); it fired only in a rejected column order, through a mislabel |
| event class | 4001 | 4001, every run |
| mandatory attributes blocked | 4 | 4 (`time`, `src_endpoint.ip`, `dst_endpoint.ip` on a proposal only; `action_id` not mapped) |

**"At least one field that resolves cleanly" does not exist, in any format.** Structural determination needs exactly
one enumerated survivor. Over the pinned 3,143-leaf table the *smallest* survivor set any token shape reaches in class
4001 is 9 (a MAC), 10 (an IPv4, a URL); numbers and words leave 650–790. The golden Squid pack has no structural
determination in it either — every field is `vendor_schema_or_device_configuration`. So the on-screen contrast is not
"knows / refuses to guess" but **"ambiguous between named rivals" (a certificate) / "a proposal with no evidence"
(unevidenced) / "asserted by a named operator"** — that is what screen 5's provenance column shows. Invariant 4's
structural-determination branch is unit-tested and, on real tables, unreachable. Raised (§5.1).

The model's labels on the *other* columns vary between runs, because the onboarding samples come from the live stream
and carry real timestamps: 4, 5 or 7 certificates were seen. The sequence asserts only the three it is built around;
`twice-live.sh` compares those and prints the rest.

## 2. How the ambiguity is resolved on stage — confirmed: operator assertion, with its limits

There is no vendor table for an invented format, so `device_logformat_configuration` and `vendor_schema_field_order` do
not apply. `operator_labelled_session` exists and would be stronger evidence (`validated_discriminator`), but as built
it maps only the slot that holds the labelled initiator and leaves the other address's certificate open. The path that
reaches promotion today is **`operator_assertion`**: `respond --discriminator operator_assertion --field pos_4
--attribute src_endpoint.ip`, per field, provenance recorded with the operator id inside the signed pack.

- **The dropdown exists** (`ULPF_LIVE_INTERACTIVE=1`): screen 5 lists every column with its samples, its certificate
  and a select whose first options are the certificate's own candidates. A choice is `POST /live/assert` → one line in
  `live/assertions.jsonl`; the UI server executes nothing; `demo/live/assertions.py` reads the queue and calls the same
  CLI. Scripted runs queue the same lines. This is the UI's **first write path** — it was read-only by design until now.
- **One answer resolves one field.** Nine assertions for nine columns — *the same count as hand-authoring the mapping*
  (effort, in counted decisions: 9 responses + 4–7 certificates read against 9 by hand; on this path ULPF costs **more**
  decisions than hand-authoring for the first family). "One question resolves many" stays step 2's claim.
- **The second onboarding is where it pays:** after the drift, 8 of 10 columns propagate under the §4.4 key and 2 are
  asserted — 2 against 10. Measured in both gate configurations.
- Why all nine and not only the four mandatory ones: an unasserted column keeps the model's label as a *mapping* with
  provenance `model_proposal`, and the live 4B labelled two columns of the v2 format `dst_endpoint.port` — a pack the
  contract refuses ("an OCSF attribute is mapped more than once"). Found on the first live run; §5.4.

The narration for the dropdown is in the runbook ("The dropdown — what to say when the resolution is not a config line").

## 3. What was built

- **`demo/live/flowgen.py`** — generator, stdlib only. Syslog/TCP with RFC 6587 octet counting, a steady rate, a
  backlog, a control file (`run` / `pause` / `drift` / `finish` / `stop`), `--drift --drift-after N`, a status file.
- **`demo/live/sink.py`** — consumer, stdlib only. `POST` NDJSON → SQLite, `event_id` primary key, `INSERT OR IGNORE`
  (delivery is at-least-once; duplicates are counted), 2xx only after commit — that answer is ULPF's acknowledgement.
  HTTP POST was chosen over syslog forward because it has a real acknowledgement.
- **`demo/live/run-live.sh`** — phases A–G (runbook table). One evidence log for the whole session across three
  runtime processes; a run directory per process; the consumer and the monitor run throughout.
- **`learning/tools/drift.py --watch`** — the same monitor over a stream that has not ended: parse success over the
  last 40 frames, fires below 80 % once 20 frames exist, names the dominant signal, says RECOVERED.
  **`--extract-signature`**: the raw bytes of one unknown-signature group out of the evidence store, `raw_hash` checked.
- **UI screen 5** — generator → ingress → runtime (evidence records, usable, quarantined, windowed parse success, the
  fired banner) → egress → consumer (rows), the monitor's log, the operator's panel, the certificate cards.

## 4. Drift — confirmed to fire, and what exactly fires

On `drift`, the generator switches to v2 (ISO 8601 timestamp, an appended zone column). Observed in every run: parse
success over the window falls 100 % → 75 % (**fires**, 10 events of the new signature) → 47 % two seconds later → 0 %;
every v2 line is quarantined at stage `routing` with its bytes in the evidence log; after healing: RECOVERED at 82 %.
**This is the first time in the project that a drift monitor fired on a running stream**, and §8.3 step 4 ("format
broken mid-run, drift detected, re-onboarded") now exists (P8 report §13.9 item 5).

What fires in the narrated sequence is **parse success falling below the threshold, dominated by
`unknown_signatures`** — *not* the signal `drift.py` calls `parse_success_drop` (routed to a family, then refused by
its parser). For an induced positional family the router's L4 sketch compares the token class of every slot exactly,
so a changed column changes the signature and never reaches the parser. The one change the router does not see and the
parser does is **whitespace**: the router tokenises with `strings.Fields`, the spec rejects a trailing delimiter.

**So that signal was made to fire too, live, as a measurement** — `bash demo/live/parse-drop-check.sh` (12 s; generator
control `drift-pad`, one trailing space per line): parse success 100 % → 72 %, **`DRIFT MONITOR FIRED … parse_success_drop`**,
35 routed-then-refused events in the window, zero unknown signatures. It is not in the narrated sequence because **it
cannot be healed by re-onboarding**: induction tokenises on whitespace exactly like the router, so the induced spec
rejects the very samples it was induced from ("12 of 12 samples fail to parse" — measured by the same script). A
format whose only change is padding needs a spec edit by a human, or an induction that looks at delimiters. Raised (§5.11).

## 5. Raised, not absorbed — all of these are pipeline changes nobody has approved

1. **Structural determination is unreachable on the pinned tables** (§1).
2. **The assertion path does no type coercion.** `apply_operator_assertion` sets an attribute and nothing else; the
   cell keeps no `coerce`. Emitted events carry `"time": "1789900220.082"`, `"action_id": "1"`, ports and counters as
   strings, and `_lineage.event_time` is 0. They pass the normalized-event schema and are wrong OCSF. The vendor-table
   path supplies coercions; nothing else does. A fix is small (derive the coercion from the pinned attribute's type and
   the token class — deterministic, no model) and it is a learning-plane behaviour change. **The format carries OCSF's
   own verdict codes (1/2) for the same reason**: an assertion cannot carry a value map, so `ALLOW`/`DENY` could never
   satisfy mandatory `action_id`.
3. **A pack promoted without a vendor table says it is Squid**: `emit.py` defaults `source` to `{vendor: Squid,
   product: Squid Cache}`, and the family description says "resolved by device configuration". Every flowtap event
   carries `metadata.product.name = "Squid Cache"`. The induced path was only ever run on Squid.
4. **Unasserted, non-mandatory model labels are emitted as mappings** (provenance `model_proposal`, certificate
   retained): invariant 4 guards mandatory attributes only. Two columns given the same label make an unpromotable pack
   and the session offers no way to *unmap* a column. The model's `unmapped_name` also survives an assertion (events
   carry `unmapped: {slot_2: "1"}` beside the asserted `action_id`).
5. **The system's request is unanswerable here and keeps being re-issued**: the analyzer selects
   `device_logformat_configuration` (free tier) for a source that has no such artifact; `operator_assertion` is not a
   library discriminator, so after each assertion the same request is issued again — the session records 9 evidence
   requests for 9 responses. It inflates the effort instrumentation.
6. **Pack activation is a process restart.** No reload. The generator is paused around it because syslog/TCP has no
   acknowledgement; an unplanned crash can lose in-flight lines.
7. **There is no re-ingest-from-evidence.** `renormalize` covers events that were normalized once; a quarantined event
   never was. The backfill here is the monitor's extraction plus an ordinary `run --input` into a **second evidence
   store**, with new event ids; the link to the original evidence record is the `raw_hash`, which the accounting checks
   by value. At 8 lines/s and two ~55 s model calls, ~90 % of a run's lines take this route.
8. **Normalized output is at rest between the connectors** (the delivery spool) — unchanged from P8 §11.3; the
   runbook's picture says so.
9. **The UI is no longer read-only** (one queue file; the server executes nothing).
10. **The live model's certificate set is not reproducible between runs** on live samples; a draw on which it fails to
    label both addresses fails phase B (not seen in 7 runs). Fallback: `ULPF_DEMO_PROVIDER=fixture`.
11. **A whitespace-only drift is detected and cannot be re-onboarded** (§4): the induced positional spec rejects leading and
    trailing delimiters that induction itself ignores.

## 6. Tried and rejected

- **Column order A** (`ts ip ip port port proto bytes bytes verdict`): the 4B labelled a counter as a port and the
  verdict as `traffic.packets`; `volume_direction` fired only through that mislabel. **Order B** (`ts ip port ip port
  proto verdict bytes bytes`): ports mislabelled, counters as `actor.process.auid`. Order C is the one in use.
- **A vendor table for flowtap** — it would make the rehearsed logformat path work and would be us writing the answer key.
- **Asserting only the four mandatory fields** — promotes, then the v2 pack is refused (§5.4).
- **A trailing-space drift as the narrated one**, because it lights up the `parse_success_drop` key — it cannot be
  healed through the path the audience watched (§4), so it is a separate 12-second check and the narrated drift is
  the realistic one: columns change.
- **`stop` for the generator at the end** — it drops the backlog; `finish` delivers it, so the accounting can be exact.
- **Comparing certificate sets or counts between the two live runs** — both depend on the clock.
- **Driving the dropdown from the UI server** (`subprocess` in a request handler) — the server stays a file server.

## 7. Carried

The crosswalk review is the team's and was not self-reviewed (agreement results stay blocked). Sequence-gap detection
remains unexercised on real data. Everything in P8 report §13.9 stands except item 5, which this sequence builds.

## 8. Second pass — what changed, what was decided, what is raised

**The gate, after everything (desktop; every check re-run, not only the last one touched):**

| | six steps, run 1 / run 2 | live sequence (phases A–I), run 1 / run 2 | same facts shown |
|---|---|---|---|
| 20 layers (pinned) | 91.5 s / 89.8 s | 168 s / 134 s | yes / yes |
| 33 of 33 layers (`ULPF_DEMO_NGL_UNPINNED=1`) | 48.3 s / 45.3 s | 149 s / 143 s | yes / yes |

`p1-check` … `p8-check` all pass after the pipeline changes (21 / 69 / 27 / 32 / 80 / 70 s; `p8-check` 187 s, which runs
`p7-check`, zero skipped tests, the golden check — 26 files byte-identical — the coverage check — committed figures
regenerate byte for byte — the connector smoke and the image checks). 73 Python tests (5 new in this pass), the Go suite
with a new reload test, `gofmt` clean. The fixture fallback runs the whole sequence in 54 s. `twice-live.sh` now compares the
Tier 1 decision, the request and its count, typed values, the alert (binding, propagated, promoted, withheld, pack
version), the monitor's signatures, the evidence-log record kinds and the accounting. The interactive path (the
*onboard* button and the dropdowns) was exercised by hand in the first pass only; the button's endpoint is new and was
**not** clicked through in a browser in this pass — the scripted path writes the same record. The laptop has run none of this.

### 8.1 The nine, in order

1. **Quarantine first, then a human.** Phase A ends in a wait. Two unconfigured sensors send; every line is quarantined
   (the sequence *asserts* `usable == 0` before going on); nothing proceeds until `{"onboard": true}` is recorded —
   the button on screen 5, or the script after 5 s. The record (`live/tier1-decision.json`) names the operator, the
   signature, and how many lines were quarantined and parsed when the decision was made. After it, onboarding runs by
   itself and stops only at the operator-assertion request. *Limit:* Tier 1 is "recorded operator id only" (plan §4.6);
   the decision record is a demo-layer file, not a pipeline artifact — raised (§8.4.1).
2. **Egress outage.** Phase D kills the consumer. Measured in every run: ULPF keeps ingesting (≥ 40 more usable events
   are required before the consumer comes back), `egress_stalled` appears in the evidence log after the 2 s threshold,
   the consumer restarts, the backlog is delivered from the cursor, `egress_resumed` follows, the row count catches up
   to ULPF's. Nothing new in the pipeline: this is P8's forwarder, shown.
3. **The storage app has a view**: `http://127.0.0.1:8790/` (served by `sink.py` itself, stdlib, offline): row count,
   rows stored per second over the last two minutes (the outage is the flat stretch, the catch-up and the backfill are
   the spikes), latest rows with typed values. Screen 5 shows the same app as an endpoint, DOWN in red during the outage.
4. **Two connectors on each side — built, both cheap.** *(The first pass was syslog/TCP in and HTTP POST out, not HTTP
   on both sides.)* Ingress: `--listen` is now repeatable for one `tcp:` plus one `http:` listener in one runtime
   (≈40 lines of Go); each frame carries its connector into its evidence record (`ingest_channel`). A second generator
   instance posts over HTTP. Egress: `--forward` was already repeatable; `stdout:` is the second sink, redirected to a
   file. The accounting requires `stdout lines == usable events` and one evidence channel of each kind.
5. **Type coercion — fixed, contained, no contract touched.** `apply_operator_assertion` now derives the cell's coercion
   from the **pinned OCSF type** of the asserted attribute and the slot's token class (`timestamp_t` + float → epoch with
   fraction, + integer → `epoch_auto`, + RFC 3339 text → rfc3339; integer types → int; `ip_t` → ip) — deterministic, never
   from a proposal; `None` when nothing can be derived (the value stays a string, as before). Emitted events now carry
   `time` in epoch ms, `_lineage.event_time == time`, integer `action_id`, ports and counters; the sequence asserts it.
   The parser-spec contract already had every coercion used. What it does **not** fix: an assertion still cannot carry a
   value map, so the format keeps OCSF's own verdict codes.
6. **The Squid stamp — fixed.** A session whose vendor has no table produces a pack whose `source` is what the operator
   said (`--vendor`, new `--product`, `--transport-hint`), and a family description naming how it was actually resolved.
   The Squid default is kept for `vendor == squid` only, so the golden pack is byte-identical (`build_vectors.py --check`: 26 files).
7. **The unanswerable request — replaced by an answerable one, and no longer re-counted.** When the library has no
   document applier for the session's vendor, the two document discriminators are dropped from the ranking and the
   request is `operator_assertion` over every pending field, with the library's remaining discriminators as alternatives.
   Separately, a request that only *shrinks* (same discriminator, a subset of the fields) is no longer logged as a new
   `request_issued`: **1 evidence request for 9 responses**, where it was 9 for 9. Vendor-table sessions are unaffected
   (one response resolves everything; the coverage figures regenerate byte for byte — see the gate).
8. **Hot reload — built, contained.** `Pipeline.Reload` swaps the router under the frame mutex, between two frames;
   the CLI re-reads `--pack` and the new `--packs-file` on SIGHUP through the **same fail-closed loader** (schema, static
   invariants, signature); a set that does not load, or an empty one, leaves the running router in place. Every changed
   pack is a **`pack_activated` / `pack_deactivated` record in the evidence log** naming the pack's version and the sha256
   of the signed bytes. The whole sequence is now **one runtime process**: no restart, the generators never pause.
   Invariant 6's static test still passes unchanged (one `Parse`, on the routed family).
9. **Automatic healing with a policy split** — §8.2.

Also closed from §5: unasserted model labels are no longer emitted **where `--withhold-unevidenced` is used** (the live
sequence and auto-heal use it; the default is unchanged so nothing else moves) — the column is parsed, carried unmapped,
its certificate retained. An assertion now clears the provider's `unmapped_name`.

### 8.2 Automatic healing — validated before building; three answers

**(a) Is "this source was already onboarded" sufficient? No.** A quarantined line carries no source identity — only
an ingest channel and a peer. If "onboarded" alone unlocked healing, anything able to reach the listener could send a
look-alike format whose columns sit where the old ones sat and **inherit the operator's answers by position** (swap the
address columns and every event's direction is wrong, on "evidence"). So `autoheal.py` requires a **source binding**:
every drifted sample's (ingest channel, peer host) must be among those that already delivered events *emitted under
this source's families*. Otherwise it writes an alert with outcome *refused* and promotes nothing. The binding is only
as strong as the transport — plain syslog/TCP and HTTP authenticate nobody — and the alert says so in a `limit` field.
A real Tier 1 / Tier 2 distinction at the transport (mTLS, syslog-TLS) does not exist in this build. Raised (§8.4.2).

**(b) Does the alert belong in the evidence log? Yes — and the part that must be there, is.** The change of
interpretation is recorded by the *runtime*, at the moment it takes effect, as a `pack_activated` leaf naming the pack's
sha256; it is hashed, Merkle-committed and exportable like a gap record. The alert document names the same sha256 and
carries the reasoning (what changed, what propagated, what the model proposed, what was promoted on which provenance,
what was withheld and why, the previous packs, the rollback command). The alert *document itself* is a file beside the
pack, **not** a leaf: committing it needs a way for the learning plane to append to the runtime's evidence store, which
does not exist. Raised (§8.4.3).

**(c) Does the acceptance policy assume a human at promotion? In three places.** `sample_provenance` wants an
`operator_id` and a tier — auto-heal records `auto-heal`, tier 1 (the samples are an onboarded source's evidence); the
pack is signed by whatever key is on the machine — unattended signing means **the pack-authority key lives on the
middleware box**, which is a real change in the threat model; and `promote` had no notion of withholding. None of it
touches a contract. Invariant 4 is untouched: a model proposal promotes nothing, mandatory or not. Raised (§8.4.4).

**The policy as built** (`learning/tools/autoheal.py`, `POLICY_VERSION autoheal-1.0`), per *field*, which is how both
rows of the table appear in one drift:

| field rests on | what happens |
|---|---|
| propagation under the §4.4 key, or a vendor table | **promoted automatically**; listed in the alert with its provenance |
| a model proposal, a certificate, or nothing | **withheld**: parsed, carried unmapped, certificate retained; the operator is asked |
| — and if a **mandatory** attribute is among the withheld | **nothing is promoted**; the alert says *blocked* and the stream stays quarantined until the operator answers |

Measured, both providers: 8 of 10 columns propagate (slots 1, 2, 4–9 — every mandatory attribute), pack 1.1 is
promoted and hot-loaded with no human, parse success recovers; slots 3 and 10 are withheld and asked; two assertions
make pack 1.2. **Rollback is one command** (`autoheal.py rollback --alert … --packs-file … --runtime-pid …`) and is run
for real in phase G, then re-applied: both changes are `pack_activated` leaves. `parse-drop-check.sh` is phase I.

**The v2 format was changed for this**, and that is a design decision to look at: the first pass's drift changed the
*timestamp* column (epoch → ISO 8601). `time` is mandatory, so under the unchanged acceptance policy that drift can
never heal in part — the third row of the table. The drift now changes the protocol column (name → IANA number) and
appends a zone: everything mandatory still propagates. **"Partial promotion is fine" holds only when what did not
resolve is not mandatory**; the blocked outcome is implemented and reachable, and is not what the sequence shows.

### 8.3 Tried and rejected (second pass)

- **Restart with a scripted pause** for pack activation — hot reload was contained, so the pause is gone.
- **A second runtime process for the second ingress connector** — two evidence logs; one process with two listeners instead.
- **Exact `ip:port` peer binding** — an HTTP client's port changes with its connection; channel + peer host, with the limit stated.
- **Promoting the model's label for the withheld columns because nothing rivals it** ("unambiguous proposal") — a proposal
  is not evidence (invariant 4's reasoning applies to every field, not only mandatory ones); withheld instead.
- **Waiting on the monitor's frame total at the end** — the runtime's quarantine file is buffered and only complete at
  exit, so the monitor lags by up to a buffer; the runtime's own count is what the accounting checks.
- **Auto-heal skipping the model** because everything promoted came from propagation — the model's labels are what the
  operator is shown for the withheld columns; but see §8.4.6.

### 8.4 Raised, not absorbed

1. **The Tier 1 decision is a demo-layer record.** The pipeline has no object for "a human decided to onboard this
   source"; a session simply starts with an `--operator`. If the decision should be provable, it belongs in the session
   and the pack's `sample_provenance`, or in the evidence log.
2. **Source binding is not authentication** (§8.2a). With the transports built, auto-healing trusts the network path.
3. **The alert document is not a leaf** (§8.2b); only the activation is.
4. **Unattended signing puts the pack-authority key on the runtime host** (§8.2c). File-based dev keys made this
   invisible; a deployment needs a decision (a separate healing authority with a narrower trust scope is the obvious one).
5. **Hot reload adds two evidence record kinds** (`pack_activated`, `pack_deactivated`). Gap-record kinds have no schema
   (P8 audit §3.5), so no contract changed — and that is the problem the audit named, now one kind larger. The verifier
   prints them with the generic branch.
6. **Healing latency is the model's** (~55 s at 20 layers) although nothing the model says is promoted; a fast path —
   promote on propagation first, label the withheld columns afterwards — would make healing sub-second. Not built.
7. **`--withhold-unevidenced` is opt-in.** The default still emits non-mandatory model labels as mappings (P3 behaviour,
   every vendor pack in the repo was built that way and is fully evidenced, so it never showed). Whether the default
   should flip is a team decision: it changes what existing sessions promote.
8. **The runtime's quarantine writer is buffered**; a live monitor sees quarantine records up to a buffer late. Flushing
   per record when a monitor is attached is a one-line runtime change, not made.
9. **The live model proposes nothing for the two withheld columns**, so the second policy row shows on stage as
   "nobody has said what this column is", not as a certificate; the fixture fallback shows the zone column as an
   `endpoint_orientation` certificate.
10. **Trace corrections (standing obligation):** the trace has no stage for a pack change on a running system, none for
    a delivery interruption (raised in P8), and Stage 9's request text does not cover a source with no document.
11. Still open from §5: structural determination unreachable (1); no re-ingest-from-evidence (7); normalized output at
    rest (8); the UI writes two queue files now (9); the model's certificate set varies between runs (10); whitespace
    drift cannot be re-onboarded (11). **Carried:** the crosswalk review is the team's, not self-reviewed; sequence-gap
    detection is unexercised on real data; the laptop has run none of this.

## 9. Third pass — the screens, stripped back (presentation only)

Screen 5 of the six-step UI is gone (key `5` there now opens the new page); the live sequence has **three plain pages**,
vanilla HTML/CSS/JS, nothing fetched from anywhere: `demo/ui/live.html` + `live.js` (System: two UP/DOWN blocks, the
phase list, and only the running phase's detail), `demo/ui/generator.html` (raw lines, scrolling, with their connector),
and the consumer's own page in `demo/live/sink.py` (a row count and the latest rows; the per-second chart is removed).
One stylesheet, `plain.css`: black on white, large type, red for down / failing and no other colour. Removed: the
per-family counts, quarantine-reason and candidate-set figures, the monitor's event log, the generic evidence-record
list, batches / duplicates, the arrows and connector boxes, tags and tinted panels.

`run-live.sh` drives the phases exactly as before; no phase control was added. **Below the UI, two demo-app edits and
nothing else:** `flowgen.py` adds its last 16 lines to the status file it already writes (the Generator page needs the
lines, not only the last one), and `sink.py`'s embedded page was rewritten. No pipeline file, no script logic.

**The interactive path was clicked through in a browser this time** (fixture provider): *onboard this source* in phase
A → the sequence left the wait; `pos_4`, `pos_6`, `pos_1`, `pos_2` chosen from the dropdowns and asserted one by one →
the blocker line went 4 → 3 → 2 → 1 → "every mandatory field has evidence"; *promote*; the outage and the alert appeared
and went away with their phases; *promote* again in phase F with the zone certificate on screen; the run ended
2,226 lines = 2,226 evidence records = 2,226 rows. The dropdown now offers `connection_info.protocol_num` (it did not,
so phase F could only be completed from the operator's notes).

**Raised, not built:** the script stops the consumer when the sequence ends, so the Database page then says DOWN in red
(the System page says STOPPED). Leaving the consumer running after phase H is a one-line change in `run-live.sh`, i.e.
below the UI — not made. The gate after this pass:

| | six steps, run 1 / run 2 | live sequence (A–I), run 1 / run 2 | same facts shown |
|---|---|---|---|
| 20 layers (pinned) | 90.6 s / 91.0 s | 180 s / 162 s | yes / yes |
| 33 of 33 layers (`ULPF_DEMO_NGL_UNPINNED=1`) | 45.6 s / 47.8 s | 150 s / 159 s | yes / yes |

73 Python tests pass. Run after the last edit to any script (the scripts' messages now say "the System page" where they
said "screen 5"; the first gate attempt was stopped for that edit and restarted from the beginning). The phase checks
were not re-run in this pass: no pipeline file changed. The laptop has run none of this.
