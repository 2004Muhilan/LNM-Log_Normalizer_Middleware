# Live demo sequence — generator in, consumer out, onboarding and drift in between

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
