# Demo runbook — what to say, what to click, what to do when something hangs

> **Laptop branch (2026-09-22): the pages this runbook describes were removed.** The demo with pages is now three
> applications started by `bash demo/start-demo.sh` — see [laptop-branch.md](laptop-branch.md) §5 for what to press.
> The six steps (`demo/run.sh`) and the scripted live sequence (`demo/live/run-live.sh`) still run exactly as described
> here, in the TERMINAL; wherever this text says \"the UI\", \"press N\" or names `live.html`, read the terminal output instead.

The demo is assembly over P1–P7: six steps, one runnable order, each step a script under `demo/steps/`
that calls the same CLIs the phase checks call and copies its artifacts into `~/ulpf-demo/`. The UI
(`demo/ui/`, served by `demo/serve-ui.py`) is a read-only layer over those files — polls them, renders
them, decides nothing. Every step runs and reads fine in a terminal without it. Nothing here needs the
network: the model server, the witness container and the UI are all local.

**Two demo documents, two jobs.** This one is about *presenting*. Machine requirements, the driver and
WSL findings, weights on ext4, the port collision, the model configuration and the measured model
figures are in [demo-machine-setup.md](demo-machine-setup.md) — prepare the machine with that first.
Measured here: the GTX 1650 laptop, WSL2 at its default 7.7 GB cap, driver 616.64, twice in a row on
2026-09-07 (§5).

## 1. Before the judges walk in (T-30 min)

The machine is prepared per [demo-machine-setup.md](demo-machine-setup.md). Open two WSL terminals in the
repository root and a browser window on the projector.

```bash
bash demo/llama-server.sh start          # the 4B on the GPU, 20/33 layers, 8k context; ~10 s (PTX cache warm)
bash demo/reset.sh                       # clean state, dev keys, vendor packs rebuilt from the corpus (~25 s)
bash demo/preflight.sh                   # 17 checks; must end "PRE-FLIGHT: all clear"
```

**The offload split is part of the script, on every machine.** Step 2's certificate set depends on how many
layers of the 4B sit on the GPU (measured on both machines, 2026-09-20; same weights by digest, same prompt,
same seed; each split is byte-stable across repeats and restarts):

| `--n-gpu-layers` | certificates in step 2 | after the logformat answer |
|---|---|---|
| **20** (the demo; `ULPF_LLAMA_NGL` default; pinned by pre-flight) | **pos_1** timestamp (`temporal_role`), **pos_3** client IP (`endpoint_orientation`), **pos_5** bytes counter (`request_response_role`) | all three resolved |
| 33 of 33 (what a 16 GB card would do if left to `auto`) | pos_1, pos_3, **pos_4** `TCP_MISS/200` (`action_outcome`) — no bytes-counter card | pos_1 and pos_3 resolved; **pos_4 stays `ambiguous`**: the logformat splits the slot into `cache_result`/`status_code`, neither among that certificate's survivors; the pack still promotes |

The narration in §2 is written against **20**. Pre-flight fails on any other value; a measurement run sets
`ULPF_DEMO_NGL_UNPINNED=1` and the check says so loudly. Step 2 at 20 layers: ~145 s on the GTX 1650 laptop,
~80 s on the RTX 5060 Ti desktop. Pre-flight also fails on a working copy with CRLF files
(`git ls-files --eol`): a Windows-side checkout once turned step 5's 98 emitted / 3 quarantined into 92 / 9.

Browser: `http://localhost:8765/`. Full screen (F11). It shows "step 2 has not run" — that is correct.
Keys on the UI: `1` certificate review, `2` tamper proof, `3` live flow, `4` discovery, `F` toggles
"follow the running step" (on by default: the UI switches to the screen of whatever step is running).

Close other GPU users (browser tabs with video, anything with hardware acceleration). The 4B leaves ~1 GB
of VRAM headroom; the 8B would not.

If `preflight.sh` fails a line, fix that line before anything else — §4 and §6 here, and the failure
table in [demo-machine-setup.md](demo-machine-setup.md) §7, say how.

## 2. The sequence (≈2 min 40 s of machine time; you talk over step 2)

Run it as one command in terminal 1 and narrate; or step by step with `bash demo/run.sh N N`.

```bash
bash demo/run.sh
```

| # | Step | Machine time | UI screen | What to say while it runs |
|---|---|---|---|---|
| 1 | Family discovery | < 1 s | `4` Discovery | "This is a mixed capture from four vendors — nobody has told the system what is in it. It clusters the lines by exactly what the router will later read: envelope, surface, declared anchors, arity. Ranked by volume: this is the order to onboard in. Note rank 11 — a PAN-OS line whose log type is outside the declared domain. Already flagged, no parser has run." |
| 2 | Live onboarding of Squid | **~140 s** (116 s is the model; the rest is under a second) | `1` Review (auto) | Six unseen Squid lines. "Structure is induced deterministically — ten slots, their token classes. The model is asked one thing: what do the slots mean. It runs locally, on this laptop's GPU, under a grammar: it can only answer with attributes from the pinned OCSF class table." While it thinks (2 min): the architecture — the model proposes, the machinery decides; invariant 4: a mandatory field never rests on a model proposal. When the certificates appear: walk the three cards — the timestamp (six temporal rivals), the client IP (source or destination?), the bytes counter (request or response length?). "For each, the library names the rivals and the evidence: type ties, held-out ties, structure weak. It does not pick. It asks **one** question, the cheapest that resolves everything: the device's logformat line." The answer goes in (the script types it). "Every field's provenance flips from *model proposal* to *device configuration*. Promoted, signed, and the Go runtime verifies the signature over the exact bytes before it parses the pack." |
| 3 | The unresolved case | < 1 s | `1` Review (scroll to the red panel) | "Slot two is the duration column. The model called it `http_status`. There is no evidence behind that — 812 type-compatible survivors, no library class naming a rival — so the system did not accept it, did not guess, kept the field pending, and the same one question covered it. After the answer it is `duration`, from the device configuration." The second box: the P3 fixture path — two candidates the library cannot separate, an *unresolved* certificate, no discriminator, no guess. "Two forms of the same rule: no evidence, no mapping." |
| 4 | Propagation | ~2 s | `1` Review (blue panel at the bottom) | "Same source, a second family with an eleventh column. Ten slots resolve from the first family's answers under the propagation key — no request. Zero operator responses and it promotes; the only open question is the new column, retained as a certificate." Then both families are merged into one signed source pack. |
| 5 | Mixed stream | ~10 s | `3` Live flow (auto) | "Four packs in one runtime — three vendors onboarded from recorded proposals, Squid from the pack you just watched. Syslog over TCP with RFC 6587 framing. Every byte goes to the evidence store *before* anything reads it. The DAG routes each frame to its family by surface facts — no parser is ever tried. 98 events, 3 quarantined: two drift signals (anchor values outside their domain) and one unowned family. ML feature tuples per event." Point at the gap-record box when it turns red: "Peer B stopped four seconds ago. That silence is now a record in the evidence log — same segment, same tree as the events." |
| 6 | Tamper and suppression | ~2 s | `2` Tamper (auto) | "The committer signs a checkpoint over the sealed segments; the verifier recomputes every root: OK. Two bundles are exported — an event, and that silence record — and the witness verifies both. The witness is a container with nothing but the verifier binary and the public key, no network." Then: "One byte flipped in the sealed segment. Verify again: FAIL, and it names the leaf — event, segment, byte range. The silence record's own root check fails with it: deleting the record of an absence is as detectable as deleting an event." |

The terminal prints the timings at the end; the UI header shows them per step.

**Drift and healing** (say, do not build): the two quarantined drift lines in step 5 are the detection
(P6: anchor value outside its declared domain → `routing_drift`, counted, bytes retained). Healing is the
same path as step 2 run by hand — **but not `bash demo/run.sh 2 2` after a full run**: step 2 onboards the
same `source_id` with the same propagation store, finds its own earlier resolution under the §4.4 key and
shows **zero certificates** (correct behaviour — the evidence is already held — and a flat demo). See
"Showing healing" below for what to run instead.

## 3. What the UI screens show

1. **Certificate review** (the demo): header KPIs (source, samples·slots, who proposed, certificates,
   requests·responses, state); the one request; the three certificate cards — field, slot, token class,
   sample values, ranked candidates with their origin (model / enumeration), the evidence line, the
   enumeration counts, and after the answer the winner with its new provenance; the operator's answer with
   the runtime's `verify-pack` line; two provenance tables (before / after); the red "no guess" panel
   (step 3); the blue propagation panel (step 4).
2. **Tamper proof**: the segment's bytes before and after (48-byte window, the flipped byte highlighted),
   the two verifier verdicts, the leaf named, the witness output for the event and for the gap record,
   the checkpoint id and mode, the gap listing after the tamper.
3. **Live flow**: frames sent / emitted / quarantined / drift / ML tuples / gap records / peers; routed
   per family with bars; quarantine reasons; the gap-record box (red when the silence lands).
4. **Discovery**: the ranked table with share bars, envelope, surface, anchor, a sample line; drift tagged.

## 4. When something hangs — per step

| Step | Symptom | Do this |
|---|---|---|
| any | UI stale or blank | It is only a viewer. Keep going in the terminal: every step prints its result. Restart it later: `python3 demo/serve-ui.py &` and reload. |
| any | a step fails | `bash demo/run.sh N N` re-runs that step alone; steps write into their own directory and can be re-run. Step 5 needs steps 2–4's packs; step 6 needs step 5's store. |
| pre-flight | `llama-server on 8081` FAIL | `bash demo/llama-server.sh start` (≈10 s; ≈3 min if the PTX cache volume was lost). If the GPU is gone: decide now to run step 2 with the fallback below. |
| pre-flight | `tcp port 6514` busy | `pkill -x ulpf-runtime` |
| pre-flight | `state reset` FAIL | `bash demo/reset.sh` |
| 2 | the model stalls or the server dies (no certificates after ~4 min) | `Ctrl-C`, then the one-flag fallback: `ULPF_DEMO_PROVIDER=fixture bash demo/run.sh 2 6`. Say: "this is the P3 path — the proposals are team-authored, the certificates, the request and the resolution are the same machinery." The UI shows *proposal by: fixture*. Steps 3–6 are unchanged. |
| 2 | slow but alive | Keep talking; the proposal takes ~116 s on this GPU (measured; the desktop did it in 14 s). The UI header says "running…". |
| 5 | runtime does not exit (frame count short) | `pkill -x ulpf-runtime`; the store is sealed on exit and step 6 still works on it. Re-run `bash demo/run.sh 5 5` if you want the clean count. |
| 5 | no gap record | peer B's silence needs the runtime alive > 4 s after B's last frame; at `ULPF_DEMO_RATE=12` the stream lasts ~8 s. Lower the rate: `ULPF_DEMO_RATE=8 bash demo/run.sh 5 5`. |
| 6 | witness (Docker) fails | the verdict is also computable in-process: `runtime/bin/ulpf-verify bundle --bundle ~/ulpf-demo/step6/bundle-event --trust keys/trust`. Say the container is the point but the maths is the same binary. |
| 6 | "DEVELOPMENT checkpoint" line worries a judge | Correct and honest: the segments here are SEALED, not kernel-IMMUTABLE, because the store runs unprivileged in the demo; the checkpoint says so in its signed `commit_mode`. The kernel-flag version is `bash scripts/p5-boundary-test.sh` (two containers, capability split) — run it in Q&A, ≈40 s. |
| Q&A | "does it work on an unseen format?" | (as written this shows zero certificates after a full run, and `demo/lib.sh` sets `SAMPLES` unconditionally — use the onboarding CLI directly with a fresh `--source-id` and `--session`, see "Showing healing") `bash demo/run.sh 2 2` with `SAMPLES=/path/to/their/lines` exported first (`export SAMPLES=...`): same path, live, ~2 min. If the structure is not positional (kv/csv) the induced structure still shows; certificates may differ. |

Recorded proposals for Squid: the P4/P6 recorded provider replays proposals *by field name* and the
induced Squid slots are unnamed, so it cannot replay the 4B's Squid recording without a small provider
change — raised, not built. The fallback is therefore the fixture path.

## 5. Measured — two consecutive runs on this laptop (`bash demo/twice.sh`, 2026-09-07)

`bash demo/twice.sh` = reset → pre-flight → all six steps, twice, no manual repair between. Both runs
passed on this laptop with the UI open; the 4B on the GPU (20/33 layers), WSL at 7.7 GB, ~6.3 GB free.

| step | run 1 | run 2 | what bounds it |
|---|---|---|---|
| 1 discovery | 0.4 s | 0.4 s | — |
| 2 live onboarding | 141.0 s | 148.9 s | the model's proposal (116–125 s of it); the rest under 1 s |
| 3 unresolved | 0.5 s | 0.6 s | — |
| 4 propagation | 1.9 s | 2.0 s | — |
| 5 mixed stream | 10.0 s | 7.7 s | the stream rate (12 lines/s) and the 4 s silence threshold |
| 6 tamper | 1.9 s | 1.8 s | two witness containers |
| total | 153 s | 161 s | |

Reset 22–24 s; pre-flight ≈15 s (the completion probe dominates). Fixture fallback for step 2: 2 s, and
steps 3–6 then behave identically (measured: 16.7 s for steps 2–6).

## 6. One-command reset and the pre-flight list

`bash demo/reset.sh` — stops runtime/senders/witness, wipes `~/ulpf-demo`, regenerates dev keys and
binaries, rebuilds the three vendor packs and the mixed capture from the corpus cache, ensures the witness
image. Keeps the model server and the UI server (`--all` stops them too). ≈25 s.

`bash demo/preflight.sh` checks, in this order: toolchain; binaries; dev keys + signed golden pack;
corpus cache; state reset present; weights on ext4; weights digest = manifest; Docker responsive; GPU
visible to Docker; llama-server on 8081 with `--n-gpu-layers 20 --ctx-size 8192` and the offload line;
a real completion from it; the witness image; port 6514 free; the UI serving index and state; memory
headroom. Exit 1 on any FAIL, and writes `~/ulpf-demo/preflight.json`.

Ports: 8081 model server (container), 8765 UI, 6514 the mixed stream's TCP listener. Port 8080 was
already taken on the demo laptop (a Jenkins service) — the demo never uses it.

## Step 7 — versioned correction (P8; optional, after the six)

`bash demo/run.sh 7 7` after a full run, ~4 s, terminal only (no UI screen). The retained certificate from
step 4 is resolved by the device's full logformat (`… %>st`); the family is promoted as pack 1.1; the runtime
re-derives the six affected events **from the evidence log** as `normalization@v2` with `derived_from: 1`;
v1's sha256 is shown identical before and after; both versions of one event are printed
(`http_request.length: "412"` → `traffic.bytes_in: 412`); a shell append and a runtime re-creation of v1 are
shown refused. Because step 6 left a byte flipped, step 7 **first shows the correction refused over altered
evidence**, restores the byte from step 6's record, re-verifies, then corrects — say: "a correction is
derived from the evidence, never from the previous interpretation, so it will not run over tampered
evidence." Needs a reset before it can run again: a version is never rewritten.

## Step 8 — drift healing (P8; optional, after the six)

`bash demo/run.sh 8 8` after a full run; ~45 s on the desktop at 20 layers (the model labels an ASA family live),
terminal only. **Healing is semi-automatic by design** — say it first: a system that re-learns on its own from
whatever arrives can be taught by an attacker, so the machine *detects* and a human *re-onboards* (architecture
§3.6). The automatic loop is not missing; it is refused.

1. **The monitor** (`learning/tools/drift.py`) reads step 5's quarantine and sorts it into what a human does next:
   `RE-ONBOARD CANDIDATE asa-message-id=302015` — an id *inside* the vendor's declared domain that no onboarded
   family owns; and two `DOMAIN VIOLATION`s (`999999`, `WEIRD`) — *outside* the declared domains, never candidates.
2. **The bytes come back out of the evidence store**, `raw_hash` checked: "they were kept when nothing could read
   them — that is what makes healing possible." The operator adds the device's own capture of that message id.
3. **The same path the audience watched in step 2**: spec, the model's labels, certificates, one evidence
   request, the vendor's field-order documentation, promotion, a signed pack. Point at `propagated slots 0`:
   302015 is a new L3 anchor value, so under the propagation key nothing pre-empts it — which is why this, and
   not re-running step 2, is the healing demo (step 2 again shows zero certificates: the store already holds
   that resolution, correctly).
4. **The same capture replayed before and after**: `quarantined 3 → 2`, `cisco-asa-fw-01/asa-302015: 1`, and the
   two domain violations are **still quarantined**. "It healed what the vendor documents and kept refusing what
   nobody documents."

Fallback (`ULPF_DEMO_PROVIDER=fixture`): replays the model's recorded labels for the *sibling* family 302013 —
the script says so on screen; say it too. Step 8 writes only under `step8/`; steps 5–7 are untouched and it can be
re-run without a reset.

## The connector picture (for the "is this middleware?" question)

Logs come **in** through connectors — file, stdin, syslog UDP, syslog TCP with RFC 6587 octet counting, HTTP
receive, a directory drop — are evidenced, routed, parsed and normalized, and go **out** through connectors:
`--forward syslog+tcp://siem:6514` (RFC 5424 in octet-counted frames), `--forward https://collector/ingest`
(NDJSON POST), `--forward stdout:` — repeatable, any mix. `bash scripts/p8-connectors-smoke.sh` shows all nine in
under a minute, plus the case that matters: **a SIEM that stops accepting costs no event and is not silent** —
ingestion completes, the interruption is an `egress_stalled` record *in the evidence log* (a Merkle leaf the
verifier prints), and `ulpf-runtime forward` delivers the rest from a persisted cursor when the SIEM returns.
What to say precisely, because it will be probed:
- **There is no file-tail ingress.** `--input` reads to EOF; a growing file is handled by dropping rotated files
  into `--pull-dir`.
- **Delivery is at-least-once.** HTTP has a real acknowledgement. Syslog over TCP has none (RFC 6587): after a
  connection failure the last batch is sent again, receivers deduplicate on `event_id`, and order is guaranteed
  within a connection, not across a reconnect. Syslog over UDP is refused as an egress: it cannot tell a sink
  that stopped accepting from one that is fine.
- **What is at rest:** the evidence log, *and* the normalized spool the cursor points into (the `--out` file /
  the lake). "Nothing stored but the evidence log" is **not** true as built; a pure pass-through would re-derive
  undelivered events from the evidence log on restart — the correction path shows that works — and is not built.
- **The evidence log is the third connector class** — ingress, evidence, egress — and its backend can be swapped;
  it cannot be switched off without giving up the guarantees it carries (raw-before-interpretation, gap leaves,
  corrections, the witness) and without a contract change: lineage requires `raw_hash`, segment and offset.

**Two stores, two protection levels — say which is which.** The **evidence log** (P5) is hash-chained,
Merkle-committed and signed, and kernel-immutable when the store runs privileged (the demo runs unprivileged:
the checkpoint says `sealed_only_dev`, signed). The **normalization lake** that step 7's corrections live in is
protected by its API (exclusive create, consecutive versions), read-only file modes and a sha256 manifest that
`lake verify` recomputes — **not kernel-immutable and not signed**. Root can rewrite a lake file; `lake verify`
then names the version. v1 being "byte-identical" is a checked hash, not a cryptographic commitment.

## The live sequence — generators in, a consumer out, and everything that can go wrong in between (three plain pages)

`bash demo/live/run-live.sh` after the usual set-up (reset, model server, UI). Parallel to the six steps; everything it
writes is under `~/ulpf-demo/live`. **About 3 min at 20 layers, about 2 min at 33** (two model calls; timings in
[live-demo-report.md](live-demo-report.md)). Acceptance: `bash demo/live/twice-live.sh`.

**Three pages, each doing one job** — plain, large type, black on white; **red means down or failing and nothing else is coloured**. Open all three before you start (key `5` in the six-step UI jumps to the first):

| page | what is on it | when you point at it |
|---|---|---|
| **System** — http://localhost:8765/live.html (the main screen) | two status blocks, **Generators** and **Consumer**, UP / DOWN in very large type (the whole block turns red when down); the list of phases A–I, each pending / running / done, advancing by itself; and **only what the running phase needs**: A the quarantined / parsed / guessed counters and the *onboard* button; B and F the certificate cards and one row per column (dropdowns when interactive); C two counters; D "ULPF is ahead of the database by N" and the outage records; E parse success and the ALERT; G–H the three numbers of the accounting; I the whitespace case. When a phase ends its detail goes away | all the time |
| **Generator** — http://localhost:8765/generator.html | the raw lines as they are produced, scrolling, each prefixed with the connector it leaves through (`syslog TCP` / `HTTP POST`). Nothing else. At the drift the lines visibly change shape (a number where `tcp` was, a zone at the end) | phase A ("this is what arrives: no labels anywhere") and phase E ("firmware 2.0") |
| **Database** — http://127.0.0.1:8790/ (served by the consumer app itself; loads once the sequence has started) | a row count and the latest events, newest first, typed. During the outage the page itself says DOWN and the rows stop; after the restart they resume and the count jumps — no chart, the stopping and resuming is the picture | phases C, D, G |

Nothing on these pages drives the sequence: `run-live.sh` advances the phases exactly as before. The only controls are the two that already existed — the *onboard* button and the dropdowns + *promote* — and they only exist in an interactive run.

```
flowtap sensor A --syslog/TCP (RFC 6587)--\                          /--HTTP POST (NDJSON)--> sink: SQLite + its own page
flowtap sensor B --HTTP POST---------------+--> ONE ULPF runtime ----+
                                                evidence log           \--stdout-------------> a file (any pipe)
```

One runtime process for the whole sequence: packs are **hot-loaded** (SIGHUP), never a restart, the generators never pause.

| phase | what happens | what you say |
|---|---|---|
| **A** quarantine first, then **wait** | two sensors nobody configured start sending over two different connectors. Every line is quarantined: bytes in the evidence log, **0 parsed, 0 guessed**; the monitor reports an unknown signature. Then **nothing happens** — until a human presses *onboard this source* (interactive) or the script records op-014's decision after 5 s | "This is the trust decision, and it is the only place a human is structurally required for a new source. ULPF does not learn from traffic because it arrived — that is how you poison a parser. It keeps the bytes and waits. *(press)* That was Tier 1: a named operator, recorded. From here it runs by itself." |
| **B** onboarding, automatic except for ambiguity (~60 s at 20 layers — talk) | samples come **out of the evidence log** (raw_hash checked); the model labels them; certificates fire — `endpoint_orientation` on both addresses, `temporal_role` on the timestamp; the system asks **one** question, and it is an answerable one: *operator assertion* (no vendor document exists for this source); see *the dropdown* below. Signed pack, **hot-loaded** | "The model recognised addresses, ports, a timestamp. It cannot know which address initiated — the sensor sees both directions — so the system refuses to choose and says exactly between which candidates. That is the only thing that stopped the automation." |
| **C** flowing | two ingress connectors, two egress connectors, all four visible as endpoints; typed OCSF in the consumer's database (`time` in epoch ms, integer ports and `action_id`, vendor `flowtap`) | "Different connectors in, different connectors out, one evidence log in the middle. Open the database page." |
| **D** egress outage (~12 s) | the consumer is **killed**. ULPF keeps ingesting (the *ULPF is ahead by* counter climbs, the sink box goes red); after 2 s the outage is an **`egress_stalled` record in the evidence log**; the consumer restarts; the backlog is delivered from the cursor; `egress_resumed`; on the database page: a flat stretch, then a spike, row count equal again | "The SIEM died. A forwarder would drop or block. ULPF does neither: ingestion carries on, the interruption of *delivery* is recorded in the same tamper-evident log as the events, and when the consumer is back it gets everything from where it stopped. Nothing dropped, nothing silent." |
| **E** drift → **self-healing with an alert** (~55 s at 20 layers — talk) | both sensors get "firmware 2.0" (protocol as a number, a new zone column). Parse success collapses, **the monitor fires**, lines quarantine. `autoheal.py` runs with **no human**: checks the drifted traffic comes from the onboarded source's channels and peers, pulls samples from the evidence log, **8 of 10 columns propagate** from what the operator already said (every mandatory one among them) → pack 1.1 promoted, hot-loaded, stream flowing again; an **ALERT** records what changed, what propagated, what the model proposed, what was promoted, the pack's sha256, the rollback command; the runtime records `pack_activated` with the same sha256 **in the evidence log**. The **2 columns nobody has evidence for are withheld** — carried unmapped — and the operator is asked | "A vendor pushes firmware to a fleet. Confirming a prompt on every middleware box is not an operation anybody can run. So for a source a human already onboarded, drift heals itself — **but only as far as evidence goes**. Eight columns are where they were: the operator's earlier answers still hold. Two are new: the system will not pick a meaning for them — that would be a guess — so it parses without them and asks. The alert is the audit trail, and the pack change is a leaf in the evidence log." |
| **F** the operator answers the two | two assertions → pack 1.2, hot-loaded; events now carry the zone and the protocol number | "Two answers, against ten mapping decisions by hand." |
| **G** backfill | everything quarantined while unreadable is replayed from the evidence log through the current pack into the same database; *also here:* the alert's **rollback, one command**, run for real and then re-applied (two more `pack_activated` leaves) | "Everything that arrived while nobody could read it was kept. Now it can be read." |
| **H** accounting | `generated == evidence records == database rows`; backfilled rows linked to the original evidence records by `raw_hash`; 5 `pack_activated`, 1 `egress_stalled`, 1 `egress_resumed` | "N lines in, N evidence records, N rows. Unknown source, dead consumer, changed format — zero lines lost, zero guessed." |
| **I** the third case (~12 s) | whitespace drift (one trailing space): `parse_success_drop` fires — routed, then refused — **and re-onboarding cannot fix it** ("12 of 12 samples fail to parse") | "Three kinds of drift. One heals itself on old evidence. One heals as far as evidence goes and asks. And this one no policy can heal: induction ignores the very whitespace the parser rejects. It always needs a human — and it is the only place this signal has ever fired for real. We show it because it is true." |

**The dropdown — what to say when the resolution is not a config line.** In step 2 the operator pastes Squid's
`logformat` line and one document resolves every field. **There is no such document for a format we invented**, and
the system now says so itself: its one request reads *"No vendor documentation or device configuration is known to
ULPF for this source … state what each pending field is"*. `ULPF_LIVE_INTERACTIVE=1`: the System page shows the *onboard this source*
button in phase A, then one dropdown per column in phase B (the certificate's candidates first). **This path was clicked through
in a browser on 2026-09-20** — the button, four assertions, *promote*, and *promote* again in phase F — and the run balanced. Choose `pos_4 → src_endpoint.ip`,
`pos_6 → dst_endpoint.ip`, `pos_1 → time`, `pos_2 → action_id`, watch the four blockers clear, press **promote** —
the rest is filled from the operator's notes. Scripted (default): the same answers, queued through the same file.
- Say: "I am not configuring a parser — I am **answering the question the system asked**, one field at a time; each
  answer is recorded with my operator id inside the signed pack as `operator_assertion`. Weaker than a vendor document,
  and labelled so. The type of each value is *not* mine to say: it comes from the OCSF schema — I said 'this is `time`',
  the schema says `time` is a timestamp, the column is an epoch, so it is coerced as one."
- **Do not claim "one question resolves many fields" here**: one answer, one field; nine assertions for nine columns
  is the same count as mapping by hand. That claim is step 2's. What this sequence shows instead is the *second*
  onboarding: **0 answers to get the stream back, 2 to complete it, against 10 by hand.**

What **not** to say: that healing is unconditional (it refuses traffic not bound to the onboarded source, promotes
nothing on a model proposal, and promotes nothing at all if a mandatory attribute did not resolve); that the binding
is authentication (it is channel + peer host; plain syslog/TCP and HTTP authenticate nobody); that the live model
raises a certificate on the two withheld columns (it usually proposes nothing for them — "nobody has said what this
column is"; the fixture fallback shows the zone as an `endpoint_orientation` certificate); that the backfill is a
product feature (it is the monitor's extraction plus an ordinary `run --input` into a second evidence store, linked by
`raw_hash`); that healing is instant (the model call dominates: ~55 s at 20 layers, although nothing the model says
is promoted).

| symptom | do |
|---|---|
| phase B fails "the certificates … did not fire" | the model did not label both addresses on this draw (its labels vary with the live sample lines). Re-run; or `ULPF_DEMO_PROVIDER=fixture bash demo/live/run-live.sh` — under a minute, says FALLBACK on screen, say it too |
| ports 6515 / 8516 / 8790 busy | `bash demo/reset.sh` stops the live apps too; or `ULPF_LIVE_TCP_PORT`, `ULPF_LIVE_HTTP_PORT`, `ULPF_LIVE_SINK` |
| interactive run sits in phase A, B or F | it is waiting for you — that is the point of phase A; the System page. In F just press *promote* (or choose `pos_3 → connection_info.protocol_num`, `pos_10 → src_endpoint.zone` first) |
| the Database page says DOWN in red after the sequence has finished | expected: the script stops the consumer at the end. The System page says STOPPED, not DOWN. Do not leave the Database page on the projector after phase H |
| skip the whitespace case | `ULPF_LIVE_SKIP_PAD=1` |

## If a judge asks for the coverage curve

Show `docs/metrics/coverage.svg` and say, in this order: (1) **the traffic mix is assumed** — fixtures carry no
volume distribution, so there are four declared mixes, least to most favourable, and no number is quoted from one
alone; (2) **coverage is measured** — a stream is built per mix and the runtime says what is usable as families are
added; (3) **cost is counted decisions, not minutes** — nobody was timed; (4) the result: **for the same coverage,
60 decisions with ULPF against 211 by hand; 8 evidence requests resolved 42 ambiguities**; nine families make
**24–49 % of corpus-derived traffic** usable depending on the assumed mix (100 % only on the demo's own stream);
(5) what it does **not** show: the predicted concave shape — falling marginal cost appears once, on our synthetic
Squid family; ASA's five families cost the same each, by the propagation key's design. Do not say "four vendors
covered": Elastic's own Squid capture routes at 15 % under the family learned from the trace's six lines
(P8 report §13.5) — that is a healing story, not a coverage claim.

## Showing healing — the reasoning behind step 8 (raised 2026-09-20; built the same day as step 8)

What a judge should see is *drift detected → the same onboarding path → the quarantined lines now flow*, and
the honest version of that uses only what exists:

1. **The detection is already on screen**: step 5's two `routing_drift` quarantines (and the one in-domain,
   unowned `%ASA-6-302015`, which is the better healing subject — it is a real family the corpus contains,
   not a synthetic violation).
2. **Heal by onboarding the unowned family, not by re-onboarding Squid.** `302015` is a new L3 anchor value,
   so the §4.4 key differs and propagation cannot pre-empt it: the session shows certificates and a request.
   By hand: `grep '%ASA-6-302015' corpus/cache/beats-cisco-asa/asa.log > /tmp/asa-302015.log`, then
   `python -m ulpf_learn onboard-spec --samples /tmp/asa-302015.log --spec drafts/sufficiency/asa-302013.json
   --vendor cisco-asa --family-id asa-302015 --unwrap-envelope --provider model …`, answer with
   `vendor_schema_field_order`, promote, `merge` into the ASA source pack. **Built as step 8**: the draft spec
   `drafts/sufficiency/asa-302015.json` (the 302013 draft with the message id changed — "Built outbound UDP" has
   the same shape; 35 of 35 corpus lines parse and its values are oracle-checked) and a `families:` row in
   `library/vendor-tables/cisco-asa.yaml`.
3. **Replay the quarantine**: re-run step 5 (`bash demo/run.sh 5 5`) with the healed pack — the `302015` line
   routes and emits, quarantined drops from 3 to 2, and the evidence log shows the original bytes were
   retained throughout. The two genuine domain violations stay quarantined, which is the point.

If Squid itself must be the subject (a changed `logformat`), the flat result is avoided only with a **fresh
`--source-id`** or a fresh propagation store — and saying why: propagation is keyed to the source, and a
source whose format changed is, for evidence purposes, a new structure under the same source, which is what
versioned corrections (invariant 8) exist to record.
