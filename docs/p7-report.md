# P7 report — transport, envelope and framing breadth; gap accounting

**Status: P7 built and its exit criteria met on the demo laptop (the only machine now); stopped for
verification before P8.** Nothing from P8 was built. Headline: everything arrives correctly framed however
it arrives — syslog over UDP/TCP (RFC 6587 octet counting with non-transparent fallback), HTTP receive, a
directory-drop collector, one multiline mechanism, JSON-array de-batching, recursive envelope unwrap with
the relay chain recorded and the CEF application envelope after it — and **absence became tamper-evident**:
a silenced peer, a sequence gap or a connection cut mid-frame produces a gap record that is an evidence-log
leaf like any event, committed under the same signed checkpoint, exported as the same bundle and verified by
the same witness. Invariant 7 held under load sized to this machine (§4). Reproduce with `scripts/p7-check.sh`
(no model, no corpus, Docker only for the witness step of the demo).

Two things happened before P7 in this session and are recorded here because they change what the reports
claim (§0): a fix pass (four code-level findings from the first run on the laptop) and the laptop
measurements P4 owed.

## 0. Before P7: the fix pass and the laptop measurements

**Fix pass** (commit `e2ccb8a`, `docs/README.md` "Fix pass 2026-09-07"). The runtime container's test stage
had not passed since P5: `runtime/Dockerfile` never copied `keys/trust`, so the signed golden pack could
not load inside the image and eight pack/pipeline tests failed there — only `p2-check.sh` runs that stage,
so P5 and P6 shipped with the in-container suite never having passed. Fixed (`COPY keys/trust`), re-run:
96 in-container passes against 111 on the host, the difference being exactly the corpus replay subtests
that skip without `corpus/cache`. Nothing else had drifted. `cryptography` was undeclared and the clean-clone
test could not have caught it because it reused the developer's venv; the dependency is declared and the
test now bootstraps a fresh venv and asserts it (passed on the laptop against the fix-pass commit).
`models.py fetch` treated a closed connection as completion; it now knows the expected length and resumes.
The top-level README said five contracts.

**Laptop measurements** (`docs/demo-laptop-runbook.md` §5–6, `spike/results/laptop-1650/`): the CPU floor and
the GPU figures for both candidate models are in the runbook and in the demo-shape recommendation delivered
with this report; the P4 report's "outstanding" status is closed by those files, and its model choice
remains provisional until the team reads the numbers.

## 1. Demonstrable outcome

| Plan P7 outcome | Result |
|---|---|
| **The syslog-forwarded CEF stream routes to the correct pack** | `TestForwardedCEFRoutesToItsPack`: a mixed stream — `<13>… fw01 cef: CEF:0\|Vendor\|Product\|1.0\|100\|Blocked\|5\|rt=… src=… dst=…`, a bare CEF line, a syslog-wrapped Squid line, a line with a CEF header *inside* its text, a CEF line with an unowned signature id — through one runtime with the Squid pack and a CEF pack (declared `cef`, kv surface, anchored on the CEF header's `signature_id`): 3 emitted (2 CEF, 1 Squid), 2 quarantined by routing with bytes retained, lineage `relay_chain: [rfc3164, cef]`, `envelope.signature_id: 100`, `time` from `rt`. Every event validates against normalized-event 1.3.0 |
| **A batched JSON file dropped in the pull directory explodes into individually hashed events** | `scripts/p7-demo.sh` §2 and `TestDebatchProducesIndependentlyHashedRecords`: one file, one received frame, 6 `batch_element` evidence records with 6 distinct `raw_hash` values and one shared `batch_hash`; `ulpf-runtime reconstruct` returns the file byte for byte; the file is renamed `.done` |
| **Silencing a source produces a signed gap record the verification tool displays** | `scripts/p7-demo.sh` §3: two UDP senders, one stops; after `--silence-after 400ms` the runtime appends `silence` (peer, last event, duration) as leaf 6 of the open segment; `ulpf-committer commit` signs `ckpt_000001` over it; `ulpf-verify gaps` prints it as *committed in ckpt_000001, root recomputed, signed by ulpf-committer-dev*; `ulpf-runtime export` bundles it; the witness container (`ulpf-verify bundle`, `--network none`, only the public key) says `VERIFY: OK` |
| Octet-counted capture over TCP | `scripts/p7-demo.sh` §1: three peers; counted frames, one LF-terminated line, a 300 KiB counted message (5 pieces against the 64 KiB cap), a peer that declares 200 bytes and disconnects after 40: 12 frames + 1 `connection_lost` gap record, 308,268 bytes reconstructed byte-exact |

| Exit criterion | Result |
|---|---|
| **Invariant 7 under load** — connection flood, oversized messages, idle connections hold the memory cap | §4: 3,000 connections against `MaxConns=64`: 64 served, 2,936 refused at accept, peak 64 active, heap +8 MiB (bound 32 MiB); a 32 MiB message against a 64 KiB cap: 512 (octet) / 513 (newline) bounded pieces, **0 MiB** measurable heap growth, pieces rebuild the message; 400 idle peers mid-frame: all closed at the idle timeout, all 400 partial frames retained low-confidence, 400 `OnClose` callbacks |
| Overflow emits truncation-flagged events | every piece of an over-cap message is `truncated` / `continuation`; the pipeline retains them as evidence and never parses them (`truncated_frames` in stats) |
| Malformed frames retained as evidence, never dropped | a bad RFC 6587 header falls back to non-transparent framing for that frame; a count the peer never fills is emitted truncated/low; a malformed JSON batch stays one whole frame; `frames == records` in every test |
| **Envelope-ambiguity test** — application text resembling a CEF header resolves by precedence, raw bytes retained | `TestEnvelopeAmbiguityResolvesByPrecedence` (frame) and the CEF pipeline test: transport before application, outer before inner, position decides — `CEF:0\|…` inside a payload is payload; a syslog-looking header inside a CEF extension is payload; the raw record holds every byte either way |
| Both suites green, container stage green | runtime 11 packages, 130+ tests incl. 9 P7 pipeline tests and 14 P7 frame/gap tests; learning suite 55; container test stage passes since the fix pass |

## 2. Deliverables

- `runtime/internal/frame`: `octet.go` (RFC 6587 octet counting, per-frame non-transparent fallback, bounded pieces, unfilled counts retained), `tcp.go` (listener: `MaxConns` semaphore with accept-and-close beyond it, per-read idle deadline, one 64 KiB read buffer + one frame per connection, partial frames emitted on any read error, `OnClose` for gap accounting, counters), `http.go` (POST bodies through a hard cap; over-cap answered 413 with what was retained; array bodies handed whole to de-batching; concurrency bound), `pull.go` (directory drop: name order, `.done` rename, batch files whole through a cap, multiline through the joiner), `multiline.go` (start pattern, line/byte bounds, no timer; terminators kept inside the event), `debatch.go` (element spans from the JSON decoder's input offsets, original bytes, batch hash/index/size, malformed kept whole), `chain.go` (`UnwrapChain`: two syslog levels then CEF; `UnwrapCEF` with escaped pipes), `Frame.Peer`, `Framing.Batch*`, `Newline.scanOne` (partials emitted on read errors).
- `runtime/internal/gap`: `Tracker` (per peer: sequence gap / reset, silence / silence end, connection lost), `Record` with canonical JSON, `SequenceID` (RFC 5424 `[meta sequenceId]`).
- `runtime/internal/evidence`: `Record.Peer`, `MethodGapRecord`, `AppendFrom`, `Reconstruct` skips gap records.
- `runtime/internal/pipeline`: de-batch → raw write → unwrap chain → continuity → `RouteChain` → parse → normalize; silence sweeper; `Pipeline.Lost`; stats `received_frames`, `batch_elements`, `relay_chains`, `truncated_frames`, `low_confidence_frames`, `gap_records`, `gap_kinds`, `peers`.
- `runtime/internal/route`: `RouteChain` (L1 over the chain: syslog anywhere / cef / raw), CEF header fields as `envelope_header` locators (`signature_id`, `device_vendor`, `device_product`, `name`).
- `runtime/internal/normalize`: lineage 1.3.0 (`relay_chain`, `batch`, innermost `envelope`).
- `runtime/internal/checkpoint/gaps.go` + `ulpf-verify gaps` (`--json`): every gap record with checkpoint, recomputed root and signature verdict, or `UNCOMMITTED`.
- `ulpf-runtime run`: `--listen tcp:` / `http:` (udp: unchanged), `--pull-dir` / `--pull-once`, `--max-conns`, `--idle-timeout`, `--max-body-bytes`, `--max-event-bytes`, `--multiline-start` / `--multiline-max-lines`, `--silence-after`, `--no-debatch`.
- Contracts: normalized-event **1.3.0** (`contracts/README.md`); Python `SUPPORTED_VERSIONS`; golden vectors regenerated (lineage `1.3.0`).
- Tests: `frame/{chain,octet,debatch,multiline,tcp,http_pull}_test.go`, `gap/gap_test.go`, `pipeline/p7_test.go` (relay chain, forwarded CEF, de-batch evidence, gap leaves committed → exported → witness-verified → tamper detected, sequence gap from SD, TCP partial → gap record).
- Scripts: `p7-check.sh` (suites, invariant 7 at machine-sized load, named P7 tests, demos), `p7-demo.sh`; README, docs index, plan v1.6 rows 38–45.
- `learning/tools/spike.py`: `--cuda-cache` (PTX JIT once per machine); offload recorded from the **last** `offloaded N/M` line (the first probe line said 33/33 on the laptop while the server ran 22/33 — a tool bug that would have mislabelled every laptop result).

## 3. Findings and decisions (raised, not absorbed — each is a plan row)

### 3.1 The innermost envelope is the device's (row 38); L1 under chains (row 39)

P6 handed P7 "the innermost payload and the outermost envelope". Built the other way for fields: on a
relayed message the outer RFC 5424 header is the relay's clock and host; the device's own header is inside
it and is what `envelope_field` mappings (ASA's `time`) and `envelope_header` anchors must read. So
`_lineage.envelope` is the innermost envelope and `relay_chain` records every level, outermost first. L1
matches the family's declaration against the whole chain: a syslog family needs a syslog envelope at any
level (either RFC form, as P6 decided), a `cef` family needs the CEF envelope, `raw` needs nothing; a
`cef` family does **not** accept a bare syslog line. The P6 tests are unchanged.

### 3.2 CEF is an application envelope, unwrapped after two syslog levels (row 40)

The plan's "two levels" are transport levels. The forwarded-CEF outcome needs a third notion: an
application header that is not a transport envelope. `UnwrapChain` removes up to two syslog envelopes,
then CEF only if it *starts* the innermost payload — precedence transport → application, outer → inner;
position decides, which is the envelope-ambiguity rule. The CEF header's seven fields ride in the
envelope record; the extension is the payload, parsed by a kv family. A third syslog level stays in the
payload, visible, never discarded (`TestUnwrapChainDepthBound`).

**Not built:** a CEF family in the learning plane. The pipeline test authors its pack in memory (the P6
pattern); onboarding CEF from samples — induction of the kv extension with the `cef-extension` decoder
for values containing spaces — is a pack-authoring/induction question for P8's re-onboarding path, and
the four corpus vendors emit no CEF. The demo claim is therefore "routes a forwarded CEF stream to its
pack", proven with a hand-built pack, not "onboards CEF".

### 3.3 Gap records are evidence records (rows 41–42) — the novelty claim, with the P5 rigour

The mechanism was unspecified. Decision: **no new structure.** A gap record is appended to the evidence
store exactly like an event — raw bytes = its canonical JSON (sorted keys, no whitespace, `gap-record
1.0.0`), framing method `gap_record`, peer recorded — in the segment that was open when it was detected,
next to the events around it. Consequences, all tested:

- it is a Merkle leaf (`H(0x00 ‖ "ulpf-leaf-v1" ‖ segment ‖ offset ‖ length ‖ raw_hash)`), so the P5
  committer commits it, the P5 checkpoint signs it, `ulpf-runtime export` bundles it and the P5 witness
  verifies it with only the public key (`TestGapRecordsAreCommittedLeaves`, demo §3);
- removing it from the index changes the segment root: `ulpf-verify evidence` fails the checkpoint and
  `ulpf-verify gaps` shows the remaining records with `root_verified: false` — absence of the absence record
  is as detectable as absence of an event;
- `Reconstruct` skips gap records, so the byte-exact reconstruction property (P2 kill-test) is unchanged: they
  annotate the stream, they are not bytes of it; the reconstruction still verifies each one's hash;
- `ulpf-verify gaps` lists every record with its checkpoint, recomputed root and signature verdict, and prints
  `UNCOMMITTED` for one the committer has not reached yet — never hidden.

What is detected, and what is not claimed: `sequence_gap` only from RFC 5424 `[meta sequenceId="N"]` (the
one standard sequence on the wire; none of the four corpus vendors carries it), with a backwards step
recorded as `sequence_reset` — a restart, not a loss; `silence` per peer after `--silence-after`, once,
closed by `silence_end` with the measured duration; `connection_lost` when a stream peer leaves a partial
frame (the partial frame itself is a low-confidence evidence record). A file source ends before any sweep,
so file replays never claim silence. There is no claim about messages a source never sent.

**Trace correction (standing obligation):** the worked trace has no gap stage; Stage 13's lineage is unaffected
because gap records are not normalized events. The trace should gain one sentence at the evidence-log
stage: "discontinuities are recorded as leaves of the same log" — recorded here, to be applied to the trace
by the team.

### 3.4 normalized-event 1.3.0 (row 43) — and a P5 contract omission

Additive: `relay_chain`, `batch`, `kind: cef` with header fields, `level`, `version` minimum 0 (CEF:0).
Found on the way: the P5 UDP listener has emitted `framing.method: udp_datagram` since P5 and the enum
never admitted it; no P5/P6 test validated listener output against the schema. Admitted now; the P7 pipeline
tests validate every emitted event against the contract (`validateEvents`), which P6's tests did for ML
records only. Python `SUPPORTED_VERSIONS` updated; golden `normalized/line1.json` regenerated at 1.3.0.

### 3.5 De-batching happens before the raw write (row 44)

Invariant 3 is per record: what must be durable before parsing is the element. Each element is its own
evidence record over its *original* bytes (spans from the JSON decoder's input offsets, no re-serialisation);
the array syntax lands in the first element's prefix, the inter-element prefixes and the last element's
suffix, together with the enclosing frame's own prefix/suffix, so the batch reconstructs byte for byte and
the stream property survives; every element carries the batch hash, index and size (`_lineage.batch`).
A malformed array, an empty one, trailing bytes, or more elements than the bound → one whole frame,
retained, quarantined by routing — never a partial explode.

### 3.6 TCP built in full; multiline without a timer (row 45)

The plan's fallback (newline-only TCP, octet counting on a canned capture) was not needed: RFC 6587 with
per-frame fallback, the per-connection cap, the idle deadline and partial-frame retention took a day and
are bounded by construction — resident memory ≤ `MaxConns × (64 KiB + MaxEventBytes)`. The multiline
mechanism deliberately has no "max wait" timer: a streaming source flushes its open event when its own idle
timeout closes the connection, and a file source flushes at EOF. The timer would have been the bug farm.

### 3.7 Two laptop-only findings that changed the tooling

- `spike.py` recorded the **first** `offloaded N/M layers` line; llama.cpp's `-fit` logs several probes and the
  last is what runs. On the laptop the first said 33/33 while 22/33 ran. Fixed to the last match; the
  P4 desktop results were full offload in every probe, so they are unaffected.
- Granite 8B-Q4 with `--n-gpu-layers auto` and the 16k default context on the 4 GB card was *slower than
  CPU* (prompt eval 6 tok/s, generation 1.8 tok/s): the fit heuristic offloaded everything and the driver
  paged VRAM through shared memory. `--ngl 20 --ctx 8192` is the measured configuration; the runbook's
  §4 says so.

## 4. Invariant 7 under load — sized to this machine, and said so

Machine: i5-10500H (12 threads), 16 GB, WSL2 cap 7.7 GB with ~6 GB available at test time. Sizes were
chosen to be large against the bounds asserted and small against the machine: a 3,000-connection flood
(ephemeral ports and fds well within limits), a 32 MiB single message against a 64 KiB cap, 400 idle
peers. The bounds asserted are the ones the design promises, independent of message size:

| Test | Load | Bound asserted | Measured |
|---|---|---|---|
| connection flood (`MaxConns` 64, newline framing, peers hold half a line) | 3,000 connections at once | heap growth ≤ 64 × (64 KiB + 64 KiB) + 24 MiB = 32 MiB; peak active ≤ 64 | accepted 64, refused 2,936, peak active 64, heap **+8 MiB**; at the idle timeout all 64 closed and their 64 partial lines retained |
| oversized message (octet-counted and newline, 64 KiB cap) | one 32 MiB message | heap growth ≤ 16 MiB whatever the size; every piece ≤ cap and flagged; pieces rebuild the message (streaming hash) | 512 / 513 pieces, **0 MiB** measurable growth, rebuilt |
| idle connections (octet framing, 200 ms idle) | 400 peers, each declaring 40 bytes and sending fewer | every connection closed at the timeout; every partial retained low-confidence; one `OnClose` each | 400 / 400 / 400 |

`scripts/p7-check.sh` runs these with `ULPF_LOAD_CONNS=3000 ULPF_LOAD_MB=32 ULPF_LOAD_IDLE=400` and prints the
machine's thread and memory figures next to them; the ordinary `go test` uses 600 / 4 / 50 so the suite
stays quick. The measurement is the Go heap in the test process with no piece retained (the first version of
the oversized test kept every piece and measured its own buffers — 64 MiB for a 32 MiB message — which is
why the assertion is a streaming hash now).

## 5. Raised, not absorbed — boundary items

1. **Innermost envelope for fields, L1 over the chain** (§3.1, rows 38–39): reverses the letter of the P6
   inheritance note; the P6 tests pass unchanged. Needs the boundary's yes.
2. **CEF as a third, application level** (§3.2, row 40): "two levels" read as two transport levels.
3. **Gap records as evidence records** (§3.3, rows 41–42): the design choice behind the novelty claim —
   same segment, same tree, same tools; `Reconstruct` skips them. Also the trace sentence.
4. **normalized-event 1.3.0** (§3.4, row 43) — and that `udp_datagram` had been emitted outside the contract
   since P5: the fix is in; the process gap (listener output never validated) is closed by `validateEvents`.
5. **De-batch before the raw write** (§3.5, row 44).
6. **No multiline timer; TCP not cut** (§3.6, row 45).
7. **Posture (carried from P5 §5a.4, unchanged):** the ingest path still runs root + `CAP_LINUX_IMMUTABLE`;
   gap records inherit whatever that posture is, no better and no worse.
8. **Sequence-gap scope:** only RFC 5424 `meta sequenceId`; vendor-specific counters (e.g. Cisco's
   `%ASA` sequence numbers when `logging timestamp`/`device-id` options add them) are a P8 or later
   locator question, raised so the demo does not over-claim.

## 6. What was tried and rejected

- **Reconstruct returning gap records' bytes in the stream** — breaks the byte-exact property and the
  kill-test; rejected in favour of skipping them (they remain verified leaves).
- **A separate gap log (its own segment kind or file)** — a second structure to commit, sign, export and
  verify; rejected: the whole point is that absence gets the machinery presence already has.
- **A multiline "max wait" timer inside the joiner** — needs a clock and a goroutine per source and
  interacts with the pipeline lock; rejected for flush-on-idle/close, which the transports already provide.
- **Passing the outermost envelope to routing (as P6 wrote)** — wrong for `envelope_field` mappings
  (relay clock); rejected for innermost-with-chain.
- **Aligning the newline framer's piece flags with the octet framer (first piece truncated, later pieces
  continuation)** — the P2 test pins the P2 convention (full pieces truncated, the partial tail
  continuation); the octet framer adopted the P2 convention instead.
- **Counting heap growth with the pieces retained in the test** — measured the test, not the framer.
- **Applying `.wslconfig` before the CPU floor** — deliberately not, so the floor reflects the machine as
  found (runbook §2).

## 7. What the next phase inherits

- **P8 drift monitors** now have `truncated_frames`, `low_confidence_frames`, `gap_records`/`gap_kinds`,
  `peers`, `relay_chains` and `batch_elements` in the run stats besides P6's `quarantine_reasons` and
  `drift_signals`; `silence` per peer is the "source suppressed" signal the P8 demo sequence names.
- **P8 demo step "a source suppressed, surfaced by verification"**: `scripts/p7-demo.sh` §3 is that step end
  to end (silence → leaf → signed checkpoint → `ulpf-verify gaps` → bundle → witness); P8 scripts it with the
  four vendor packs and the daily root on a second machine.
- **Re-onboarding path (P8)**: a CEF family from samples needs the kv extension induced with the
  `cef-extension` decoder; the runtime side is done.
- **Packaging (P8)**: the runtime image gains no dependency (invariant 2 re-verified in `p7-check.sh`); the
  new listeners are flags on the same binary.
- **Trace correction**: the gap-record sentence (§3.3).
- **Laptop**: the runbook carries the GPU figures and the `--ngl 20 --ctx 8192` rule for the 8B; the demo
  shape decision is the team's, made on those numbers.
