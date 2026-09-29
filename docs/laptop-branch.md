# Branch `laptop` — what it is and what it adds

Branched 2026-09-21 from the desktop `main` (`4a97b32`), so it already contains everything built there: P8 (audit,
versioned corrections, coverage), **drift detection and self-healing** (`learning/tools/drift.py`, `autoheal.py`,
demo step 8, live phases E–F, `demo/live/parse-drop-check.sh`), and the **connectors** (ingress: file, stdin, syslog
UDP/TCP, HTTP, directory drop — TCP and HTTP together in one runtime; egress: syslog/TCP, HTTP POST, stdout, with a
persisted cursor and outages recorded in the evidence log). The last laptop-built commit was `1a4b849`; it ran on the
desktop only after a one-line loader fix that `main` already had. Additions on top:

## 1. Formats: JSON, XML, LEEF

| format | was | now |
|---|---|---|
| positional, CSV, key=value, regex templates; syslog RFC 3164 / 5424; CEF header | implemented | unchanged |
| **JSON** | the router recognised the surface; no op could parse it | `json` op — **parser-spec 1.2.0** |
| **XML** | named in the contract enums only | `xml` op — parser-spec 1.2.0; the router recognises a payload that opens a tag |
| **LEEF** 1.0 / 2.0 | named in the contract enums only | application envelope like CEF — **normalized-event 1.4.0** (`kind: leef`, `leef_delimiter`) |

Both contract bumps are additive and were approved as a reopening of the frozen op set. Rules of the new ops (the same
one as every op — every input byte is covered by exactly one span):

- `json`: `keys` maps dotted paths from the root object to cells. A string's span includes its quotes, its value is the
  unescaped text (`json-string`); numbers / true / false / null are their own bytes; an array is one verbatim value;
  objects are descended into. Undeclared leaves are opaque spans at `unknown.<path>`, or the parse is rejected.
  A declared key occurring twice fails.
- `xml`: `paths` maps element names joined by `/` (attributes `path@name`) to cells. Value = trimmed element text,
  CDATA verbatim; **entities are not decoded**; namespaces are part of the name; repeated siblings or mixed content on
  a declared path fail.
- LEEF: recognised only at the start of the payload, after the transport envelopes; the header goes into the lineage
  envelope (`device_vendor`, `device_product`, `device_version`, `signature_id` = event id); the attribute list is the
  payload, parsed by a `kv` family whose pair separator is TAB (1.0) or the declared delimiter (2.0). A syslog line of
  the form `host LEEF:1.0|…` / `host CEF:0|…` no longer loses the header to the tag rule (both stacks).
- Events keep declaring lineage `1.3.0`; only an event carrying a LEEF envelope declares `1.4.0`. No golden vector and
  no existing `parser_hash` changed (`build_vectors.py --check`: 26 files identical).

Verified: Go unit tests (`dsl/structured_test.go`, `frame/leef_test.go`), an end-to-end run with all three formats,
Squid and a malformed JSON line in one stream (`pipeline/formats_test.go`, every event schema-validated), and the
**cross-stack op matrix** — the Python reference executor and the Go engine agree span for span on every JSON and XML vector.

Limits, stated: no corpus fixture is JSON, XML or LEEF, so these formats are exercised on hand-written and generated lines
only; there is no Python CEF envelope twin (`--unwrap-envelope` strips syslog only). As of 2026-09-21 the learning plane could
execute and validate json/xml specs but not produce them — superseded by §4 (spec drafting, and a LEEF header twin).

## 2. Per-log view — inside the System page

For every log: the **raw bytes** exactly as received (re-hashed and compared with the recorded `raw_hash`), length,
segment and offset, ingest channel, peer, framing; the **format** the runtime detected (envelope, payload surface, arity,
token classes, routing signature); and the **parsed result** — pack, family, the normalized OCSF event and its lineage,
or the quarantine stage and reason. It was a standalone page (`demo/inspect-logs.py`, removed); it is now what the System
page shows when a log is selected (`GET /api/log?id=ev_…` on :8765 returns the same as JSON).

## 3. Laptop compatibility

Nothing here is machine-specific: no new dependency (Go stdlib, Python stdlib + what the venv already has), no GPU
use. Ports of the demo, all on 127.0.0.1: 8780 generator, 8765 system (and /lake), 8792 lake writer, 9200 OpenSearch, 5601 Dashboards, 6515 + 8516 ULPF ingress. Pre-flight still pins 20 GPU layers (the laptop's split) and the default
llama image is the upstream one the laptop uses; `ULPF_LLAMA_IMAGE=ulpf-llama` is a desktop-only override. A fresh
clone needs its git-ignored inputs: `corpus/cache`, `ocsf/cache`, `models/cache/Qwen3.5-4B-Q4_K_M.gguf`
(`docs/demo-machine-setup.md`). **Not run on the laptop** — built and gated on the desktop only.

## 4. Spec drafting — every generator format onboards live and heals (2026-09-22)

`learning/ulpf_learn/draft.py`: for **self-describing** formats — JSON, XML, key=value (LEEF's attribute list included) and
CSV — the parser spec is read off the samples, deterministically, with no model (the P4 boundary is unchanged: the model
labels fields, it never builds a spec). `Session.onboard` drafts when the samples are not whitespace tokens and induces as
before when they are. A drafted spec's cells are rebuilt from the plan, so an asserted field carries its coercion.

- **Unknown keys are rejected, deliberately.** JSON and XML have no L4 sketch in the router; a key nobody has seen would be
  carried opaque and *silently*. Rejected, a changed format fails its parse, the monitor sees routed-then-refused events,
  and the spec is drafted again. The cost: a rare optional key the samples did not contain quarantines its events until then.
- **Propagation by name.** For a family that names its fields (JSON, XML, key=value) the §4.4 key carries `name:<field>`
  instead of the slot index: a key inserted before the known ones must not inherit its neighbour's answer
  (`test_named_fields_propagate_by_name_not_by_position`). Positional and CSV families keep the index. Existing keys are unchanged.
- A Python twin of the LEEF header split (`draft.leef_split`) — the learning plane had none.
- **Found and fixed:** the Go pack loader's own semantic walk (`runtime/contracts/loader.go`) did not know the `json` and
  `xml` ops, so a *pack* with such a family was refused although the engine compiled the spec. The 1.2.0 work had only
  tested in-memory packs. Now covered by `TestStructuredOpsPassTheSemanticWalk` and by `test_draft.py` (verify-pack per format).

- **Router, a narrowing of the P6 L1 decision (approved 2026-09-22):** a `raw` family still imposes nothing on a relay's
  syslog header, but it no longer matches a payload that arrived inside an **application** envelope (CEF, LEEF) — that
  envelope names the format. Before, a bare key=value family and a LEEF family of the same pair count were two candidates
  for every LEEF line, which the router quarantined as ambiguous (found by `demo/apps-check.sh`; the ambiguity existed for
  CEF since P7 and had never been exercised). `TestRawFamilyDoesNotOwnWhatArrivedInAnApplicationEnvelope`; the rest of the
  Go suite and the 26 golden files did not move.

Limits: CSV needs nine or more cells (the router's own rule); repeated XML siblings and LEEF 2.0 with a declared delimiter
are not drafted; nothing here was exercised on a real corpus — no corpus fixture is JSON, XML or LEEF.

## 5. The demo — three applications, three pages, everything a button

```bash
bash demo/llama-server.sh start      # or ULPF_DEMO_PROVIDER=fixture: team-authored proposals, and the System page SAYS so
bash demo/start-demo.sh              # fresh state every time; `bash demo/start-demo.sh stop` stops all three and the runtime
```

| page | what it is | buttons |
|---|---|---|
| **1 Generator** :8780 (`demo/apps/generator.py`) | a log-producing application, outside ULPF | ingress connector: Syslog over TCP · HTTP POST · Disconnected — format: Positional · CSV · key=value · JSON · XML · LEEF — Start/stop — **Trigger format drift** ("firmware 2.0": the protocol becomes a number, a zone field appears) |
| **2 System** :8765 (`demo/apps/system.py`) | ULPF: one runtime, the monitor, onboarding and healing | policy **Auto-onboard ON/OFF**, **Answers: prepared sheet / ask me**; per alert **Roll back**; click an application → its incoming logs → click a log → raw / format / normalized |
| **3 Data lake** :8765/lake | the lake's own read-only view (DuckDB, fixed queries) | find one event by `event_id` |
| **4 SIEM** :5601 | OpenSearch Dashboards (the SIEM's own UI): the dashboard and Security Analytics findings | — |

*Replaced 2026-09-27: the SQLite consumer page ("3 Database", `demo/apps/database.py`) is removed; see §7.*

What happens, and on what authority:

- **Who is connected** is read off the evidence records (ingest channel + peer), never off the generator. Names come from
  `demo/apps/inventory.json` — the operator's declaration of which application sits behind which host.
- **A format nobody has onboarded** → every line quarantined, bytes kept → onboarding. *Auto-onboard ON*: it starts by itself,
  and the record says "by policy, set by op-014". *OFF*: nothing happens until the operator presses **Onboard this
  application's format** (the Tier 1 decision). The ambiguous fields are answered from op-014's **prepared sheet** (each one an
  operator assertion, marked prepared) or, with *ask me*, by the operator in dropdowns. The pack is verified by the Go engine
  and hot-loaded; the activation is an evidence-log record.
- **Switching format is not drift**: a format seen for the first time is a new family (nothing carries over between, say,
  JSON and XML — the propagation key includes the structure). A format already onboarded just parses: its pack is still loaded.
- **Drift** on an onboarded format of a bound source (same channel, same host) → **alert + automatic healing**, policy
  `autoheal-1.1`: fields carried over on the operator's earlier evidence, pack loaded, events flow again; what nobody has
  evidence for (here: the protocol, whose class changed, and the new zone) is **withheld and asked on the page — never taken from
  the sheet, never guessed**; the operator answers, a corrected pack (1.1) is loaded. Two detections: unknown signature
  (positional, CSV, key=value, LEEF) adds a family; routed-then-refused (JSON, XML) replaces it — 1.0 healed the first only.
  Going *back* from drift is, for JSON and XML, another drift (healed with no questions: every field is known by name).
  **Roll back** removes the alert's pack, restores what it replaced, and holds automatic healing for that format.
- **Database**: each egress connector is an independent at-least-once delivery with its own cursor in ULPF, and all three are
  always configured. Disconnect: the rows stop, ULPF keeps ingesting, the stall is an evidence-log record. Reconnect on the
  same connector: delivery resumes where it stopped. Switch connector: that connector delivers from where *it* stopped, so
  stored events arrive again and are ignored (counted) — `event_id` is the primary key.

Stated limits: lines quarantined while a format is being learned are **not backfilled** into the database by this demo (the
scripted live sequence does that, phase G); on the laptop one model call takes noticeably longer than on the desktop, and
every line sent meanwhile is quarantined — lower the rate (`ULPF_LIVE_RATE`, default 6/s) or pause the generator. Ingress
offers two connectors because the runtime serves TCP and HTTP together, not UDP. The console executes operator actions
itself (it is the operator's console, bound to 127.0.0.1); the binding authenticates nobody, as before.
`bash demo/apps-check.sh` walks all of this headless through the same HTTP APIs the buttons call.

## 7. Egress as middleware — N destinations, a bounded spool, a SIEM and a lake (2026-09-27)

ULPF is not built around a SIEM or a lake. A destination is a **transport plus an encoding**, and anything that speaks a
supported pair connects with no product-specific code. OCSF stays the internal format; every encoding is a projection of
it at the edge. Destinations are a list (`--forward` repeated; the demo reads `demo/apps/destinations.json`).

| encoding | transport | flag | tested against |
|---|---|---|---|
| OCSF JSON (NDJSON) | HTTP POST | `http(s)://…` | unit tests; the lake writer |
| OCSF JSON in RFC 5424 | syslog over TCP (RFC 6587) | `syslog+tcp://…` | unit tests (P8) |
| `_bulk` (OpenSearch / Elasticsearch) | HTTP | `bulk+http(s)://host:port[?index=…]` | **real OpenSearch 2.19.2** + the contract-checked stand-in |
| Splunk HEC envelope | HTTP | `hec+http(s)://…` (token in `$ULPF_HEC_TOKEN`) | a fake collector only — not a live Splunk |
| CEF (lossy projection) | syslog over TCP | `cef+tcp://…` | ULPF's own CEF parser reads it back; not a live CEF SIEM |
| OCSF JSON | stdout / a file | `stdout:` | unit tests |
| Parquet | HTTP → the lake writer (`adapters/lake`) | `http://…/ingest` | DuckDB; tests; the gate |

**One cursor per destination (confirmed, P8 already did this).** One forwarder per destination, each with its own
goroutine, backoff and cursor; a dead destination next to a live one delivers nothing and delays nothing (measured:
500 of 500 events to the live one in 314 ms while the other was down). Cursors are now keyed by the destination's NAME,
not its position in the list.

**The bounded spool** (`--spool DIR --spool-cap 256MiB --spool-segment 16MiB`; `egress/spool.go`). Before, the spool was
the `--out` file: one file, never trimmed. Now: 16 MiB segments named by their global offset; a segment is removed when
every destination has passed it (**the slowest destination governs retention**); above **80 % of the cap** a lagging
destination gets one `egress_lagging` evidence record ("nothing has been skipped yet"); above the cap the destinations
still inside the oldest segment are moved past it, each move an **`egress_skipped`** evidence record naming the
destination, the first and last `event_id`, the count and the byte range — that destination only; the raw bytes stay in
the evidence log, so the range is recoverable by re-deriving it (**no re-delivery tool is built**). The cap is a flag:
256 MiB is the demo value (events here are ~1.3 KB: ~206 000 events, ~9.5 h at 6/s); `--spool-cap` defaults to 1 GiB;
size production as rate × tolerated outage — one hour at 11 600 events/s is ~54 GB. `--out` is unchanged and optional
with `--spool`; the six steps, the goldens and the phase checks still use it.

**Decided 2026-09-27 — no exemption from the cap.** A destination that is still accepting but more than the cap behind (a
burst) is skipped exactly like a dead one: the cap is a hard bound on the disk, and protecting the disk protects the evidence
log, which matters more than a skipped range (which is recorded, never silent). Size the cap as **rate × tolerated
outage** (one hour at 11 600 events/s of ~1.3 KB ≈ 54 GB; the demo's 256 MiB holds ~9.5 h at 6 events/s).
**Follow-up, not built: a re-delivery tool** that re-derives a skipped range from the evidence log for one destination.

**Reversal, recorded: the run RESUMES.** "Every run creates a fresh spool" (P8) is reversed for `--spool`: a run resumes
the spool and every destination's cursor; `--spool-fresh` starts over. Cursors persist only after the destination
acknowledged; a destination without acknowledgement (syslog) gets its last batch again after a restart (at most a
redelivery, never a loss); a half-written last line is cut back on reopening and recorded as `spool_truncated`.

**Rejections (the approved classification).** Per-document 429/5xx inside a bulk answer: retried, those only.
Whole-request 429/5xx: retried with backoff (a stall). 413: split; a single event still too large is rejected.
Document-level mapping/parse errors: **`egress_rejected`** evidence record (event, destination, error type, reason), then
passed over — shown loudly on the System page, because it almost always means the index template is wrong. A whole-request
400/401/403 is never a rejection (it is our encoding or our credentials): a stall. The bulk action is `index`, not
`create`: a redelivery overwrites (a new `_version`), it does not duplicate and does not fail with 409.

**The SIEM: OpenSearch 2.19.2 + Dashboards** (`demo/siem/`, Apache 2.0, offline, **security plugin DISABLED to save
memory — demo only, not hardening**). One index per OCSF class (`ulpf-ocsf-<class_uid>`), an index template (IPs `ip`,
times `date`, strings keyword, `unmapped` as `flat_object`), `_id = event_id`. Dashboard "ULPF — normalized events":
events by class, denied connections over time, top source addresses, quarantine count (the console posts its counts to
`ulpf-metrics`). Security Analytics: its prebuilt OCSF detections cover CloudTrail, Route 53 and VPC Flow only, so a
custom log type `ulpf_ocsf_network`, two rules — a known-bad address, and a deny spike (an aggregation rule: more than 3
denies from one source per minute) — and a detector over `ulpf-ocsf-4001` every minute. **Verified against our indices:**
findings within a minute, naming documents by `_id` = `event_id`. The Generator's **Attack burst** (12 denied flows from
198.18.7.7) makes the spike rule demonstrable; a per-event "denied" rule was dropped (a finding every second).

**The contract check — the stand-in cannot drift** (`demo/siem/contract-check.py --limits`, outside the gate, run before
any demo). The gate uses `demo/siem/fake_bulk.py`; the check sends the same requests to it and to real OpenSearch and
compares what matters (the errors flag; per document status, result, `_version`, error type; the count afterwards): new
documents, redelivery (updated, v2), an invalid IP rejected alone, the coercions the mapping allows, a type conflict,
`create` → 409; with `--limits`, a throwaway container with a 4 KB request limit and a one-slot write queue: a real 413,
and real 429s both as whole requests and per document. It caught a real drift on its first run: OpenSearch names a
throttled write `rejected_execution_exception`, the stand-in said `es_rejected_execution_exception` (Elasticsearch's
name) — fixed; ULPF classifies by status, so behaviour did not change.

**The lake: OCSF Parquet in Amazon Security Lake's layout convention** (`adapters/lake/lakewriter.py`, a destination
adapter that ships with ULPF; DuckDB writes and reads it). `ext/ulpf_<class>/region=local/accountId=000000000000/
eventDay=YYYYMMDD/part-<spool>-<first>-<last>.parquet` — this FOLLOWS the layout convention; it is **not tested against
Security Lake**. Local disk only (no object storage: MinIO is archived; SeaweedFS would be the choice, and DuckDB's
`httpfs` would need pre-baking). Every file's schema comes from the **pinned OCSF class table**, never inferred (tested:
two batches that inference types differently get one identical schema); lineage columns first (`event_id`, `raw_hash`,
`segment_id`, `offset`, `length`, the pack), the whole lineage as JSON too; a class with no pinned table is kept whole as
JSON. Exactly once through redelivery and crashes: ULPF sends each batch's spool range; the writer keeps a durable
high-water mark per spool, stages with fsync before acknowledging, rotates by size or age, writes a hidden temporary file
and renames it (a crash never shows a half-written file), names files by their spool range (a repeated flush replaces
the same file). **Decided 2026-09-27 — the full schema stays**; trimming it to what the loaded packs emit would reopen the consistency problem. **Measured cost of the fixed schema:** ~3 600 schema elements (network activity), ~280 KB of footer, ~390
KB fixed per file — heavy for the demo's 10-second rotation, a few percent for production-sized files.
DuckDB's own UI does **not** work offline (measured: it serves its page by fetching assets from ui.duckdb.org; with no
network it answers HTTP 500), so the System console has a read-only lake page with fixed queries (`/lake`).

**The traceability round trip** (`demo/apps/trace.py`; the System page's **Prove it**): a Security Analytics finding →
its `event_id` → the SIEM document's lineage → the raw bytes from the evidence log, re-hashed → a signed Merkle checkpoint
(committer in the development seam `ULPF_COMMIT_SEALED=1`, said so) → `ulpf-runtime export` → `ulpf-verify bundle`:
VERIFY OK → the same event in the lake, same `raw_hash`. Requirements (a) and (d) end to end; where Proof of Derivation
plugs in later.

**The outage, redone.** *Stop the SIEM* (`docker stop`): the SIEM's block turns red, its *ahead by* climbs (measured 103
and 115 in two runs), the lake's stays at 0; *Start the SIEM again*: the backlog arrives from its cursor, the counter falls
to 0, and the SIEM's document count equals the events ULPF parsed — no loss, no duplicate (measured: 695 = 695 = 695 lake
rows). The scripted live sequence does the same with the stand-in (killed, restarted with its state).

**Memory** (desktop, measured under load): OpenSearch 1.33 GiB (512 MB heap), Dashboards 184 MiB, model server at 20 layers
1.73 GiB, lake writer 128 MiB, console 125 MiB, runtime 19 MiB. **Laptop estimate** against its 10 GB WSL cap: the model
server larger there (~2–3 GB with the CPU repack of the layers not on the GPU), so ~5–6.5 GB at peak with Docker's own
overhead — **expected to fit, with ~3.5 GB to spare; not measured on the laptop.** Do not run `contract-check.py --limits`
during the demo (it starts a second OpenSearch). Fallbacks: `ULPF_SIEM_DASHBOARDS=0` (OpenSearch only: a screen is lost,
the System page still shows the SIEM's status and counts), `ULPF_SIEM=fake` (no containers). Disk: the two images are
~4.7 GB.

## 8. The gate (desktop, 2026-09-27, after the last change — egress as middleware included)

`p1-check` … `p8-check` pass (34 / 47 / 39 / 47 / 102 / 84 / 209 s; zero skipped tests, 26 golden files byte-identical,
coverage figures regenerate byte for byte); the Go suite (13 packages) and 99 Python tests pass.
`demo/siem/contract-check.py --limits`: PASS — the stand-in answers like OpenSearch 2.19.2 on every scenario, including a
real 413 and real 429s (whole-request and per-document).

| | six steps, run 1 / run 2 | scripted live sequence, run 1 / run 2 | same facts shown | demo check, model (key=value, LEEF, JSON), real SIEM |
|---|---|---|---|---|
| 20 layers (the laptop's split, pinned) | 86.4 s / 86.2 s | 196 s / 157 s | yes / yes | PASS, 454 s |
| 33 of 33 layers (desktop only) | 45.2 s / 47.8 s | 141 s / 141 s | yes / yes | PASS, 369 s |

Demo check with fixture proposals, all six formats in one session, real OpenSearch: PASS — outage: SIEM 94 behind, lake 0;
a Security Analytics finding (known-bad address) proven back to the evidence in six steps; 692 parsed = 692 SIEM documents
= 692 lake rows (692 distinct event ids), 0 rejected. In every live run the outage showed the SIEM's cursor frozen (e.g.
79 → 79) while the lake's advanced (87 → 124).

Found on the way, fixed, stated:
- `rangeIDs` counted a skipped range as empty (the batch read ran past the range): caught by the skip test.
- With `--spool`, `--out` was no longer flushed per event, so its live readers saw half lines: restored.
- The lake writer's JSON path for a class without a pinned table had an operator-precedence bug: caught by its test.
- The stand-in answered `es_rejected_execution_exception` (Elasticsearch's name) where OpenSearch says
  `rejected_execution_exception`: caught by the contract check on its first run.
- Test harness only: the cap test fed its input all at once, so under load a HEALTHY destination was momentarily past the
  96 KiB test cap and was (correctly, by the approved policy) skipped once — the input is now paced like a live stream;
  the demo check pressed *drift* before one event of the new pack had been parsed, so the source binding (correctly)
  refused to heal — it now waits for events to flow first; the live sequence's outage assertion used arbitrary thresholds
  (SIEM ≥ 40 behind, lake +40) that missed by one or three events — it now asserts the exact invariant (the SIEM's cursor
  does not move, the lake's advances and stays current).
- Not fixed, observed once: one gate run's P5 witness test saw an empty bind-mounted bundle directory (Docker Desktop
  mounting a `/tmp` path); the same test passed standalone at once and in the next two gate runs.
- Observed once, in the 33-layer configuration (desktop only): the model gave no label for column 6 in one live run, so the
  certificate the scripted demo is built around did not form (phase B stopped, loudly). The model sees real-timestamped
  sample lines, which differ every run; the positional onboarding path is unchanged by this work. It passed in the next
  two 33-layer runs. Not seen at the laptop's 20-layer split.

Not run on the laptop.

## 9. One-command gate, 12.7 minutes (2026-09-27)

`bash scripts/gate.sh` (the laptop: `--laptop`, no 33-layer lane). It runs everything the gate above ran — the phase
checks, the contract check, the demo check with the real SIEM, and the acceptance criterion (six steps twice and the live
sequence twice, on 20 and 33 layers) — in **12.7 minutes** (759 s, all PASS), where the same work sequentially took ~45
minutes (44.5 measured on the last full run) and over an hour with reruns. No test was removed.

Where the time went, measured from the last sequential gate: phase checks 9.4 min, SIEM + contract 0.7, fixture demo check
3.8, then per configuration six steps twice (4.1 / 2.9), live sequence twice (5.9 / 3.6) and a demo check with the model
(7.6 / 6.2). Three causes, three fixes:
- **The phase checks are cumulative**: every one re-ran the full Go suite (≈9 times per gate), the Python suite (≈8), the
  golden-vector check and the key bootstrap, four of them the invariant-2 image build; the witness test ran three times,
  the boundary test and the four-vendor build twice (once to show the output, once for the exit status). Now the gate runs
  each ONCE (the Go suite with `-v` for the no-silent-skip scan, the Python suite with `-rs`), and `ULPF_GATE_SHARED=1`
  makes each phase check run only its unique part. Run on their own, the phase checks are unchanged (cumulative), except
  that the double runs are gone for good.
- **Everything was sequential.** Now four lanes run at once: A (suites + phase checks), D (SIEM, contract, fixture demo
  check), G20 and G33 (six steps twice, live sequence twice), each model lane with its own state directory, ports, model
  server and witness container (`ULPF_DEMO_STATE`, `ULPF_*_PORT`, `ULPF_LLAMA_NAME`, `ULPF_WITNESS_NAME`). The two model
  servers share the desktop GPU.
- **The model-driven demo checks (13.8 min) duplicated what the model lanes test**; the gate runs the demo check once, with
  fixture proposals (the destinations, not the model, are what it tests). `ULPF_DEMO_PROVIDER=model bash demo/apps-check.sh`
  stays as a pre-demo check.

Isolation needed for lanes, fixed on the way: `reset.sh` killed EVERY `ulpf-runtime`/`ulpf-committer` on the machine and
re-ran the key bootstrap (which re-signs the golden pack) — now it kills only its own state directory's processes and the
gate bootstraps once; every `pkill` in the demo scripts is scoped to its state directory (the first parallel run failed
because the demo check's stop killed the other lanes' lake writers).

| lane | what | time |
|---|---|---|
| shared | keys, binaries, golden signature, gofmt, vet, golden vectors | 8 s |
| A | Go suite 17 s (0 skipped), Python 18 s (99), invariant 2 10 s, p1 2, p2 12, p3 14, p4 12, p5 63, p6 32, p8 (incl. p7, coverage) 199 | 379 s |
| D | contract check 56 s; demo check, six formats, real SIEM 288 s | 344 s |
| G20 | six steps twice 120.8 / 110.5 s (same facts); live sequence twice 248 / 184 s (same facts) | 751 s |
| G33 | six steps twice 68.6 / 54.0 s (same facts); live sequence twice 214 / 175 s (same facts) | 612 s |

The critical path is G20: its runs are 25–40 % slower than alone (CPU and GPU contention). **The laptop variant
(`--laptop`) is not measured**: one small GPU, 10 GB — expect it to be dominated by the 20-layer lane at laptop speed.

## 10. Unified visibility (f) and the throughput figures (g) (2026-09-27)

**Every source in one SIEM.** The System console replays the four-vendor mixed capture (Cisco ASA, Palo Alto PAN-OS,
FortiGate, Squid behind a syslog relay — built by `demo/reset.sh` from the corpus, never committed) from `127.0.0.2`,
with the three vendor packs loaded next to the golden pack; it is a second application in the list ("vendor relay"),
declared not learnable in `inventory.json`, so its unknown lines are quarantined and counted, never onboarded or healed.
Button: *Four-vendor relay ON/OFF*. The dashboard now splits every panel by vendor; its time axis is ULPF's receive time
(`_lineage.ingest_time`), because the recorded capture keeps its 2018–2020 event times. **Cross-vendor saved searches:**
*Denied connections from one source address — any device* (`action_id:2 and src_endpoint.ip:"…"`) and *Denied connections
from the internal network (10.0.0.0/8) — every device* (on the dashboard). One query, OCSF's field names, every device.
Stated: the capture has no source address seen by two vendors (the fixtures come from different Elastic test sets), so the
single-address search shows one device at a time; the subnet search shows Fortinet, Squid and the generator together.
PAN-OS has no denied connection in the capture. Checked by `demo/apps-check.sh`: all five sources in the SIEM, the subnet
query returns three devices, both saved searches exist, and the index pattern carries the time field (found by looking at
the dashboard: Dashboards drops subfields of `_lineage` from its field list, so the denies panel failed until setup added
them).

**Throughput and integration efficiency: `docs/throughput.md`** (harness `scripts/bench/throughput.py`, measuring tool
`runtime/cmd/ulpf-bench`, raw results `docs/metrics/throughput.json`). In one line: parsing and normalization do ~10,600
events/s per process and scale across processes (3.35 billion a day extrapolated on 4 cores, measured); **with the evidence
log as built — two fsyncs per event — one stream does 215 events/s on this disk (18.6 million a day)**, and end to end is
bounded by the same (143/s). Raised, not built: group commit for the evidence log (it changes invariant 3's wording).

Gate after these changes: `bash scripts/gate.sh` PASS in 796 s (lanes A 436 s, D 364 s, G20 787 s, G33 605 s); lane D
re-run after the dashboard field fix: PASS (310 s).

## 11. Group commit, a shared attacker across two devices, the evidence archive design (2026-09-27)

**Group commit (decision 1, approved).** Invariant 3 now reads: *no event is parsed or delivered until the batch containing its
raw bytes is durable on disk.*
- **The evidence store:** `AppendBuffered` stages a frame (hash, record and offset are final) and `Sync` writes the batch and
  fsyncs the segment and the index. `Append`/`AppendFrom` stay durable before they return; gap records and annotations use
  them.
- **The pipeline:** commits at `--commit-events` (256) or `--commit-wait` (10 ms, wall clock), whichever comes first, and only
  then interprets the batch, in order.
- **Committed first:** a reload, a closed connection and a silence sweep, so a `pack_activated` leaf still precedes every event
  interpreted under it.
- **HTTP receive:** answers 202 only after the commit (503 if it fails).
- **Visible change:** a sequence-gap record now follows the batch of the message that revealed it, not the message itself
  (tested both ways).
- **One test's hidden pacing:** the spool-cap test's "healthy" destination only kept up because an fsync per event paced the
  stream; the test now paces at 4 ms.
- **Wording changed in:** the plan (§2 row 3, §11 row 65), the store and pipeline package comments, the CLI help, the harness,
  and dated notes in the P2 and P8 reports.
- **Tests:**
  - the kill-test, rewritten: batches of 2, death after the batch holding frame 3; 4 frames are recovered byte-exact and the
    output holds only the first batch;
  - a property test: nothing is written downstream while a frame is staged;
  - the time cap: a lone frame is committed within the wait;
  - HTTP: 202 comes after the commit, and a failed commit answers 503.

**Re-measured (`docs/throughput.md`, three runs each, medians):**

| | before (fsync per event) | after (group commit) |
|---|---|---|
| parse | 10,431/s | unchanged |
| with the evidence log | 195/s | **5,232/s** (27×; 0.45 billion a day per stream, extrapolated) |
| end to end, into OpenSearch and the lake | 143/s | **1,507/s**, now set by the lake writer (1,670/s alone) |

- The evidence path is now CPU-bound: 3,978 events per CPU-second, so 2.9 cores on average for one billion a day.
- The virtual disks did not grow.

**One attacker, two devices (decision 4).** Every 15th line from the generator is a denied flow from 10.10.10.10, which the
FortiGate in the recorded capture also denies. `Flowtap.line(src=…)` keeps the random sequence unchanged.
- The saved search *Denied connections from 10.10.10.10 — every device that logged it* returns Fortinet and flowtap.
- `demo/apps-check.sh` requires both.

**Evidence archive (decisions 2 and 3): designed, not built.** See `docs/evidence-archive-design.md`. Four points are raised
there for a decision before building:
1. segment ids are per directory, so a `store_id` in `_lineage` is needed, which is a contract change;
2. the runtime, which holds the capability that sets the immutable flag, is also the one to clear it and delete;
3. the committer becomes a continuously running service, and ships;
4. UDP cannot be refused at the cap.


Gate after these changes: `bash scripts/gate.sh` PASS in 723 s (lanes A 439 s — Go suite 108 tests, 0 skipped; D 377 s — the
one-source query returns Fortinet and flowtap; G20 713 s and G33 621 s — same facts both runs). The WSL2 and Docker virtual
disks did not grow across the measurement and the gate (75.884 GB and 84.65 GB before and after).

## 12. The evidence archive — ULPF keeps only a short local buffer (2026-09-27, built)

The sponsor answered yes to all four points of `docs/evidence-archive-design.md` §6 and it is built. §0 of that document
lists the code, the tests and the few places the build differs from the design text.

**The four answers, as built:**
1. **`_lineage.store_id`**, normalized-event **1.5.0**:
   - the golden vector is regenerated;
   - the lake has a `store_id` column, and the SIEM template maps it as a keyword.
2. **The runtime deletes; the committer ships.** The store clears the kernel flag it set, only under the deletion conditions,
   which keeps the P5 separation.
3. **The committer is an always-running service** (`--every 5s --archive`). It reads evidence, writes its commit tree and the
   archive, and never modifies or deletes evidence.
4. **UDP at the cap is counted, discarded and recorded** in the `evidence_buffer_full` / `_resumed` records, never parsed or
   delivered. Strict deployments relay UDP through TCP, as documented.

**What the runtime enforces:**
- **An archive is required.** `run` refuses to start without `--evidence-archive` (exit 2); `--dev-no-evidence-archive`
  overrides it with a banner, a line before the stats, and `"evidence_archive": "DISABLED …"` in the stats.
- **Shipping:** byte-exact, read back and checked against the seal record; the receipt is written last. A restart resumes, and
  the archive is never overwritten.
- **Deletion needs all five conditions:**
  - a signed checkpoint covers the segment;
  - the receipt matches the seal record, and the archived bytes still hash to it when re-read;
  - the covering checkpoints are shipped, byte-identical;
  - the grace period has passed;
  - no proof is reading the segment.

  Never by age alone.
- **Checkpoints stay local**, for the chain.
- **The cap:** a high-water record, then at the cap intake stops and a committed `evidence_buffer_full` record is written;
  nothing older is deleted.
  - TCP and file input wait.
  - HTTP gets 503 with `Retry-After`.
  - UDP datagrams are counted and discarded.
- **One lookup path** (`evidence.Locator`: local, else the archive, with the local catalogue of deleted segments) serves:
  - "Prove it", export and reconstruct;
  - renormalize;
  - `ulpf-verify evidence|gaps|locate`.
- **Protection, recorded in the P5 report:** the kernel lock covers only the local buffer. In the archive, tampering is
  detected (the verifier names the exact event); preventing it needs write-once storage.

**The demo:**
- `start-demo.sh` starts the committer beside the console; the archive is `$APP/evidence-archive`, a folder beside the lake.
  The runtime runs with a grace period of 60 s and a buffer cap of 64 MiB.
- **The System page** has a new block: segments shipped, segments pending (open, or not yet committed or shipped), local
  buffer usage against the cap, segments deleted locally, and whether the committer is running.
- **Pre-flight** checks:
  - the archive location is writable;
  - the committer's key is present and trusted;
  - the runtime refuses to start without an archive.
- **`apps-check`**:
  - waits for shipped segments to leave the buffer;
  - exports an event whose segment was deleted locally from the archive, and verifies its bundle;
  - runs **Prove it** on the oldest SIEM document whose segment is gone, and requires it to read the archive;
  - prints the local disk used.
- **Every other test and demo sequence runs with `--dev-no-evidence-archive`:** the gate's scripts, `twice.sh`, the live
  sequence, the throughput harness and the golden vectors.

**Local evidence disk in the demo, before and after shipping** (a shortened apps-check: two formats, real SIEM, ~5 minutes):

| | bytes | segments |
|---|---|---|
| evidence written (all local if nothing were shipped) | 1,153,535 | 52 |
| local at the end of the check (inside the 60 s grace period) | 579,052 | 26 |
| local one grace period after the stream stopped | **2,829** (the open segment) | 1 |
| kept locally for good: catalogue (event id → deleted segment), deletion log, `store.json` | ~60 KB | — |
| in the archive | 1,150,706 of segment files, plus the commit tree mirror | 51 shipped |

While the stream runs, the local buffer holds about one grace period of evidence plus the segments not yet committed. At
the demo's rate (~14 events/s) that is a few hundred KB, 0.5 % of the 64 MiB cap.

**In the full gate's demo check** (six formats, ~6 minutes, grace 60 s):
- 3,108,042 bytes of evidence were written in 139 segments.
- At the end, 558,572 bytes (18 %) were local in 26 segments; the rest was shipped (136 segments) and deleted locally (108).
- 129 KB of catalogue and deletion log is kept locally.

**Found by the gate and fixed** (the first two gate runs failed; the third passed):
1. **Step 5 of the demo sequence started its sender after a fixed 0.7 s.** Under the gate's parallel load the runtime was not
   listening yet, so the sender was refused and the runtime waited forever.
   - `demo/steps/5-mixed.sh` now waits for the runtime to report it is listening.
   - So does `scripts/p7-demo.sh`, which had the same fixed sleep for TCP and UDP.
2. **The System console's count of parsed events could fall short by a few**, while the SIEM, the lake and `out.jsonl` agreed
   with each other.
   - The console reads the index files, then the outcomes. An outcome read before its index line was dropped.
   - Group commit writes a batch's index lines and outcomes between the two reads, which widened the window.
   - Such lines are now kept and matched on the next tick.
3. **An index file could be deleted locally before the console had read all of it** (the console lagging by more than the
   grace period). The console now finishes such a file from its archived copy, which is byte-identical.

Gate after these changes: `bash scripts/gate.sh` PASS in 748 s:
- lane A 412 s — Go suite 115 tests, 0 skipped;
- lane D 416 s — 3,031 parsed = 3,031 SIEM documents = 3,031 lake rows; "Prove it" read the archive; the one-source query
  returns Fortinet and flowtap;
- lanes G20 739 s and G33 623 s — same facts both runs.

The WSL2 and Docker virtual disks did not grow (75.884 GB and 84.65 GB before and after).

## 13. Scale-out, the lake writer, the Parser Transparency Log, Proof of Derivation (2026-09-27)

Built in the order 1 → 2 → 3 → 4. The instruction said 1 → 2 → 4 → 3, but also that Proof of Derivation depends on the
transparency log, so the log came first. Details:
- `docs/throughput.md`: scaling matrix, process death, the lake profile and fix;
- `docs/transparency-and-derivation.md`: the log, the derivation, the certificate;
- the plan's §11, rows 67–71.

**1. Scale-out.**
- **Listeners:** `--reuse-port` for TCP, UDP and HTTP. The kernel's default flow hash keeps each connection, or each UDP
  sender's port, on one process; there is no eBPF or random distribution.
- **Directory pull:** `--pull-shard i/N`, by the file's source key.
- **Demo:** `ULPF_PROCESSES=N` (default 2) starts N runtimes, N committers and N lake writers into one lake root, plus one
  packs file per process. The System page lists the processes and which applications reached each.
- **Crash recovery**, found by the process-death measurement: with a resumed spool, a restart interprets every evidence
  record committed after the spool's last event. Nothing accepted is lost.
- **Measured:**
  - the P × G matrix, with exactly-once and affinity held in all 36 runs;
  - one process does 2.7–3.1k events/s end to end with the archive on; 4 processes × 8 senders reach 5,269/s (3,233/s
    until Parquet);
  - the limit is the shared machine's CPU, about 17 cores of this kind for one billion a day, extrapolated;
  - process death: the senders moved and start fresh on the other process, nothing accepted was lost, and 544 events were
    lost in flight (TCP syslog has no application acknowledgement).
- **Limits stated:** one busy sender cannot be split; a moved sender starts with fresh per-source state.

**2. The lake writer.** Profiled first: a fixed ~0.45 s per file (the full schema) times many small files, the wide write,
and an fsync pair per 100-event batch. Fixed with:
- size rotation in production;
- `preserve_insertion_order=false`;
- `?batch=1000`;
- one writer per process.

Result: 1,660 → 4,448 events/s on the same 152,914 rows. The full schema is kept.

**3. The Parser Transparency Log** (`runtime/internal/tlog`, `ulpf-tlog`, `ulpf-witness`).
- **Formats:** C2SP signed-note checkpoints, an RFC 6962 tree, and a `c2sp.org/tlog-proof` beside each pack, verifiable
  offline.
- **The runtime refuses** any pack without a valid inclusion proof. The check is inside `pack.Load`, with no bypass; tests
  cover startup, hot reload and the static no-constructor rule.
- **Signing is logging**, so auto-healed packs are logged before activation.
- **The witness** cosigns consistent checkpoints only: a fork is refused 422 (tested). In the demo it runs on the same
  machine and stands in for an independent site.
- **Demo moment:** *Push an UNLOGGED pack to process N* — refused, recorded as `pack_refused` in that process's evidence
  log, and shown on the page.
- **The parser history view** shows every pack and how it was produced.

**4. Proof of Derivation** (`runtime/internal/derivation`, `ulpf-runtime derive`, `ulpf-verify derivation`).
- **The check:** the exact logged pack, re-run on the committed bytes, reproduces the SIEM's document field for field.
- **Excluded from the comparison:** `_lineage.processing_time` only.
- **The bundle:** one file, verified offline.
- **Tampering** of a raw byte, the pack or a SIEM field is each caught and named.
- **Contract:** normalized-event **1.6.0** adds `_lineage.parser_sha256`, because id and version alone can name more than
  one logged pack.
- **The BSA §63(4) certificate:** a printable draft. Part A is pre-filled; its declaration and Part B are blank, marked NOT
  COMPLETE, with a note that it is not legal advice.

**Found and fixed while building:**
- the verifier-key parser split on `+`, which standard base64 can contain (caught by the tests);
- the kill before interpretation (the crash recovery above);
- the first matrix's timing bias toward several processes (above);
- a matrix broken by rebuilding the binaries mid-run. Benchmarks now run a frozen copy (`ULPF_BENCH_BIN`).

**Deviations and open items:**
- **Witness cosignatures are verified and reported, but not required by default** (`--tlog-min-witnesses 0`). Packs logged
  while no witness ran (bootstrap, the gate's other lanes) carry none.
- A pack refused at **startup** is on stderr only: the evidence store is not open yet.
- **The bundle verifier loads the pack against the local contract schemas and pinned OCSF index.** Their hashes are
  recorded in the bundle and checked.
- `store_id` is an input the derivation takes from the evidence directory, not covered by a signature.
- Scaling across machines, and a second OpenSearch node, were not measured. Nothing was verified on the laptop.

**Gate after these changes, both configurations, on the desktop:**
- `bash scripts/gate.sh` PASS in 781 s: lanes A (Go suite 128 tests, 0 skipped; Python 100), D, G20 and G33.
- `bash scripts/gate.sh --laptop` PASS in 797 s: lanes A, D and G20. This is the laptop's configuration run on the
  desktop, not the laptop.
- Lane D runs the demo with a **real evidence archive** (not the development override), two processes, the witness, the
  unlogged-pack refusal, Proof of Derivation and the certificate.
- The WSL2 virtual disk grew 0.16 GB over the whole batch (75.884 → 76.04 GB); Docker's did not grow (84.65 GB).

## 14. What ULPF itself can handle — measured with pinned cores (2026-09-28)

The scale-out matrix of §13 shared 8 cores between everything. It was re-measured with each component pinned to its own
cores, replay senders from 8–32 loopback addresses, and the evidence log and archive on in every run. The full report is in
`docs/throughput.md`, "What ULPF itself can handle"; harness `scripts/bench/capacity.py`; results
`docs/metrics/capacity.json`.

**Changed by it:**
- **`?batch=N` now means N events.** The forwarder also cut every batch at its default 256 KiB, about 134 normalized
  events, so `?batch=1000` to the lake never sent 1,000. `egress.BatchBytesFor(n)`: N × 4 KiB, between 256 KiB and
  32 MiB, tested (`TestBatchOfNIsNEventsNotTheDefaultByteBound`).
- **The fake bulk receiver:**
  - `disable_nagle_algorithm`: its header and body writes stalled ~40 ms per request on the client's delayed ACK;
  - `--ids FILE`, a measurement mode that counts and records ids instead of holding millions of documents.

**Results, on the desktop:**
- One process: 5,310 events/s for 10 minutes on 1.44 CPUs.
- 2, 4 and 6 processes: 9.5k, 13.9k and 15.8k/s (88 %, 64 %, 49 % per process). The losses are CPU sharing between two
  threads of a core and disk waits (~25–33 %, measured on tmpfs); with few senders, idle processes.
- ULPF alone held one billion a day (11,574/s) for the full 3-minute windows with four or six processes, on ~5.5 logical
  CPUs.
- End to end, with OpenSearch and the lake on the same machine: 7.0k/s for 10 minutes. ULPF's two cores were saturated,
  OpenSearch kept pace, and the lake writers fell about 40 s behind.
- Exactly-once and affinity held in all 42 recorded runs.

**Gate after these changes, both configurations, on the desktop:**
- `bash scripts/gate.sh`: **PASS in 687 s**. Lanes: A (Go suite 129 tests, 0 skipped; Python 100), D (apps-check, a real
  evidence archive and real OpenSearch: 3,395 parsed = SIEM = lake), G20 and G33.
  - The first run of it failed in lane D. The learning plane's `python -m ulpf_learn` (working directory on the Windows
    drive, `/mnt/c`) reported `No module named ulpf_learn` for one onboarding job while the other three lanes were
    running. It did not recur in the `--laptop` run or in the re-run, and nothing in this change touches the learning
    plane. Recorded as a transient; not explained.
- `bash scripts/gate.sh --laptop`: **PASS in 757 s** (A, D, G20). This is the laptop's configuration run on the desktop, not
  the laptop.
- The virtual disks did not grow during the gates. Over the whole batch, WSL2's grew 3.69 GB (81.645 → 85.336 GB);
  Docker's did not (90.893 GB).

## 15. A real device: FortiGate 7.4.12 (2026-09-29)

Details, results and findings: `docs/real-device-fortigate.md`.

**The device.** A licensed FortiGate VM (evaluation, serial FGVMEVXFB-07ZH02) under Containerlab/vrnetlab in its own WSL
distro. It sends syslog over TCP to ULPF.
- The lab is started by `demo/devices/fortigate/start.sh`: `docker start` only.
- vrnetlab is patched in the container: the licence's UUID is pinned, and port2 is added for a traffic container.
- The distros share one network namespace, so ULPF is reachable at the Containerlab bridge, 172.20.20.1.
- `ULPF_REAL_DEVICES=1` binds the demo's one syslog/TCP listener on all addresses. The runtime takes one `tcp:` listener,
  so there is no second port.

**Results:**
- The corpus-built FortiGate pack parses the real device's default-format traffic logs: 254 of 264, time and fields
  checked. It misses the `type=event` family and the csv, cef and json formats.
- Real events reach OpenSearch and the lake.
- "Prove it" and Proof of Derivation pass on a real-device event.
- Live format drift quarantined every changed format with the bytes kept. Nothing healed and nothing was promoted.

**Raised, not changed:**
- the learning plane's drafter does not unwrap syslog/CEF envelopes;
- the prepared answer sheet is not scoped to a source;
- FortiGate csv is attributed to the PAN-OS pack as drift, and the console ignores `routing_drift`;
- the console's trigger window is shared by all sources.

**Demo-only changes:**
- `ULPF_REAL_DEVICES`;
- the inventory entry for 172.20.20.2;
- the REAL DEVICE label;
- the relay kept on loopback.

**Gate, both configurations, on the desktop, with the FortiGate lab running beside it:**
- `bash scripts/gate.sh`: **PASS in 762 s** (A: Go 129 tests, 0 skipped, Python 100; D; G20; G33).
- `bash scripts/gate.sh --laptop`: **PASS in 812 s** (A, D, G20). This is the laptop's configuration run on the desktop, not
  the laptop.

**Before those passes, three runs failed, each on a timing check and each passing in the other runs.** None of them touches
code changed here: this change has no Go code, and none in apps-check or the gate.
- **Desktop, first run:** lane D's affinity checker exited with an empty report, meaning the checker itself failed, not a
  split connection. Its log was overwritten before it could be read.
- **`--laptop`, first run:** `TestUnloggedPackIsRefusedAtStartupAndOnReload` waits 5 s for the refused reload, and did not
  see it in time.
- **`--laptop`, second run:** `start-demo.sh` counted committers and lake writers 2 s after starting them, and one was not
  up yet. That failed start left its demo running; it was stopped by hand.

These three waits are raised as flaky under load; they were not changed.

**After the gate, a lab fix.** At 13:47 UTC the FortiGate container died about 70 minutes after starting: vrnetlab's
`launch.py` crashed on a `ScrapliTimeout` and took the VM down with it. Its scripted serial-console login waits for the
default prompt, then for a `Password:` it has already half-read.
- `patch-vrnetlab.py` now also patches `/launch.py`: a login prompt means the VM is up, and nothing is typed on the console.
- The container is `healthy` after the patch, and the licence stayed Valid through the crash and three restarts.
- Only `demo/devices/fortigate/` changed after the gate runs. The gate does not exercise those files.
