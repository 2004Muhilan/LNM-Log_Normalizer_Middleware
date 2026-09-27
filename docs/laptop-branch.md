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
the same file). **Measured cost of the fixed schema:** ~3 600 schema elements (network activity), ~280 KB of footer, ~390
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
