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
use. Ports of the three-app demo, all on 127.0.0.1: 8780 generator, 8765 system, 8790 + 8791 database, 6515 + 8516 ULPF ingress. Pre-flight still pins 20 GPU layers (the laptop's split) and the default
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
| **3 Database** :8790 (`demo/apps/database.py`) | a consumer application (SQLite), outside ULPF | egress connector: HTTP POST · Syslog over TCP · File (stdout connector) · Disconnected; click a row → the stored OCSF event |

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

## 6. The gate (desktop, 2026-09-22, after the last change — the router narrowing included)

`p1-check` … `p8-check` pass (26 / 74 / 31 / 37 / 83 / 74 / 189 s; zero skipped tests, 26 golden files byte-identical, coverage
figures regenerate byte for byte); the Go suite and 90 Python tests pass.

| | six steps, run 1 / run 2 | scripted live sequence, run 1 / run 2 | same facts shown | three-app check, model (key=value, LEEF, JSON) |
|---|---|---|---|---|
| 20 layers (the laptop's split, pinned) | 89.1 s / 89.3 s | 177 s / 167 s | yes / yes | PASS, 367 s |
| 33 of 33 layers (desktop only) | 45.7 s / 45.9 s | 134 s / 144 s | yes / yes | PASS, 273 s |

Three-app check with fixture proposals, all six formats in one session (onboard + drift + answers each, then the database's
disconnect / reconnect / connector switch): PASS — 377 rows stored for 377 parsed events, 633 duplicates ignored.
The pages themselves were clicked through in a browser on the desktop (connector, format, start, the application's log list,
one log's detail, the drift alert, both dropdown answers, the corrected pack). **Nothing here has run on the laptop.**
One model call was 32–62 s at 20 layers on the desktop; on the laptop expect longer, the six steps at 150–160 s (measured
there on 2026-09-07) and the scripted live sequence correspondingly slower.
