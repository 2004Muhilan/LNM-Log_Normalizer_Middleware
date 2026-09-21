# Branch `laptop` — what it is and what it adds

Branched 2026-09-21 from the desktop `main` (`4a97b32`), so it already contains everything built there: P8 (audit,
versioned corrections, coverage), **drift detection and self-healing** (`learning/tools/drift.py`, `autoheal.py`,
demo step 8, live phases E–F, `demo/live/parse-drop-check.sh`), and the **connectors** (ingress: file, stdin, syslog
UDP/TCP, HTTP, directory drop — TCP and HTTP together in one runtime; egress: syslog/TCP, HTTP POST, stdout, with a
persisted cursor and outages recorded in the evidence log). The last laptop-built commit was `1a4b849`; it ran on the
desktop only after a one-line loader fix that `main` already had. Three additions on top:

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

Limits, stated: the learning plane can *execute* and *validate* json/xml specs but does not **induce** them — a JSON or
XML source is onboarded from a given spec (`onboard-spec`), like CSV and KV sources; there is no Python LEEF/CEF
envelope twin (the runtime unwraps them; `--unwrap-envelope` strips syslog only), as was already the case for CEF;
no corpus fixture is JSON, XML or LEEF, so these formats are exercised on hand-written lines only.

## 2. Per-log inspector — `demo/inspect-logs.py`

Read-only, stdlib, offline. For every log: the **raw bytes** exactly as received (re-hashed and compared with the
recorded `raw_hash`), length, segment and offset, ingest channel, peer, framing; the **format** the runtime detected
(envelope chain, payload surface, anchors, arity, token classes); and the **parsed result** — pack, family, the
normalized OCSF event and its lineage, or the quarantine stage and reason.

```bash
python3 demo/inspect-logs.py --evidence ~/ulpf-demo/live/ev --run ~/ulpf-demo/live/run-1          # page on :8770
python3 demo/inspect-logs.py --evidence ~/ulpf-demo/ev --out ~/ulpf-demo/step5/out.jsonl --quarantine ~/ulpf-demo/step5/q.jsonl
python3 demo/inspect-logs.py --evidence EV --run RUN --event-id ev_…                               # one log as JSON
```

## 3. Laptop compatibility

Nothing here is machine-specific: no new dependency (Go stdlib, Python stdlib + what the venv already has), no GPU
use, no new port except the inspector's 8770. Pre-flight still pins 20 GPU layers (the laptop's split) and the default
llama image is the upstream one the laptop uses; `ULPF_LLAMA_IMAGE=ulpf-llama` is a desktop-only override. A fresh
clone needs its git-ignored inputs: `corpus/cache`, `ocsf/cache`, `models/cache/Qwen3.5-4B-Q4_K_M.gguf`
(`docs/demo-machine-setup.md`). **Not run on the laptop** — built and gated on the desktop only.

## 4. The gate (desktop, 2026-09-21, after the last change)

`p1-check` … `p8-check` pass (22 / 71 / 27 / 33 / 82 / 72 / 179 s; zero skipped tests, goldens byte-identical, coverage
figures regenerate byte for byte); the Go suite and 77 Python tests pass.

| | six steps, run 1 / run 2 | live sequence, run 1 / run 2 | same facts shown |
|---|---|---|---|
| 20 layers (the laptop's split, pinned) | 90.0 s / 87.6 s | 196 s / 183 s | yes / yes |
| 33 of 33 layers (desktop only) | 48.2 s / 46.6 s | 132 s / 133 s | yes / yes |

On the laptop expect the six steps at 150–160 s (measured there on 2026-09-07) and the live sequence to be
correspondingly slower: it makes two model calls.
