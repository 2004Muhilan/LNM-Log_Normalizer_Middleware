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

## The final demo FROM CONTAINERS (2026-10-01; pages simplified 2026-10-02) — the same pages, the same seven steps

ULPF now runs as containers ([container-deployment.md](container-deployment.md)): each runtime process is its own
container, with a committer and a lake writer beside it. Everything below ("The final demo") is unchanged; only the start
differs, and the Runtime panel on the System page has **Add process** / **Remove process**.

**T-30 min** (the lab and the model as before; the stack runs on the Linux Docker Engine of the `Containerlab` distro):

```bash
python3 demo/devices/preflight.py                                       # in Ubuntu: licence, containers, both devices reach :6515
wsl -d Containerlab -- bash demo/devices/agent/start.sh                 # the lab agent (lab.sh behind HTTP: the console's device buttons)
wsl -d Containerlab -- env ULPF_LAB_AGENT=http://127.0.0.1:8799 bash deploy/ulpf.sh up devices
```

**The extra moment — after step 4 (flow), or whenever a judge asks "does it scale?":**
- **Press:** Runtime → **Add process**. **Seen:** in about a second a row *Process 3*. A new process always takes the lowest free
  number; removed ones are listed only under **Show retired**. The limit is one per CPU Docker reports.
- **Say:** "Each runtime process is a container. Adding one is a button: a new container with its own evidence store, every
  active parser loaded, on the same ingress port — the kernel spreads new connections over the processes."
- **Press:** **Remove process**. **Seen:** *draining*, then the line "Process 3 removed — nothing left behind". The devices go on parsing.
- **Say:** "Removing one loses nothing: it waits until every destination has what that process parsed, stops it — it seals
  its evidence — waits until its evidence is shipped to the archive, and only then removes it. Its events stay provable."
- **Don't say:** that an open connection moves without a reconnect (it closes; the device reconnects to another process),
  or that Docker Desktop is supported (a published port rewrites the sender's address — the page warns).

The generator demo in containers: `bash deploy/ulpf.sh up generator`. The host-process demo (`start-demo.sh`) stays as it was.

## The final demo — real devices, real destinations (2026-09-30)

Two real devices in the lab:
- **the licensed FortiGate 7.4.12 VM;**
- **Suricata 7.0.7,** on the FortiGate's own wire.

Two real destinations: **OpenSearch** and the **Parquet lake**. The pages are the same (System, Data lake, SIEM); the first
device controls (FortiGate, Suricata, Lab traffic) are the top row of the System page. The presenter never needs a terminal.

**The generator demo is the FALLBACK** (`bash demo/start-demo.sh`, unchanged below), and the gate runs on it. The gate
cannot depend on the licensed VM.

### Before the judges walk in (T-30 min)

1. Model: `bash demo/llama-server.sh start`.
2. `bash demo/start-demo.sh devices`. It runs the **device pre-flight** first, and stops if any of it fails:
   - the Containerlab distro is kept up **without a window**: a hidden Windows-side `wsl.exe` session named
     `ulpf-clab-keepalive`, started once;
   - the **FortiGate licence reads Valid**. If not, STOP: never redeploy, one evaluation per account;
   - every lab container is running, and a stopped one is started;
   - the traffic loop runs;
   - **both devices really reach ULPF's syslog port**: a throwaway listener on :6515. A FortiGate that does not send is
     **reconnected automatically** (its syslog setting is re-committed);
   - then both are disconnected again for the first step.
3. The demo then starts with **the devices disconnected, OpenSearch stopped and no lake writer**. Everything is connected
   on stage.
4. Open the System page, the Data lake page, and in the SIEM tab the dashboard **"ULPF — real devices, side by side"**.

`ULPF_SKIP_DEVICE_PREFLIGHT=1` starts without the check. Don't, unless you know why.

### The seven steps — what to press, what to say

**1. Connect ingress.**
- **Press:** FortiGate **Connect**, then Suricata **Connect** (top row).
- **Seen:** each device's syslog connector turns ON. Within seconds both appear under *Sources*, as
  *Syslog over TCP* on `tcp:0.0.0.0:6515`, with the REAL DEVICE tag, the FortiOS version and the serial.
- **Say:** "Two real devices. The firewall is a licensed FortiGate VM; the IDS is Suricata watching the firewall's own
  wire. Each connects through ULPF's syslog ingress connector, over TCP. ULPF only sees a channel and a peer; the
  inventory says which device sits behind which address."
- **If** the FortiGate does not appear within ~20 s: the page reconnects it by itself (a second attempt, shown in the
  action log). The watchdog also re-commits its syslog if it goes silent for 60 s while ON.

**2. Connect egress.**
- **Press:** SIEM — OpenSearch **Start**, then Data lake **Connect**.
- **Seen:** both destination blocks turn **UP**. *Ahead by* — what ULPF kept in its spool while they were not there —
  falls to 0.
- **Say:** "Destinations are a list: a transport and an encoding each. Each has its own cursor over one bounded spool.
  What arrived before they were connected was kept and is delivered now, from each cursor."

**3. Onboarding.**
- **FortiGate:** it is parsed at once (`fortigate-traffic`), recognised by its **existing pack**, built from the vendor's
  documentation. Its row reads *bound: routed only among its source's 1 pack*.
- **Suricata:** it is unknown, so every alert is quarantined, bytes kept. **Press:** its onboarding job → **Onboard this
  application's format**.
  - The local model proposes, and **ambiguity certificates** appear. Every run had five or six:
    - `timestamp`: *temporal role* — `time` or `end_time` or `metadata.logged_time`;
    - `src_ip`, `src_port`, `dest_ip`, `dest_port`: *endpoint orientation* — is this the source or the destination?
    - sometimes `action`: *action outcome*.
  - The operator answers each field on the page: `timestamp` → time, the addresses and ports, `proto`, `action` →
    `action_id` with the value map `allowed=1, blocked=2`, `signature` → message. Then **Promote**.
  - The pack is signed, logged in the transparency log, verified by the Go engine and hot-loaded; Suricata's alerts
    parse from then on.
- **Say:** "The model proposes; it never decides. Where the samples cannot tell two meanings apart, ULPF issues a
  certificate and asks for evidence. Here it asks the operator, and records who answered what."
- **Note:** an extra "New family of a known source" job can appear for the FortiGate: every device action logs an admin
  in over SSH, and those login events are a family no pack owns. Leave it (it waits for a click), or onboard it as a bonus.

**4. Flow.**
- **Press:** Lab traffic → **Send attack traffic**, then the SIEM tab.
- **Seen:**
  - *Events per device over time*: FortiGate and Suricata side by side.
  - The link **Saved search: one attacker, every device** (`src_endpoint.ip: 10.10.1.10`) returns the FortiGate's denies
    AND Suricata's alerts for the same connections.
  - The Data lake page: the same events in Parquet, one schema.
- **Say:** "One query, OCSF field names, two vendors: FortiGate called it `srcip`, Suricata `src_ip`; the SIEM only knows
  `src_endpoint.ip`."

**5. Egress outage.**
- **Press:** SIEM — OpenSearch **Stop (outage)**.
- **Seen:** the OpenSearch block goes DOWN and its *ahead by* climbs, while the lake's stays near 0.
- **Press:** SIEM — OpenSearch **Start**. The backlog arrives from its cursor.
- **Say:** "No duplicates: the document id is the event id, so a redelivered event overwrites."

**6. Drift.**
- **Press:** FortiGate log format **JSON**. The device itself switches, live.
- **Seen:** a DRIFT alert on the FortiGate (bound source). Most fields **heal automatically**: 44–47 of 50–53 in the
  runs, carried over by name from the answers ULPF already has for this device. The unknown ones are **asked**: 6–7, the
  interim-update counters, `app`, sometimes `dstcountry`. The healed pack loads, and the JSON parses.
- **Honest detail:** a few JSON lines carry keys the 12 samples did not show (2–6 of the next 30 in the runs). They are
  quarantined, bytes kept, and would drive the next heal. Say so if a judge spots them.
- **Suricata keeps parsing throughout.** Each line is routed only among the packs of the device that sent it, so the
  FortiGate's JSON family and Suricata's JSON family never collide.
- **Say:** "Same device, new format: nothing guessed. What the device names the same way carries over; what is new is
  asked."
- **After:** switch the format back to **Default**.

**7. Prove it, then the certificate.**
- **Press:** click Suricata (or the FortiGate) in *Sources* → an event → **Prove it** in its detail.
- **Seen:** the SIEM document, the original bytes re-hashed from the evidence log or archive, the signed checkpoint, the
  Merkle proof, **Proof of Derivation** (the exact logged pack, re-run, reproduces the SIEM's document), and the same
  event in the lake.
- **Then:** **BSA §63(4) certificate — draft** (in the *Prove it* panel).
- **Say:** "Part A is filled from ULPF's records; the declaration and Part B are for people to complete and sign. It is
  never presented as complete, and it is not legal advice."

### "allowed" and "deny" for the same connection

Suricata watches a copy of the traffic and blocks nothing, so its alerts say `action: allowed`: "the sensor let it pass".
The FortiGate is what denied it.
- **Say:** "The IDS saw the attempt; the firewall stopped it."
- **Don't say:** that Suricata's "allowed" means the attack got through.

### What not to say

- **That the binding authenticates a device.** It trusts the sender's address: sound over TCP (the handshake), spoofable
  over UDP.
- **That Suricata's class was chosen by evidence.** Network Activity is what the model proposed and the operator kept.
- **That alerts quarantined before the pack existed were re-derived.** They stay quarantined with their bytes.
- **That the witness is independent.** It runs on the same machine.

## The demo with pages (laptop branch) — the generator FALLBACK — what to say

**Before (T-30 min, network still available once):** `pip install -r learning/requirements.txt` (DuckDB); pull the SIEM
images (`docker pull opensearchproject/opensearch:2.19.2 opensearchproject/opensearch-dashboards:2.19.2`); then offline:
`bash demo/preflight.sh` (it checks both images and DuckDB are local), `python3 demo/siem/contract-check.py --limits`
(the gate's SIEM stand-in answers like the real OpenSearch — run it before the SIEM is under demo load), then
`bash demo/start-demo.sh`. **Say once, early: the OpenSearch security plugin is disabled in this demo to save memory. It
is not a production configuration.**

1. **The line to open with (multi-destination):** "ULPF is middleware. It does not know it is talking to OpenSearch or to a
   lake — a destination is a transport and an encoding, and this one list decides where events go. Each destination has its
   own cursor over one bounded spool, so a dead one never holds the others back."
2. Generator: connector, a format, *Start*. System: the application appears; onboarding runs; both destination blocks show
   **UP** and *ahead by 0*. SIEM (tab 4): the dashboard fills — events by class, denies over time, top sources, quarantine
   count. Data lake (tab 3): Parquet files per day, **one schema in every file**, lineage columns first.
3. **The outage:** System → *Stop the SIEM (outage)*. "The SIEM is gone. Watch the two counters: the SIEM's *ahead by* climbs,
   the lake's stays at zero — ingestion does not wait for anyone, and the lake does not wait for the SIEM. The interruption is
   itself an evidence record." → *Start the SIEM again*: "Its backlog arrives from its own cursor, the counter falls to zero,
   and because the document id is the event id, a redelivered event overwrites — nothing is stored twice."
4. **Detections:** Generator → *Attack burst*; about a minute later the finding is in the System page (and in the SIEM's own
   Security Analytics page). "We wrote a custom log type and two rules — OpenSearch's prebuilt OCSF rules only cover AWS logs."
5. **The strongest moment — Prove it:** "Take the SIEM's finding. Its document id is ULPF's event id. From that id: the
   original bytes out of the evidence log, hashed again right now, their Merkle proof checked under a signed checkpoint by a
   verifier that holds only a public key — and the same event in the lake, same hash. A SIEM finding back to the original
   evidence, provably unaltered." (The committer runs in the development seam — sealed, not kernel-immutable; say so if asked.)
   **Then the derivation (Proof of Derivation, 2026-09-27):**
   - Say: "The bytes are unaltered — but was THIS the parser that made the SIEM's event? The trace fetches the exact pack
     from the parser transparency log, verifies its inclusion proof, re-runs it on these bytes, and the output equals the
     SIEM's document field for field. The only field left out is the moment of normalization: it records WHEN, not WHAT."
   - *Download the derivation bundle*: one file, verified offline by `ulpf-verify derivation`, with no ULPF running. If a
     byte of the raw record, the pack or the SIEM document is changed, it says which one.
   - *BSA §63(4) certificate — DRAFT*: say "Part A is filled from what ULPF knows: the device, how the record was produced,
     SHA-256 and the hash. The declaration and Part B are left blank for people to complete and sign — it is never
     presented as complete, and it is not legal advice."
6. Drift, self-healing and the per-log view are unchanged (docs/laptop-branch.md §5).
7. **Scale-out (2026-09-27):** the runtime block lists N processes (default 2; `ULPF_PROCESSES=N bash demo/start-demo.sh`),
   all on the same ports.
   - Say: "The kernel hashes each connection to one process, so a sender's per-source state stays in one place."
   - The application list says which process each application reached.
   - What not to say: that one busy sender is spread over processes (it is not: one connection, one process); that a
     sender keeps its state when its process dies (it reconnects to another and starts fresh there).
8. **The evidence archive block:** segments shipped, pending, local buffer against its cap.
   - Say: "ULPF keeps only a short local buffer. The rest is shipped byte-exact to the archive and deleted here only
     when every condition holds."
   - *Prove it* on an old event reads the archive.
9. **The parser transparency log block:** every pack ULPF may load, how it was produced (hand-written, vendor-onboarded,
   onboarded, auto-healed) and when it was logged, with the witness's cosignature.
   - *Push an UNLOGGED pack to process 1*: the pack is validly signed, but not in the log. The process refuses it, the
     running packs stay, and the refusal is a `pack_refused` record in that process's evidence log (shown in red).
   - Say: "The witness runs on this machine; it stands in for an independent site. Real deployments put witnesses on
     separate machines."

What not to say: that the lake is "Security Lake compatible" (it follows the layout convention; never tested against it);
that Splunk or a CEF SIEM was tested (fake receivers only); that the security plugin is on; that the certificate is a
complete or signed BSA certificate (it is a draft for a person and an expert to complete); that the witness is
independent (it is on the same machine in the demo); anything about the laptop (the laptop has not been re-verified
since the scale-out, archive, transparency-log and derivation work).

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

> **Laptop branch, 2026-09-27:** in the scripted sequence the consumer is now THREE destinations — the SIEM stand-in
> (`demo/siem/fake_bulk.py`, contract-checked against OpenSearch), the lake writer, and stdout. Phase D kills the SIEM:
> the lake keeps flowing while the SIEM falls behind, then the SIEM's backlog arrives with no document twice. Phase H
> balances generated == evidence records == SIEM documents == lake rows (one Parquet schema). The pages described below
> were removed; read the terminal.

`bash demo/live/run-live.sh` after the usual set-up (reset, model server, UI). Parallel to the six steps; everything it
writes is under `~/ulpf-demo/live`. **About 3 min at 20 layers, about 2 min at 33** (two model calls; timings in
[live-demo-report.md](live-demo-report.md)). Acceptance: `bash demo/live/twice-live.sh`.

**Three pages, each doing one job** — plain, large type, black on white; **red means down or failing and nothing else is coloured**. Open all three before you start (key `5` in the six-step UI jumps to the first):

| page | what is on it | when you point at it |
|---|---|---|
| **System** — http://localhost:8765/live.html (the main screen) | two status blocks, **Generators** and **Consumer**, UP / DOWN in very large type (the whole block turns red when down); the list of phases A–I, each pending / running / done, advancing by itself; and **only what the running phase needs**: A the quarantined / parsed / guessed counters and the *onboard* button; B and F the certificate cards and one row per column (dropdowns when interactive); C two counters; D "ULPF is ahead of the database by N" and the outage records; E parse success and the ALERT; G–H the three numbers of the accounting; I the whitespace case. When a phase ends its detail goes away | all the time |
| **Generator** — http://localhost:8765/generator.html | the raw lines as they are produced, scrolling, each prefixed with the connector it leaves through (`syslog TCP` / `HTTP POST`). Nothing else. At the drift the lines visibly change shape (a number where `tcp` was, a zone at the end) | phase A ("this is what arrives: no labels anywhere") and phase E ("firmware 2.0") |
| ~~**Database**~~ — **gone.** The SQLite consumer and its page were removed; on :8790 the sequence now runs the SIEM stand-in (`demo/siem/fake_bulk.py`), and the pages demo shows OpenSearch Dashboards and the Data lake page instead | — | — |

Nothing on these pages drives the sequence: `run-live.sh` advances the phases exactly as before. The only controls are the two that already existed — the *onboard* button and the dropdowns + *promote* — and they only exist in an interactive run.

```
flowtap sensor A --syslog/TCP (RFC 6587)--\                          /--bulk HTTP--> SIEM stand-in :8790 (the SQLite sink is gone)
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

## A real device: the FortiGate lab (optional; `docs/real-device-fortigate.md`)

**Start.**
1. `wsl -d Containerlab -- bash …/demo/devices/fortigate/start.sh` (docker start only — never containerlab deploy/destroy).
   It prints the licence status and stops if it is not Valid.
2. `ULPF_REAL_DEVICES=1 bash demo/start-demo.sh`: the syslog/TCP listener binds all addresses. The FortiGate sends to
   172.20.20.1:6515.
3. If the FortiGate does not connect within a minute, `syslog-format.sh default` restarts its syslog.

**Show.**
- The System page lists **FortiGate firewall (real device, Containerlab)** with a REAL DEVICE tag, next to the relay.
- Its default-format traffic logs are parsed by the corpus-built FortiGate pack.
- "Prove it" and Proof of Derivation pass on one of its events.
- **Live format change:** `syslog-format.sh csv|cef|json` quarantines the new format with the bytes kept.

**A demo moment: a new event family, live.**
1. Make a few admin logins on the device (`fgt-cli.sh "get system status"`, a handful of times).
2. The console shows **NEW EVENT FAMILY from FortiGate (bound: … parsed by fortigate-fw-01)**: system events no family owns.
3. The model proposes OCSF Authentication. There is no prepared sheet for this device, so the operator answers on the page:
   - eventtime → time, user → user.name;
   - status → status_id with a value map `success=1, failed=2`.
4. Press Promote. The next logins are parsed; "Prove it" and Proof of Derivation pass on them.

The trigger window is per source (2026-09-30), so the relay can stay ON.

**Live format change:** `syslog-format.sh csv|cef|json` is shown as **format drift of the FortiGate (bound source)**, never as
another vendor's drift. The console then onboards the new format and asks the operator.

**`json` heals by name (2026-09-30).** `syslog-format.sh json` heals automatically in part:
- 47 of 52 fields carry over by name from the FortiGate vendor pack's documented answers, and the pack loads with no
  question;
- 5 interim-update counters no one has answered yet are carried unmapped and asked.

**What not to say:**
- that every format change heals: only self-describing formats (JSON, key=value) carry answers by name. csv and cef
  (whose keys differ) ask;
- that csv or cef are fully handled: csv is drafted as CSV of `key=value` cells, and CEF values with spaces need a
  parser-spec change. Both are raised in the doc.

## A second real device: Suricata on the FortiGate's wire (optional; `docs/real-device-suricata.md`)

**Start** (after the FortiGate lab): `wsl -d Containerlab -- bash …/demo/devices/suricata/start.sh`. It builds the image
once, while online. The ruleset is local only.

**Show.**
- The System page lists **Suricata IDS (real sensor, Docker)** with a REAL DEVICE tag, 172.20.20.11.
- Its alerts are quarantined as a new format. The console drafts the JSON, the model proposes, and the operator answers.
- The pack is hot-loaded.
- At ULPF's output, each Suricata alert matches the FortiGate's log of the same connection (same source and destination
  port).

**Order no longer matters.** The 2026-09-30 rehearsal found the FortiGate's and Suricata's JSON families sharing one
routing key. Since the routing change, each device's lines are routed only among its own source's packs, so both parse
side by side (`docs/laptop-branch.md` §19).

**Show, after it is onboarded (2026-09-30):**
- Its alerts are in OpenSearch (`ulpf-ocsf-4001`) and the lake.
- **One search, two devices:** `src_endpoint.ip: 10.10.1.10` over `ulpf-ocsf-*` returns the FortiGate's denies and
  Suricata's alerts for the same connections.
- "Prove it" on a Suricata alert passes every step: the SIEM document, archived bytes, checkpoint, Merkle proof, Proof of
  Derivation, and the lake row.

**"allowed" on Suricata and "deny" on the FortiGate, for the same connection:**
- **Why:** Suricata runs as an IDS. It watches a copy of the traffic and blocks nothing, so every alert says
  `action: allowed`, meaning "the sensor let it pass", not "the connection succeeded". The FortiGate is the device that
  blocked it.
- **How ULPF maps it:** Suricata is kept as Network Activity (4001), and the operator's value map sends `allowed` to
  `action_id` 1.
- **What to say:** "The IDS saw the attempt and alerted; the firewall stopped it. Each device reports its own verdict."
- **What not to say:** that Suricata's "allowed" means the attack got through.

**What not to say:**
- that Suricata's class was chosen by evidence. The model proposed Network Activity and the operator kept it.
  OCSF 1.3's Detection Finding keeps the addresses in an array ULPF cannot write, and the page has no class override
  (not built, by decision);
- that alerts quarantined before the pack existed were re-derived. They stay quarantined, bytes kept. `renormalize`
  corrects events that were already normalized; it has no path for events that never were.
