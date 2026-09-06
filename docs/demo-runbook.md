# Demo runbook — what to say, what to click, what to do when something hangs

The demo is assembly over P1–P7: six steps, one runnable order, each step a script under `demo/steps/`
that calls the same CLIs the phase checks call and copies its artifacts into `~/ulpf-demo/`. The UI
(`demo/ui/`, served by `demo/serve-ui.py`) is a read-only layer over those files — polls them, renders
them, decides nothing. Every step runs and reads fine in a terminal without it. Nothing here needs the
network: the model server, the witness container and the UI are all local.

**Machine:** the GTX 1650 laptop, WSL2 at its default 7.7 GB cap, driver 616.64. Measured on it, twice in a
row, on 2026-09-07 (§5).

## 1. Before the judges walk in (T-30 min)

Open two WSL terminals in the repo (`cd /mnt/c/VSCode/sih2026-ulpf`) and a browser window on the projector.

```bash
bash demo/llama-server.sh start          # the 4B on the GPU, 20/33 layers, 8k context; ~10 s (PTX cache warm)
python3 demo/serve-ui.py &               # http://localhost:8765  (once; it survives resets)
bash demo/reset.sh                       # clean state, dev keys, vendor packs rebuilt from the corpus (~25 s)
bash demo/preflight.sh                   # 15 checks; must end "PRE-FLIGHT: all clear"
```

Browser: `http://localhost:8765/`. Full screen (F11). It shows "step 2 has not run" — that is correct.
Keys on the UI: `1` certificate review, `2` tamper proof, `3` live flow, `4` discovery, `F` toggles
"follow the running step" (on by default: the UI switches to the screen of whatever step is running).

Close other GPU users (browser tabs with video, anything with hardware acceleration). The 4B leaves ~1 GB
of VRAM headroom; the 8B would not.

If `preflight.sh` fails a line, fix that line before anything else — the table in §6 says how.

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
same path as step 2 run by hand: `bash demo/run.sh 2 2` with the new samples in `SAMPLES`. The automatic
loop is designed (P8) and not built; say so plainly if asked.

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
| Q&A | "does it work on an unseen format?" | `bash demo/run.sh 2 2` with `SAMPLES=/path/to/their/lines` exported first (`export SAMPLES=...`): same path, live, ~2 min. If the structure is not positional (kv/csv) the induced structure still shows; certificates may differ. |

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

Ports: 8081 model server (container), 8765 UI, 6514 the mixed stream's TCP listener. Port 8080 belongs
to a Jenkins service on this laptop — never use it.
