# ULPF demo — portable replay bundle

A recorded run of the six-step ULPF demo (SIH 2026, PS 26156), replayed through the demo's own UI.
Needs: **Python 3 (standard library only) and a browser.** No pip, no Docker, no GPU, no Go, no
network — nothing in here ever opens a connection except your browser to localhost.

```bash
unzip demo-replay.zip
cd demo-replay
python3 serve.py            # prints http://localhost:8765/
```

Open **http://localhost:8765/** and press **1** to start step 1. Full screen (F11) for a projector.

## Keys

| key | does |
|---|---|
| `1` … `6` | jump straight to that step (a judge asks for the tamper one again: press `6`) |
| `n` or `→` | next step |
| `p` or `←` | previous step |
| `space` | pause / resume the step being replayed |
| `t` | show / hide the real terminal output of the current step |
| `s` | cycle the four screens (certificate review → tamper → live flow → discovery) |

The UI follows the running step automatically. Each step's artifacts appear when its replay window ends;
step 5's event stream plays out line by line; step 2 is compressed to 18 s while the badge shows the
real 145 s it took live.

## What is inside

- `serve.py` — the replay server (stdlib). `ui/` — the demo UI unchanged, plus `replay.js`.
- `capture/` — one real run: `status.json` (real per-step timings), `state/` (every file the UI reads:
  sessions, certificates, packs, the mixed capture, the event stream, the tamper result), `terminal/`
  (each step's terminal output, and the reset and pre-flight output).
- `real/` — optional real mode (see below). `NOTICE.md`, `ELASTIC-LICENSE.txt` — provenance and licences.
- `PRESENTER.md` — what to say per step, the real timings, the replay sentence, what to do if it hangs.

## Optional: run steps 5 and 6 for real on this machine

`real/bin/` holds static Linux x86-64 binaries of the runtime, the committer and the verifier. They
need nothing else. This runs the mixed stream through the real runtime with the recorded packs, then
commits, verifies, exports, verifies the bundle in-process (the witness *container* is the only thing
replaced), flips a byte and verifies again — on this laptop, on any newline-delimited capture you give it:

```bash
bash real/run-real.sh                       # the recorded mixed capture
bash real/run-real.sh /path/to/other.log    # any capture: unknown families quarantine, known ones route
python3 serve.py --real                     # steps 1–4 from the recording, 5 and 6 from this machine
```

Steps 1–4 cannot run here: they are the learning plane (Python with `google-re2`, `jsonschema`,
`cryptography`), which the standard-library constraint rules out. The badge says which mode is showing.
