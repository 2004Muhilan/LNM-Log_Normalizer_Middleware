# Presenter notes — replay bundle

**The sentence, if asked whether this is live:** "This is a replay of a run recorded on our demo machine (<<MACHINE>>)
on <<RUN_ID>>; the times on screen are the real ones, the replay is compressed. The live version needs the
GPU and the model server; this machine has neither." The badge in the corner says REPLAY the whole time.
Do not present the replay as live — the system's whole posture is not claiming more than it proves.

## Real timings of the recorded run (shown in the badge as each step plays)

| step | title | live |
|---|---|---|
<<TIMINGS>>

Replay windows: step 2 → 18 s (the model's 116–125 s of thinking is what is compressed); step 5 → 9 s
(about real); the rest 2–3 s so the "running" state is visible.

## What to say, per step (press the number)

1. **Discovery** (screen 4). "A mixed capture from four vendors, nobody told the system what is in it. It
   clusters lines by what the router will later read — envelope, surface, declared anchors, arity — and
   ranks by volume: the onboarding order. Rank 11 is a PAN-OS line whose log type is outside the declared
   domain: already flagged, no parser has run."
2. **Live onboarding of Squid** (screen 1, plays 18 s). "Six unseen Squid lines. Structure is induced
   deterministically; the model — a 4B running locally on the demo machine's GPU under a grammar — is asked only
   what the ten slots mean. It proposed; the library named the rivals for three of them: timestamp
   (six temporal candidates), client IP (source or destination), the bytes counter (request or response).
   It did not pick. One question, the cheapest that resolves everything: the device's logformat line.
   The answer goes in, every field's provenance flips from *model proposal* to *device configuration*, the
   pack is promoted, signed, and the Go runtime verifies the signature over the exact bytes before it
   parses it." Live this took the time in the badge; the model is 116–125 s of it.
3. **The unresolved case** (screen 1, scroll to the red panel). "Slot two is the duration column. The
   model called it `http_status`. No evidence behind that — 812 type-compatible survivors, no library class
   naming a rival — so the system did not accept it, did not guess, kept the field pending, and the same
   one question covered it; after the answer it is `duration`." The second box is the fixture path: two
   candidates the library cannot separate, an unresolved certificate, no guess.
4. **Propagation** (screen 1, blue panel). "Same source, a second family with an eleventh column: ten
   slots resolve from the first family's answers, no request, zero operator responses, promoted; the new
   column stays a retained certificate." Both families merged into one signed source pack.
5. **Mixed stream** (screen 3, plays 9 s). "Four packs in one runtime, syslog over TCP with RFC 6587
   framing, every byte to the evidence store before anything reads it. The DAG routes by surface facts —
   no parser is ever tried. 98 events, 3 quarantined: two drift signals, one unowned family. ML tuples per
   event. Peer B stopped: that silence is a record in the evidence log, same segment, same tree."
6. **Tamper and suppression** (screen 2). "The committer signs a checkpoint; the verifier recomputes every
   root: OK. Two bundles — an event and the silence record — verified by the witness, a container with
   only the verifier and the public key. Then one byte flipped in the sealed segment: FAIL, and it names
   the leaf — event, segment, byte range. The silence record's root check fails with it: deleting the
   record of an absence is as detectable as deleting an event."

Press `t` at any step to show that step's real terminal output next to the screen.

**Drift and healing** (say, do not claim more): the two drift lines in step 5 are the detection; healing
is step 2's path run again by hand with the new samples. The automatic loop is designed, not built.

**"DEVELOPMENT checkpoint" in the verifier output:** honest and expected — in the recorded run the store
ran unprivileged, so segments are SEALED, not kernel-IMMUTABLE, and the signed checkpoint says so
(`commit_mode`). The kernel-flag version is a separate two-container test in the repository.

## If something hangs

| symptom | do |
|---|---|
| browser shows nothing / "server not reachable" | the terminal running `serve.py` must stay open; restart it and reload. Port 8765 busy: `python3 serve.py --port 8770` and open that. |
| a step's screen looks empty | the step is still inside its replay window (badge shows the %); press `space` to pause, `n` to finish it, or the number again to restart it. |
| you want the raw evidence for a claim | `t` shows the recorded terminal output; `capture/state/` holds every file (sessions, packs, the stream, the tamper result) as JSON. |
| a judge asks "run it on different input" | real mode, if the binaries are in `real/bin`: `bash real/run-real.sh their.log` then `python3 serve.py --real`; steps 5 and 6 run for real, 1–4 stay recorded and the badge says so. |
| real mode fails to start | port 6514 busy (`pkill ulpf-runtime`), or the binaries are missing (pure-replay bundle). Fall back to the replay. |
