# Replay bundle — produce your own

The replay bundle (`demo-replay.zip`) is a recording of one real run of the six-step demo, replayed
through the demo's own UI by a standard-library Python server. It is **not committed**: the recording
embeds lines from Elastic-licensed test fixtures, which this repository never carries (P1 decision,
`corpus/README.md`). The zip and the capture are ignored by git. Build it yourself on a machine set up
for the live demo (`docs/demo-machine-setup.md`):

```bash
bash demo/replay/capture.sh          # reset, pre-flight, the six steps with terminal output -> ~/ulpf-demo-capture (~3 min)
bash demo/replay/build.sh            # -> ~/demo-replay.zip
bash demo/replay/build.sh ~/x.zip --no-binaries    # pure replay, no static binaries (smaller)
```

What `build.sh` packages: the recording (`capture/`), the demo UI plus `replay.js` (the REPLAY badge and
presenter keys), `serve.py`, the docs from `bundle-docs/` with the recording's timings substituted into
`PRESENTER.md`, `NOTICE.md` and Elastic's licence text (the notices ELv2 requires to travel with the
content), and — unless `--no-binaries` — static `linux/amd64` builds of the runtime, committer and
verifier with `real/run-real.sh`, which runs steps 5 and 6 for real on the receiving machine. Steps 1–4
stay recorded there: they are the learning plane, whose dependencies (`google-re2`, `jsonschema`,
`cryptography`) the stdlib constraint excludes.

Hand the zip over directly; do not publish it.
