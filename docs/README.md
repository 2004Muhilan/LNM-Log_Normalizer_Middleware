# Phase reports

Every phase ends with its own report here, committed as part of that phase's work. The reports are
the project's memory: the basis of the final submission, and the only place the reasoning survives
once the code has moved on.

| Report | Status | Date |
|---|---|---|
| [P1 — contracts, corpus, and the dual-stack harness](p1-report.md) | accepted; boundary decisions verified (addendum) | 2026-09-05 |
| [P2 — runtime vertical slice on a hand-authored pack](p2-report.md) | accepted; boundary items settled (spec.go verified, usability definition) — §7 | 2026-09-05 |
| [P3 — learning plane, deterministic half: certificates without a model](p3-report.md) | accepted; boundary items settled (library-decided ambiguity implemented; model and serving runtime decided) — §6 | 2026-09-05 |
| [P4 — model integration: the model proposes, the machinery decides](p4-report.md) | accepted; model choice provisional (Granite 4.1 8B, pending the laptop run); **demo-laptop measurements outstanding** (see [the runbook](demo-machine-setup.md)) | 2026-09-06 |
| [P5 — evidence log completion: Merkle commitment, the privilege boundary, signing, the witness](p5-report.md) | accepted; boundary items settled (`commit_mode` stamped, no private keys in git, signature before contract, root+CAP posture noted) — §5a | 2026-09-06 |
| [P6 — multi-vendor routing: the DAG, families, propagation, ML emission](p6-report.md) | accepted; boundary items settled (parser-pack 1.3.0 approved, tiebreaker dropped, `ml-feature 1.0.0` frozen as the sixth contract, crosswalk review left to the team) — §5a | 2026-09-06 |
| [P7 — transport, envelope and framing breadth; gap accounting](p7-report.md) | built; stopped for verification before P8 (boundary items open — §5) | 2026-09-07 |
| [P8 — the closing account: the audit, versioned corrections, what the numbers support](p8-report.md) · [test-coverage audit](p8-test-audit.md) | done as re-scoped 2026-09-20 (audit; invariant 8; effort in counted decisions; packaging). Drift healing, replay mix, coverage curve **not built**. Crosswalk review and three audit items owed by the team | 2026-09-20 |

Also here: [Demo runbook](demo-runbook.md) — the six-step live demo (`demo/`), what to say and click, the fallback per step, the twice-consecutive timings. [Demo machine setup](demo-machine-setup.md) — what must be true on a machine before the live demo or the model spike runs there: driver, `.wslconfig`, GPU in Docker, weights on ext4, ports, the model configuration, and every measured figure from the GTX 1650 laptop (CPU floor, both candidate models on the GPU, the live-session comparison).

## Fix pass 2026-09-07 (between P6 and P7, not a phase)

Four code-level findings from the first setup run on the demo laptop, fixed together and separately
from P7 so the P7 diff stays about P7:

| Finding | Fix | Verified by |
|---|---|---|
| `runtime/Dockerfile` test stage never copied `keys/trust`, so the signed golden pack could not load inside the container: eight pack/pipeline tests failed there and had since P5 — the stage is only run by `p2-check.sh`, so P5 and P6 shipped without the in-container suite ever passing | `COPY keys/trust ./keys/trust` in the test stage (public keys only; `keys/dev` is never copied) | test stage green; in-container run 96 passes, host 111 — the 15 missing are the corpus replay subtests that skip without `corpus/cache`, by design; nothing else differs |
| `cryptography` (imported by `signing.py` since P5) undeclared anywhere; the clean-clone test never noticed because it reused the developer's venv | declared in `learning/requirements.txt` and `pyproject.toml`; the bootstrap installs from `requirements.txt` (single declaration); `wsl-bootstrap.sh` honours `ULPF_VENV`/`ULPF_ENV_FILE`/`ULPF_SDK`; every script sources `${ULPF_ENV_FILE:-~/.ulpf-env}`; `clean-clone-test.sh` builds a fresh venv and env file, asserts the fresh interpreter is in use and the developer's venv is not on `sys.path`, and imports every learning-plane dependency before running the checks | clean-clone test on the laptop against this commit (result in the P7 report §0) |
| `models.py fetch` treated a closed connection as a complete download and reported a digest mismatch | expected size from `Content-Length`/`Content-Range`; short reads resume with a Range request up to 30 attempts; the digest is compared only on a complete file | fake-server exercise (short read → resume → verified); the laptop's 4B download |
| top-level README said five contracts | six (ML feature tuple, P6) | — |

## Convention

Shape (as in `p1-report.md`): demonstrable outcome; deliverables; detail on whichever checks carried
the most weight; **raised, not absorbed** — every decision that touched a contract, an invariant, or
a settled architecture point; phase-boundary signals.

From P2 onward, two additions:

- **What was tried and rejected**, not only what was built. The reasoning behind a discarded
  approach stops a later phase from re-litigating something already settled.
- **What the next phase inherits**: obligations, open questions, and anything deferred, with the
  phase that picks it up.
