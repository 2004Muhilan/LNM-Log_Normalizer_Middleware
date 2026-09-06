# Phase reports

Every phase ends with its own report here, committed as part of that phase's work. The reports are
the project's memory: the basis of the final submission, and the only place the reasoning survives
once the code has moved on.

| Report | Status | Date |
|---|---|---|
| [P1 — contracts, corpus, and the dual-stack harness](p1-report.md) | accepted; boundary decisions verified (addendum) | 2026-09-05 |
| [P2 — runtime vertical slice on a hand-authored pack](p2-report.md) | accepted; boundary items settled (spec.go verified, usability definition) — §7 | 2026-09-05 |
| [P3 — learning plane, deterministic half: certificates without a model](p3-report.md) | accepted; boundary items settled (library-decided ambiguity implemented; model and serving runtime decided) — §6 | 2026-09-05 |
| [P4 — model integration: the model proposes, the machinery decides](p4-report.md) | accepted; model choice provisional (Granite 4.1 8B, pending the laptop run); **demo-laptop measurements outstanding** (see [the runbook](demo-laptop-runbook.md)) | 2026-09-06 |
| [P5 — evidence log completion: Merkle commitment, the privilege boundary, signing, the witness](p5-report.md) | accepted; boundary items settled (`commit_mode` stamped, no private keys in git, signature before contract, root+CAP posture noted) — §5a | 2026-09-06 |
| [P6 — multi-vendor routing: the DAG, families, propagation, ML emission](p6-report.md) | accepted; boundary items settled (parser-pack 1.3.0 approved, tiebreaker dropped, `ml-feature 1.0.0` frozen as the sixth contract, crosswalk review left to the team) — §5a | 2026-09-06 |

Also here: [Demo laptop runbook](demo-laptop-runbook.md) — what must be true on the GTX 1650 laptop before the P4 spike can run there (driver, `.wslconfig` memory, GPU in Docker, offload knob, CPU floor).

## Convention

Shape (as in `p1-report.md`): demonstrable outcome; deliverables; detail on whichever checks carried
the most weight; **raised, not absorbed** — every decision that touched a contract, an invariant, or
a settled architecture point; phase-boundary signals.

From P2 onward, two additions:

- **What was tried and rejected**, not only what was built. The reasoning behind a discarded
  approach stops a later phase from re-litigating something already settled.
- **What the next phase inherits**: obligations, open questions, and anything deferred, with the
  phase that picks it up.
