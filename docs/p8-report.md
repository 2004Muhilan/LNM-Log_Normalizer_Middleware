# P8 report — the closing account: the audit, versioned corrections, what the numbers support

**Status: P8 as scoped on 2026-09-20 is done; this is the last phase report.** The plan's P8 was cut for
time when the live demo was built instead (it exists: `demo/`, [demo-runbook.md](demo-runbook.md)); what
remained was re-scoped to five items in priority order — the test-coverage audit, versioned corrections
(invariant 8), metrics from data already held, drift healing if time allowed, a packaging pass — preceded by
a fix pass for what the first desktop run of P7 and the demo found. Built and measured on the desktop
(RTX 5060 Ti); the laptop has not run this commit. Reproduce: `bash scripts/p8-check.sh` (needs the corpus
cache and Docker, and refuses to run without either), `bash demo/twice.sh`, `bash demo/run.sh 7 7`.

Acceptance, as set: **the demo runs twice without manual repair, in both offload configurations**, after
everything below — and `twice.sh` now fails if the two runs *show* different things, not only if one exits
non-zero.

| | run 1 | run 2 | same facts shown |
|---|---|---|---|
| 20 layers (the demo; pinned) | 89.4 s (step 2: 74.6) | 89.6 s (74.3) | yes — pos_1 / pos_3 / pos_5 |
| 33 of 33 layers (`ULPF_DEMO_NGL_UNPINNED=1`) | 45.4 s (30.0) | 46.0 s (31.6) | yes — pos_1 / pos_3 / pos_4 |

The two configurations differ in exactly one recorded fact, the third certificate (`diff` of the two fact
files: `pos5 request_response_role` ↔ `pos4 action_outcome`) — the offload dependence found on 2026-09-20
and now pinned. `p1-check` … `p8-check` all pass (18 / 31 / 24 / 29 / 77 / 67 / 40 / 65 s).

## 1. The fix pass (commit `579d9bc`, before P8)

The loader accepts normalized-event 1.3.0; every `go test` in the scripts and the Dockerfile runs with
`-count=1`; hash-bearing paths are `-text` and pre-flight fails on a CRLF working copy; the machine label in
provenance is derived; pre-flight pins the offload split at 20 layers; the replay bundle's `run-real.sh`
summary and machine-specific doc text are fixed. Two validations asked for:

- **Does `-count=1` slow the suite materially?** No: 4.6–5.5 s uncached against 2.7 s cached for
  `go test ./...`. **Are other tests exposed the same way?** Yes, most of them: eight test files in five
  packages read outside the module root (`contracts/`, `contracts/golden/`, `drafts/`, `keys/trust`,
  `ocsf/pinned`, `corpus/cache`). Applied everywhere rather than surgically.
- **Should `.gitattributes` cover more?** It covered everything (`* text=auto eol=lf`) and that was the
  problem: normalising at commit is what let a CRLF working copy stay invisible (`git status` clean, blob
  LF, file on disk CRLF). Hash-bearing paths are now `-text` — bytes, never converted — so the divergence
  shows as a modification. Verified by writing a CRLF fixture: `M` in `git status`, `w/crlf` in `--eol`.

## 2. The audit — [p8-test-audit.md](p8-test-audit.md)

Four masked tests were the prompt; the audit's first result is a fifth, and it is the worst of the five.

**The external witness failed open.** `VerifyBundle` returned findings with a nil error on three paths and
`ulpf-verify bundle` failed only on the error: a bundle with `checkpoint.json.sig` deleted printed
`FINDING checkpoint: signature file missing` and then `VERIFY: OK … signed by a trusted authority`, exit 0.
It was hidden by a negative test that could not fail — "unknown authority refused" ran on the bundle the
previous step had tampered, against a trust path that did not exist, output discarded. Fixed, with the
missing-signature and untampered-bundle cases added in Go and in the witness script. This is a defect in
the theme demo's verifier that shipped through P5, P7 and the demo; it is recorded here, not softened.

Beyond that the audit names ~100 points across 22 scripts. **Fixed in P8** (each now fails where it
passed): no demo step had `pipefail`, so every `cmd | tee | || step_fail` was dead code and step 2 could not
fail; five pre-flight checks ran `cmd | tail` in a pipefail-less subshell and could not fail, and the
completion check passed on an empty completion; step 5 asserted an accounting identity that holds with zero
events (it passed the 92/9 CRLF run) — it now asserts quarantined = 3 with the expected reasons and both
Squid families at 6; step 6 never asserted the *before* verification or which leaf; `twice.sh` compared
nothing; `p7-demo` printed a verdict computed differently from its exit status; invariant 2(b) inspected
whatever image existed and passed on an empty listing; the oversized-message heap bound was vacuous at the
default size; `gofmt -l` could never fail; Docker skips were silent; the root-without-capability boundary
test tried only append. `p8-check.sh` is written against the patterns: named tests must each print
`--- PASS` by name, zero skips in both suites, corpus and Docker required, requirement (k) checked by
value.

**Open, by decision or for time** — the three the team should close first: (1) `build_vectors.py`
regenerates the goldens it is about to be checked against at the top of every phase check —
`normalized/line1.json` pins nothing; (2) the five corpus replay tests compare counts and status and **no
extracted value** — P4's defect, still present on the Go side; (3) the model that answered is never
compared with the digest the pack records. Also open and listed: the subset guard compares two strings and
never rehashes the table; three negative vectors are rejected by the schema before the semantic check they
were written for; `clean-clone-test.sh` cannot fail after line 52; `check-drafts.sh` exits 1 permanently;
lineage `batch` has never appeared in an emitted event in any test; `agreement.py` pairs by a lineage field
that is never emitted; the 302013 recording stands in for two other ASA families whose packs say
`proposed_by: model`; four of five uid-65532 "kernel refusals" in the boundary test are file modes.

## 3. Versioned corrections — invariant 8

**The demo** (`bash demo/run.sh 7 7` after a full run; 3.8 s; not part of the six timed steps). Step 4
promoted the 11-slot Squid family with a retained certificate: slot 11 rested on a proposal,
`http_request.length`, its rival `http_response.length` unrefuted. The operator now supplies the device's
full logformat, ending `%>st`:

1. the certificate resolves — to neither proposal: the vendor table says `%>st` is `traffic.bytes_in`, an
   integer — and the same session promotes **pack version 1.1**;
2. `ulpf-runtime renormalize` re-derives every event **from the evidence log's raw bytes** (each checked
   against its `raw_hash`) under the corrected packs, through the same unwrap → route → parse → normalize
   path, and seals the events whose content changed as **`normalization@v2`, `derived_from: 1`**: read 98,
   corrected 6 (`squid-proxy-01/positional-11`), unchanged 92, not applicable 0;
3. `normalization@v1` is byte-identical — sha256 before = after = manifest; `lake get --event-id` returns
   both versions (v1 `http_request.length: "412"`, parser 1.0 → v2 `traffic.bytes_in: 412`, parser 1.1,
   same `event_id`, `raw_hash`, segment, offset, ingest time); v2 validates against normalized-event in both
   stacks; a shell append to v1 and a runtime `--lake` re-creation of v1 are both shown refused.

Step 6 leaves a flipped byte in the evidence. **A correction derives from evidence, so step 7 first shows
it refused** — `raw bytes of ev_… do not match raw_hash — the evidence was altered` — restores the byte
from step 6's own record, re-verifies the log, and only then corrects. That refusal was not designed for the
demo; it fell out of re-deriving from raw bytes rather than from v1, and it is the better demonstration.

**Exit criteria.** `TestCorrectionEmitsV2AndNeverTouchesV1`: v1 byte-identical and retrievable; v2 carries
`derived_from`, the corrected value, the event's identity, validates; the same correction again seals
nothing (no empty v3); a correction over altered evidence is refused and seals nothing.
`TestNoWritePathToAnExistingVersion`, `TestVerifyFindsAnAlteredVersion`, `TestStaticNoRewritePath`
(`runtime/internal/lake`): the only writer is `Create`, exclusive, latest+1, naming what it derives from;
read-only and hashed into a manifest at close; `lake.go` holds exactly two `O_EXCL` opens and no rewrite
primitive, and its callers never build a lake path themselves.

## 4. What the numbers support

`learning/tools/effort.py` reads only the session timelines recorded since P3. **No analyst was ever timed
in this project — not on ULPF, not on a hand-written parser — so no analyst-minute figure is measured, and
none is reported as if it were.** What both paths have is counted decisions:

| source | families | semantic fields (baseline: one mapping decision each) | ULPF: evidence responses | ULPF: certificates to read |
|---|---|---|---|---|
| asa-fw-01 | 4 | 47 | 4 | 20 |
| panos-fw-01 | 1 | 53 | 1 | 10 |
| fortigate-fw-01 | 1 | 73 | 1 | 11 |
| squid-proxy-01 | 2 | 25 | 1 (the second family: 0 — ten slots propagated) | 4 |
| **n = 8 families, m = 4 sources** | | **198** | **7** | **45** |

**3.8 : 1 in counted decisions, over n = 8 families from m = 4 sources, all promoted** — an effort measure
that says nothing about whether any mapping is correct, from fixtures chosen because drafts existed for
them. The tool converts to minutes only under a stated assumption and prints the assumption; under one such
(3 min per baseline decision, 15 min per evidence response, certificates at the per-decision rate) ASA comes
out **141 vs 120 minutes — barely better than the baseline** — because a four-family source costs four
responses and twenty certificates; the wide single-family formats are where the ratio is large (FortiGate
219 vs 48). That is the honest shape of the claim: effort falls with fields per family and with
propagation, not per se. Agreement with the reference parser stands as measured in P6 and is quoted with
its sample: 208 comparable pairs over 16 of 46 ASA lines; the crosswalk behind it is **unreviewed** (owed
by the team, not self-reviewed). The replay mix and the coverage curve were not built: neither came cheap.

Machine time, for completeness (desktop; laptop in [demo-machine-setup.md](demo-machine-setup.md) §A):
model proposal for the Squid session 58 s at 20 layers, 14 s at 33; every other step under 11 s.

## 5. Packaging pass

Invariant 2 re-verified on a **freshly built** final image (the check used to inspect whatever image
existed): module graph and strings clean, static binary, 1,498 files, no weights / inference library /
Python, 3.8 MB, user `nonroot`. Requirement (k): that image normalizes the golden samples with
`--network none` and the output is checked by value (6 events; line 1's client address and URL); committer,
verifier and witness run `--network none` in the P5 tests. **Not re-verified:** the bundled learning image
(`ulpf-learning:qwen3.5-4b-q4_k_m`, 11.4 GB) dates from P4 and was not rebuilt — it predates P5–P8's
learning-plane code; the demo's model server is the `ulpf-llama` image with weights mounted, and it is not
run network-isolated (it publishes a port). Requirement (k) therefore holds for the runtime plane by test
and for the learning plane by construction only.

## 6. Raised, not absorbed

1. **The witness failed open since P5** (§2). Fixed; the behaviour change is that any finding is a failure.
2. **Invariant 8's store is not kernel-immutable.** "No write path to v1" is enforced by the lake package's
   API (exclusive create, consecutive versions), read-only modes and a sha256 manifest that `lake verify`
   recomputes. Root can rewrite the file; `lake verify` then names the version. The P5 `FS_IMMUTABLE_FL`
   boundary is not applied to the lake, and lake manifests are neither signed nor Merkle-committed — the
   normalized plane has never been in the evidence log. Stated in the package doc; a decision for the team.
3. **No contract change.** `normalization_version` and `derived_from` were in normalized-event since 1.0.0;
   the runtime now emits `derived_from` (only when version > 1, refusing a version without it). The lake
   layout and manifest have no schema (§3.5 of the audit lists every schema-less artifact).
4. **A correction is a new pack version from the same session** (`promote --pack-version 1.1`); the pack
   contract has no `supersedes` field and none was added — the link between pack 1.0 and 1.1 is the pack id
   and the lake manifest's reason string. If pack lineage should be first-class, that is parser-pack 1.4.0.
5. **Events that no longer route or parse under corrected packs keep their prior version** and are counted
   (`events_not_applicable`); a correction never deletes. Unchanged events get no v2.
6. **The runtime has a second parser call site** (`renormalize.go`). Invariant 6's static test was extended
   to hold it to the same rule — one `Parse`, on the routed family, after `RouteChain` — and to forbid any
   other file of the package from calling a parser.
7. **Pre-flight's pin has an escape hatch** (`ULPF_DEMO_NGL_UNPINNED=1`), loud in the output, because
   measurement runs need it; without it any value but 20 fails.
8. **Trace corrections (standing obligation).** Stage 13's lineage gains `derived_from` on corrected
   events and the trace has no stage for a correction at all: resolving a retained certificate after
   promotion → pack 1.1 → re-derivation from evidence → `normalization@v2`. Stage 8's certificate list is
   offload-dependent under a live model (pos_5 at 20 layers, pos_4 at 33); the trace's fixture list is
   neither. The verifier's Stage-14 wording should say a finding is a failure.
9. **Plan §11 rows 46–50**; plan header v1.7.

## 7. Tried and rejected

- **Deriving v2 from v1's JSON** — cheaper, and wrong: a correction would inherit the interpretation it
  corrects, and would run over tampered evidence without noticing.
- **Writing v2 for every event** — 92 byte-different copies saying the same thing; only changed content
  gets a version.
- **Sealing the version file up front** — left an empty v3 when a correction changed nothing; corrected
  events are collected first and a version exists only if there is something in it.
- **`t.Skip` when the tamper set-up cannot write** — the pattern under audit; it fails instead.
- **A measured analyst-minutes figure** — there is no measurement to report; counted decisions and a
  labelled assumption instead.
- **Fixing every audit finding** — about a fifth were fixed (the ones that let a demo or a verifier pass
  wrongly); closing the golden-regeneration hole changes how every phase check starts and deserves its own
  review.

## 8. Not done, and carried

- **Drift healing (item 4): not built.** How it would be shown is in the runbook ("Showing healing"):
  onboard the in-domain, unowned `%ASA-6-302015` family — a new L3 anchor value, so propagation cannot
  pre-empt it — and replay step 5; it needs a 302015 draft spec and a vendor-table row first. Re-running
  step 2 after a full run shows zero certificates, correctly: the store already holds the resolution.
- The replay mix, the coverage curve, drift monitors, review-interface polish: not built (cut with P8).
- **Owed by the team:** the ECS→OCSF crosswalk review (not self-reviewed); the three audit items in §2.
- **Unexercised on real data:** sequence-gap detection — no corpus vendor emits RFC 5424
  `meta sequenceId`; coverage is four synthetic lines.
- **The laptop has not run this commit.** Pre-flight will now fail there on anything the desktop run
  found (CRLF, offload split, empty completion); step 2 at 20 layers is the configuration it already used.
