# ULPF — Universal Log Pre-processing Framework (SIH 2026, PS 26156)

Two-stack build: **Go** runtime (`runtime/`), **Python** learning plane (`learning/`). Primary
development environment is WSL2 (Ubuntu). See `ulpf-implementation-plan.md` for the phased plan and
`ulpf-architecture.md` (kept by the team alongside this repo) for the specification.

## Layout

| Path | What |
|---|---|
| `contracts/` | The six frozen data contracts (JSON Schema 2020-12; four at P1 exit, the normalized event at P2 exit, the ML feature tuple at P6 exit; parser-pack 1.3.0 since P6), golden vectors, README with embedded decisions |
| `learning/` | Python learning plane: `ulpf_contracts` (contract validation) and `ulpf_learn` (induction, enumerator, acceptance engine, ambiguity analyzer, discriminator appliers, pack emission, review CLI, reference DSL executor); fixtures stand in for the model until P4 |
| `runtime/` | Go runtime: contract loader, DSL compiler/executor, framing (newline, RFC 6587 octet counting, UDP, TCP, HTTP, directory pull, multiline, de-batching, envelope chain), evidence store, routing DAG, normalizer, gap accounting, pipeline, CLIs (`cmd/ulpf-runtime`, `ulpf-committer`, `ulpf-verify`), Dockerfile |
| `ocsf/` | Pinned OCSF 1.3.0 class tables (`pinned/`) generated from the schema export, cross-checked against the schema source; tools in `tools/` |
| `library/` | Discriminator library v1 (data) |
| `acceptance/` | Per-class acceptance policy data (engine is P3) |
| `corpus/` | Corpus catalogue, licence verdict, fetch/inspection tools (fixture content is cached locally, never committed) |
| `drafts/sufficiency/` | Hand-drafted vendor specs for the DSL sufficiency check, plus the checker and its notes |
| `models/` | `manifest.json` pins every model (source, sha256); `cache/` is git-ignored — weights never enter git or a build context |
| `keys/` | Demo-grade ed25519 key files: `dev/` private dev authorities (fixtures), `trust/` the public-key trust store the runtime and verifier use |
| `spike/` | P4 spike: ground-truth cases (`cases/`) and measured results per machine (`results/<machine>/`) |
| `docs/` | Phase reports, the demo-laptop runbook |
| `scripts/` | WSL bootstrap and check scripts |

## Test fixtures are not vendored — deliberately

The reference corpus (Elastic Beats module test fixtures and logstash-patterns-core specs) is
**fetched at build time** by `corpus/tools/fetch_corpus.py` from commits and content hashes pinned
in `corpus/catalogue.json`, into the git-ignored `corpus/cache/`. The Beats fixtures are Elastic
License 2.0: fine to run tests against, not something to embed in a repository that may become
public — git history is permanent, and anything committed now would surface the moment visibility
changes. The Apache-2.0 fallback and the full reasoning are in `corpus/README.md`. The same applies
to the OCSF definition caches under `ocsf/cache/` (Apache-2.0, but 1.8 MB of reproducible data);
the derived pinned tables in `ocsf/pinned/` *are* committed with the source hashes they came from.

## Bootstrap and checks (WSL2)

```bash
bash scripts/wsl-bootstrap.sh      # Go toolchain under ~/sdk, Python venv under ~/.venvs/ulpf
bash scripts/wsl-run.sh python corpus/tools/fetch_corpus.py   # fetch + catalogue the corpus (needs network)
bash scripts/wsl-run.sh python ocsf/tools/fetch_ocsf.py       # fetch OCSF 1.3.0 export + source
bash scripts/wsl-run.sh python ocsf/tools/build_pinned.py     # regenerate pinned tables
bash scripts/run-crosscheck.sh     # independent completeness check of the pinned tables
bash scripts/p1-check.sh           # golden vectors + Python suite + Go suite (P1 exit)
bash scripts/check-drafts.sh       # DSL sufficiency drafts against the corpus (regex-level)
bash scripts/p2-check.sh           # P2 exit: build runtime, regenerate vectors, both suites, runtime tests
                                   # (golden span maps, adversarial specs, framing, evidence, kill-test,
                                   # corpus replay), container test stage + runtime image
```

Onboarding (the demo sequence — `scripts/p3-check.sh` runs it scripted):

```bash
cd learning
python -m ulpf_learn onboard --samples ../contracts/golden/squid-native/samples/access.log --source-id squid-proxy-01 --operator op-014 --session /tmp/s
python -m ulpf_learn certificates --session /tmp/s      # the ambiguity certificates, incl. the unresolved one
python -m ulpf_learn respond --session /tmp/s --discriminator device_logformat_configuration --input "logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt"
python -m ulpf_learn promote --session /tmp/s --out /tmp/pack --pack-id squid-native-emitted
python -m ulpf_learn review --session /tmp/s            # interactive form of the same loop
```

Model provider (P4). Weights are fetched into the git-ignored cache and digest-verified; the
learning-plane image bundles one verified model; `llama-server` is one CUDA build for `sm_75` and
`sm_120` (see `docs/demo-laptop-runbook.md` for the demo laptop):

```bash
bash scripts/fetch-models.sh                         # ~27 GB into models/cache, sha256-verified
bash scripts/build-llama-image.sh                    # ulpf-llama: llama-server, CUDA 12.8, sm_75+sm_120
bash scripts/p4-spike.sh desktop-5060ti gpu          # measure every model on THIS machine -> spike/results/<label>/
bash scripts/p4-check.sh                             # P4 exit: suites incl. op-coverage matrix, invariant 2, fixture path unchanged
python -m ulpf_learn onboard --provider model --model-id qwen3.5-4b-q4_k_m --server http://127.0.0.1:8080 --mode whole ...
DOCKER_BUILDKIT=1 docker build -f learning/Dockerfile --target learning --build-arg MODEL=qwen3.5-4b-q4_k_m --build-context models=models/cache -t ulpf-learning:qwen3.5-4b .
```

Evidence log (P5). Packs must be signed (`keys/trust` is the default trust store); the committer runs
as a separate unprivileged process over the store's volume; the verifier runs anywhere:

```bash
bash scripts/p5-keygen.sh                                     # build runtime, committer, verify; dev key pairs into keys/
bash scripts/p5-check.sh                                      # P5 exit: suites, signing fail-closed, invariant 2, boundary + witness (Docker), signed fixture demo
bash scripts/p5-boundary-test.sh                              # two containers: kernel immutable flag vs an unprivileged committer, tamper -> leaf named
bash scripts/p5-witness-test.sh                               # export a bundle; a fresh container with only ulpf-verify + public key verifies it
```

Multi-vendor routing (P6). Every onboarded source's pack is loaded into one runtime; the decision DAG
routes a mixed stream by envelope, surface structure, declared anchors and arity, never by trying parsers:

```bash
bash scripts/p6-check.sh                                      # P6 exit: suites (DAG, K cap, no-try-all, anchor admission, propagation), invariant 2, four-vendor build when the corpus cache is present
bash scripts/p6-build-packs.sh                                # onboard ASA/PAN-OS/FortiGate from the corpus cache, merge source packs, mixed stream + ML tuple, discovery, agreement (packs land in /tmp)
python -m ulpf_learn onboard-spec --samples S --spec drafts/sufficiency/asa-302013.json --vendor cisco-asa --family-id asa-302013 --unwrap-envelope --provider recorded --recording spike/results/... ...
ulpf-runtime run --pack A --pack B --source-id relay-01 --input mixed.log --evidence EV --out out.jsonl --quarantine q.jsonl --ml-out ml.jsonl
python learning/tools/discover.py capture.log                # family discovery ranking: clusters by the router's surface, ranked by volume
runtime/bin/ulpf-committer commit --evidence EV --commit EV/commit --key keys/dev/ulpf-committer-dev.json
runtime/bin/ulpf-committer daily  --evidence EV --key keys/dev/ulpf-committer-dev.json
runtime/bin/ulpf-runtime export --evidence EV --event-id ev_... --out bundle/
runtime/bin/ulpf-verify evidence --evidence EV --trust keys/trust    # recompute every root, check chain + signatures
runtime/bin/ulpf-verify bundle --bundle bundle/ --trust keys/trust    # the external witness's command
runtime/bin/ulpf-runtime run --pack P --listen udp::5514 --evidence EV --out -   # syslog UDP; envelope unwrapped after the raw write
```

Transports, framing breadth and gap accounting (P7). One runtime, any arrival: syslog over UDP/TCP (RFC 6587
octet counting with non-transparent fallback, bounded per connection), HTTP receive, a directory-drop
collector, one multiline mechanism, JSON-array de-batching (N independently hashed events), recursive
envelope unwrap (relay chain, CEF application envelope), and per-peer continuity: sequence gaps, silence
and connection loss become **gap records committed as evidence-log leaves**, listed and exported by the
verifier like any event:

```bash
bash scripts/p7-check.sh                                      # P7 exit: suites, invariant 7 under load (sized to this machine), named P7 tests, canned demos
bash scripts/p7-demo.sh                                       # octet-counted TCP capture; batched JSON drop; a silenced UDP source -> signed gap leaf -> witness
runtime/bin/ulpf-runtime run --pack P --listen tcp::6514 --idle-timeout 30s --max-conns 256 --evidence EV --out -      # RFC 6587 + newline fallback
runtime/bin/ulpf-runtime run --pack P --listen http::8514 --max-body-bytes 8388608 --evidence EV --out -                 # POST newline bodies or JSON arrays
runtime/bin/ulpf-runtime run --pack P --pull-dir /drop --evidence EV --out -                                             # files ingested in name order, renamed .done
runtime/bin/ulpf-runtime run --pack P --input app.log --multiline-start '^\d{4}-\d{2}-\d{2} ' --evidence EV --out -      # stack traces join their first line
runtime/bin/ulpf-runtime run --pack P --listen udp::5514 --silence-after 30s --evidence EV --out -                        # a peer quiet for 30 s -> silence gap record
runtime/bin/ulpf-verify gaps --evidence EV --trust keys/trust                                                            # every gap record with its checkpoint, root and signature verdict
```

Runtime CLI (after `go build -o runtime/bin/ulpf-runtime ./cmd/ulpf-runtime` in `runtime/`):

```bash
runtime/bin/ulpf-runtime verify-pack --pack contracts/golden/squid-native
runtime/bin/ulpf-runtime run --pack contracts/golden/squid-native --input contracts/golden/squid-native/samples/access.log --evidence /tmp/ev --out - --quarantine /tmp/q.jsonl
runtime/bin/ulpf-runtime reconstruct --evidence /tmp/ev --out /tmp/stream.log   # byte-exact original stream
runtime/bin/ulpf-runtime compile --spec drafts/sufficiency/asa-302013.json      # dsl_hash + parser_hash
```

From Windows, prefix commands with `wsl -d Ubuntu -- bash /mnt/c/<path-to-repo>/scripts/<script>.sh`.
