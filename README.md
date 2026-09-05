# ULPF — Universal Log Pre-processing Framework (SIH 2026, PS 26156)

Two-stack build: **Go** runtime (`runtime/`), **Python** learning plane (`learning/`). Primary
development environment is WSL2 (Ubuntu). See `ulpf-implementation-plan.md` for the phased plan and
`ulpf-architecture.md` (kept by the team alongside this repo) for the specification.

## Layout

| Path | What |
|---|---|
| `contracts/` | The four frozen data contracts (JSON Schema 2020-12), golden vectors, README with embedded decisions |
| `learning/` | Python learning plane: `ulpf_contracts` (contract validation) and `ulpf_learn` (induction, enumerator, acceptance engine, ambiguity analyzer, discriminator appliers, pack emission, review CLI, reference DSL executor); fixtures stand in for the model until P4 |
| `runtime/` | Go runtime: contract loader, DSL compiler/executor, framing, evidence store, interim router, normalizer, pipeline, CLI (`cmd/ulpf-runtime`), Dockerfile |
| `ocsf/` | Pinned OCSF 1.3.0 class tables (`pinned/`) generated from the schema export, cross-checked against the schema source; tools in `tools/` |
| `library/` | Discriminator library v1 (data) |
| `acceptance/` | Per-class acceptance policy data (engine is P3) |
| `corpus/` | Corpus catalogue, licence verdict, fetch/inspection tools (fixture content is cached locally, never committed) |
| `drafts/sufficiency/` | Hand-drafted vendor specs for the DSL sufficiency check, plus the checker and its notes |
| `docs/` | Phase reports |
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

Runtime CLI (after `go build -o runtime/bin/ulpf-runtime ./cmd/ulpf-runtime` in `runtime/`):

```bash
runtime/bin/ulpf-runtime verify-pack --pack contracts/golden/squid-native
runtime/bin/ulpf-runtime run --pack contracts/golden/squid-native --input contracts/golden/squid-native/samples/access.log --evidence /tmp/ev --out - --quarantine /tmp/q.jsonl
runtime/bin/ulpf-runtime reconstruct --evidence /tmp/ev --out /tmp/stream.log   # byte-exact original stream
runtime/bin/ulpf-runtime compile --spec drafts/sufficiency/asa-302013.json      # dsl_hash + parser_hash
```

From Windows, prefix commands with `wsl -d Ubuntu -- bash /mnt/c/<path-to-repo>/scripts/<script>.sh`.
