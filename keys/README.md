# Keys — demo-grade, file-based (plan §1 "Signatures")

Two authorities, two ed25519 key pairs, all JSON files:

| Path | Holds | Used by |
|---|---|---|
| `dev/ulpf-pack-authority-dev.json` | **private** seed + public key of the pack-signing authority | the learning plane signs `pack.json` (`learning/ulpf_learn/signing.py`; `build_vectors.py` signs the golden pack) |
| `dev/ulpf-committer-dev.json` | **private** seed + public key of the checkpoint committer | `ulpf-committer` signs minute and daily checkpoints |
| `trust/<authority>.pub.json` | public keys only — **the trust store** | the runtime (`--trust`, default this directory) verifies packs; `ulpf-verify` verifies checkpoints and bundles |

The `dev/` private keys are committed **as test fixtures for the development authorities only** so the
golden pack's signature and the suites are reproducible from a clean clone. They are not a production key
ceremony and must never be reused outside this repository's tests and demo; a deployment generates its
own with `ulpf-committer keygen --authority <id> --out <private> --pub <trust-store file>` and ships only
the `.pub.json` to the runtime. The runtime refuses any pack whose authority is not in its trust store,
whose `pack.json.sig` is missing, or whose signature does not verify over the exact bytes of `pack.json`
(`--allow-unsigned` exists for development and prints a warning). Signatures are hex ed25519 over exact
file bytes; no canonical-JSON machinery anywhere.

Separation that matters for P5: the **store** holds `CAP_LINUX_IMMUTABLE` and no key; the **committer**
holds a key and no capability. Neither can do the other's job.
