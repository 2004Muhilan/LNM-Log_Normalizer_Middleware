# Keys — demo-grade, file-based (plan §1 "Signatures")

Two authorities, two ed25519 key pairs, all JSON files:

| Path | Holds | Used by |
|---|---|---|
| `dev/ulpf-pack-authority-dev.json` | **private** seed + public key of the pack-signing authority | the learning plane signs `pack.json` (`learning/ulpf_learn/signing.py`; `build_vectors.py` signs the golden pack) |
| `dev/ulpf-committer-dev.json` | **private** seed + public key of the checkpoint committer | `ulpf-committer` signs minute and daily checkpoints |
| `trust/<authority>.pub.json` | public keys only — **the trust store** | the runtime (`--trust`, default this directory) verifies packs; `ulpf-verify` verifies checkpoints and bundles |

**Nothing private is committed.** `scripts/keys-bootstrap.sh` generates the two dev authorities locally
(idempotent; run by every `pN-check.sh` and by the clean-clone test) and re-signs the golden pack with the
local key: `pack.json` is byte-identical across clones, its `.sig` is local and git-ignored, as are
`dev/` and the dev `*.pub.json`. A deployment generates its own with
`ulpf-committer keygen --authority <id> --out <private> --pub <trust-store file>` and ships only the
`.pub.json` to the runtime. The `.sig` format is `<authority_id> <hex signature>`: the runtime verifies
the exact bytes against that authority **before** parsing the document, then requires the document to
name the same authority. The runtime refuses any pack whose authority is not in its trust store,
whose `pack.json.sig` is missing, or whose signature does not verify over the exact bytes of `pack.json`
(`--allow-unsigned` exists for development and prints a warning). Signatures are hex ed25519 over exact
file bytes; no canonical-JSON machinery anywhere.

Separation that matters for P5: the **store** holds `CAP_LINUX_IMMUTABLE` and no key; the **committer**
holds a key and no capability. Neither can do the other's job.
