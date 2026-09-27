# Parser Transparency Log, Proof of Derivation, and the BSA §63(4) draft (laptop branch, 2026-09-27)

"Prove it" showed that an event's raw bytes were not altered. This shows **which parser made the event and that it made
exactly the event the SIEM holds**. It rests on two new pieces:
1. a **Parser Transparency Log**, in which every pack is logged before any runtime may load it;
2. **Proof of Derivation**: the logged pack re-run on the committed raw bytes, checked offline.

The draft certificate under Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 packages the result for an expert.
Nothing here has been verified on the laptop.

## 1. The Parser Transparency Log

- **What is logged.** Every parser pack ULPF may load, however it was produced:
  - hand-written: the golden pack, logged by `scripts/keys-bootstrap.sh`;
  - vendor-onboarded: the three vendor packs, logged by `scripts/p6-build-packs.sh`;
  - onboarded, or auto-healed: packs promoted by the console.

  The log is append-only, separate from the evidence log. Signing and logging are one act (`ulpf_learn.signing.sign_pack`
  → `ulpf-tlog append`), so an auto-healed pack is logged **before** it is activated. The same bytes are logged once.
- **What the runtime enforces.** It refuses any pack without a valid inclusion proof. The check is inside `pack.Load`,
  the single loader, right after the signature and before anything parses the pack.
  - Every loading path goes through it: startup, hot reload (SIGHUP), and auto-heal (a hot reload).
  - No option turns it off: `--allow-unsigned` skips the signature, not the log.
  - Tests:
    - `TestEveryPackLoadGoesThroughTheTransparencyCheck` fails if anything outside the pack package constructs a pack;
    - `TestUnloggedPackIsRefusedAtStartupAndOnReload` runs the real binary through both paths.
- **Formats — the open C2SP ones:**
  - **Tree:** RFC 6962 / RFC 9162 (SHA-256, leaf prefix 0x00, node prefix 0x01), with inclusion and consistency proofs.
    `TestMerkleProofsExhaustive` checks every proof for trees of 1–40 leaves.
  - **Checkpoints:** `c2sp.org/tlog-checkpoint` (origin, size, root) as `c2sp.org/signed-note` (Ed25519, key id =
    SHA-256(name ‖ 0x0A ‖ 0x01 ‖ key)[:4]). The log's origin is its key name, `ulpf-tlog-dev`.
  - **Pack proofs:** `c2sp.org/tlog-proof@v1`, beside the pack as `pack.json.tlog-proof`. The `extra` line carries the log
    entry, whose hash is the leaf, so a proof verifies **fully offline**, which suits air-gapped sites. The entry:
    `ulpf-pack-entry/v1`, pack id, version, the sha256 of the exact `pack.json` bytes, `produced_by`, `signed_by`, `logged_at`.
  - **Verifier keys:** `*.vkey` files in the trust store: `name+keyhash+base64(type‖key)`.
- **Consistency.** The log only grows:
  - Before signing a new checkpoint, the log verifies the new tree is a consistent extension of its last checkpoint.
  - The **witness** (`ulpf-witness`, a separate process) cosigns a checkpoint only after verifying a consistency proof from
    the last checkpoint it cosigned (`c2sp.org/tlog-witness` add-checkpoint, `c2sp.org/tlog-cosignature`). Its answers:
    - 409 with its size when the log is behind;
    - 422 when the history was rewritten;
    - 403 when the checkpoint is not signed by the log.
  - `TestWitnessRejectsAnInconsistentCheckpoint` builds a fork (the same origin and key, another history), and the witness
    refuses it with 422.
  - **The witness in the demo runs on the same machine as the log: it stands in for an independent site.** Real
    deployments put witnesses on separate machines, under separate operators.
- **Witness policy.**
  - The runtime requires the log's signature and the inclusion proof.
  - Witness cosignatures are verified and reported when present.
  - `--tlog-min-witnesses N` makes N required. The default is 0, because packs logged while no witness ran (the bootstrap,
    the gate's other lanes) carry none.
  - The demo witness cosigns every checkpoint signed while it runs, and cosigns the latest one at start.
- **The demo moment.** On the System page, *Push an UNLOGGED pack to process N* sends one process a pack that is validly
  signed and contract-valid, but not in the log.
  - That process refuses it, and the running packs stay.
  - The refusal is a `pack_refused` record in that process's evidence log, shown on the page.
  - A startup refusal (a pack given on the command line) stops the runtime before its evidence store opens. It is on
    stderr, not in the evidence log.
- **The parser history** (System page): every entry, with its index, pack, version, how it was produced and when it was
  logged, plus the checkpoint and who signed it.

## 2. Proof of Derivation

`ulpf-runtime derive` builds **one** file; `ulpf-verify derivation --bundle FILE --trust keys/trust` checks it with no
network and no ULPF running. The verifier has the same deterministic engine compiled in.

**What the bundle holds:**
- The raw bytes, and the segment's whole index file. Its sha256 is in the signed checkpoint's segment root, so the event's
  own record — event id, ingest time, channel, framing — is committed, not merely asserted.
- The Merkle leaf, the proof, the segment root, and the checkpoint with its signature.
- The **exact pack**: the one the event's `_lineage.parser_sha256` names, from the log's content store (`tlog/packs/<sha256>/`),
  with its transparency proof.
- The engine version, the expected output (the event as the SIEM holds it), and the hashes of the reference data the pack
  is loaded against (the contract schemas, the pinned OCSF index).

**What the verifier checks, in three parts, naming the first that fails:**
- **raw bytes:**
  - they hash to the record;
  - the record is in the committed index;
  - the Merkle proof reaches the committed root;
  - the checkpoint signature verifies.
- **pack:**
  - it is the entry its inclusion proof names;
  - the SIEM document names this exact pack;
  - it loads through the same fail-closed loader: signature, log, contract, compiled parsers.
- **SIEM document:** the pack, re-run on the raw bytes (unwrap, route, parse, normalize, exactly as the runtime does),
  reproduces the document **field for field**. Otherwise the report lists the differing fields.

**The comparison is on a canonical form** (both JSON documents parsed; nested fields compared by dotted path). **Excluded:
one field, `_lineage.processing_time`.** It is the wall-clock moment the runtime normalized the event. It records *when*,
not *what*, and no re-run can reproduce it. Everything the runtime assigns at ingest is compared, not excluded:
- event_id, ingest_time, collector_id, ingest_channel;
- segment_id, offset, length, raw_hash, framing, store_id.

These are inputs taken from the committed evidence record. `store_id` is the one input not covered by a signature: it
names the evidence directory.

**Tests** (`runtime/internal/derivation`):
- all six golden events are reproduced;
- a changed raw byte is named *raw bytes*;
- a changed byte of the pack is named *pack*;
- a changed SIEM field is named *SIEM document*, with the field (`src_endpoint.ip`);
- the excluded field alone never fails;
- a changed `ingest_time` is caught.

**In the demo,** *Prove it* adds a *Proof of Derivation* step, with a download of the bundle.

**Contract:** normalized-event **1.6.0** adds `_lineage.parser_sha256`, additive and optional. The id and version alone can
name more than one logged pack: a re-run of onboarding logs new bytes under the same id and version.

## 3. The BSA §63(4) certificate — a draft for people to complete

From the *Prove it* view: *BSA §63(4) certificate — DRAFT, print* (`/certificate?id=…`), a printable page.

- **Part A is pre-filled from what ULPF knows:**
  - the record (its bytes, size and receipt time);
  - the source device from the inventory (name, vendor, product, source id), with the sender's address and the connector;
  - the ULPF process and evidence store that received and kept it;
  - how it was produced and kept (evidence written and made durable before interpretation, sealed, Merkle-committed under
    a signed checkpoint, shipped to the archive);
  - the hash algorithm (SHA-256) and the hash values.
- **Left blank:** the declarant's name and capacity, the affirmation that the device was in lawful control and operating
  properly, the signature, date and place. A person affirms those; software cannot.
- **Part B (the expert's certificate) is left blank.** An expert must review, complete and sign it. Nothing is
  auto-signed, and the page says on every sheet that it is NOT COMPLETE without those signatures.
- **A technical report for the expert** follows:
  - the evidence chain (every step of the trace);
  - the derivation (the pack, its log entry and witnesses, the engine, the excluded field and why);
  - how to verify offline;
  - the limits: development keys, a witness on the same machine, a development commit mode, and an archive without
    write-once storage.
- **A plain note: this is not legal advice.** The Part A / Part B structure follows the Schedule to the BSA as its authors
  understand it; check the official text before relying on it.
