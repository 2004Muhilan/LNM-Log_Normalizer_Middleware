# P5 report — evidence log completion: Merkle commitment, the privilege boundary, signing, the witness

**Status: P5 exit criteria met; stopped for verification before P6.** Nothing from P6 was built. Track A
only: the model was not touched. Reproduce with `scripts/p5-check.sh` (WSL2, Docker Desktop running: the
boundary and witness tests are containers).

## 1. Demonstrable outcome — the theme demo

**Tamper one byte in a sealed segment → the verifier names the leaf.** Two containers over one ext4 volume:
the store (root, `CAP_LINUX_IMMUTABLE`) ingests the golden Squid lines, seals the segment and sets the
kernel's immutable flag on its three files through the ioctl; the committer (distroless `nonroot`, every
capability dropped, the evidence volume mounted **read-write**) recomputes the segment's Merkle root from
the raw bytes, refuses the OPEN segment by name, and writes a signed, hash-chained checkpoint into its own
volume. Then the committer's own uid tries to append to, truncate, rename, delete and un-flag the sealed
segment: **the kernel refuses every attempt**, and refuses root without the capability too; the same
process can still read the bytes. A process *with* the capability flips byte 5; the verifier, with only
the public key, reports `FINDING seg_00000: raw bytes of ev_…0001 do not match raw_hash — tampered leaf 0
(bytes 0..124)`. Then the export: one command produces a bundle (raw bytes, lineage record, inclusion
proof, signed checkpoint, signed daily root) and **a fresh container that has never run ULPF** — the
verifier binary, the bundle and the trust store, no network — verifies it, refuses it after one raw byte
is flipped, and refuses it without the authority's public key.

| Exit criterion | Result |
|---|---|
| **Privilege boundary is a real test** | `scripts/p5-boundary-test.sh`: store `--user 0 --cap-add LINUX_IMMUTABLE`; committer `--cap-drop ALL` uid 65532, evidence volume **rw**. Append, truncate, rename, unlink, `chattr -i`: all refused by the kernel (EPERM), read allowed. Root without the capability: append refused, cannot clear the flag. Not a mount option, not a flag check — `lsattr` shows `----i---` and the attempts fail against it |
| **Ordering test** | `TestOrderingRuleNeverCommitsAWritableSegment` (Go) and the boundary script: a segment without a seal manifest is refused `open: no seal manifest; the segment can still be written`; a sealed segment whose files do not carry the kernel flag is refused `sealed but not immutable`; with the real kernel check and no capability, **nothing is ever committed** — the committer commits only what the kernel has locked |
| **Export verifies on a machine that has never run ULPF** | `scripts/p5-witness-test.sh`: `ulpf-verify bundle` in a fresh distroless container (`--network none`, only the binary, the bundle and `keys/trust`): `VERIFY: OK — raw bytes match the record, leaf proof reaches segment root …, checkpoint ckpt_000001 signed by a trusted authority`; one flipped raw byte → `FINDING event.raw: raw bytes hash to … record says …`; empty trust store → refused |
| **Signing live, fail-closed** | `pack.Load` requires `pack.json.sig` (hex ed25519 over the exact bytes) by an authority in the trust store, before compiling anything. `TestPackSignatureFailClosed`: signed golden loads; no trust store, unknown authority, missing `.sig`, a contract-valid one-byte edit, a corrupted signature — all refused; `--allow-unsigned` loads and says `SIGNATURE NOT VERIFIED`. The learning plane signs at promotion; the golden pack is signed by `build_vectors.py`; every P2–P4 check script now passes the trust store |
| Tamper detection names the leaf | `TestTamperIsDetectedAndNamed`: one flipped byte in event 2 of a committed segment → `leaf 1 (event …)`; the untouched segment stays clean. Forged signature and edited checkpoint bytes → signature / chain / daily findings (`TestSignatureChainAndDaily`) |
| Merkle correctness | `TestRootAndProofsForEverySizeUpTo33`: every leaf's proof verifies and no other leaf's does, for every tree size 1–33 (unbalanced RFC 6962-style split, domain-separated leaf/node hashing) |
| **Envelope precedence** | `TestEnvelopePrecedence`: RFC 5424 wins over 3164 when both could match; a 3164 message whose payload is a 5424-looking line is unwrapped once and the inner header stays payload (and vice versa); a header with no payload is not an envelope; a Squid line is untouched; PRI out of range or malformed is not an envelope |
| Syslog UDP | `TestUDPDatagramsAreFramesAndEvidence`: datagrams are frames, every received byte is evidence (header included), the payload is routed and parsed, an unroutable datagram is quarantined **and retained**; `TestSyslogEnvelopeUnwrappedAfterRawWrite`: 3164- and 5424-wrapped Squid lines parse, lineage carries `envelope`, reconstruction returns the wrapped stream byte for byte |
| Contracts | parser-pack **1.2.0** (`provenance.proposal`, as approved) and normalized-event **1.2.0** (`_lineage.envelope`); 22/22 vectors both stacks; 45 learning tests; runtime suite green; invariant 2 green (three static binaries, 2.6 MB image) |

## 2. Deliverables

- `runtime/internal/merkle` — canonical leaf `H(0x00 ‖ "ulpf-leaf-v1" ‖ segment_id ‖ offset₈ ‖ length₄ ‖ raw_hash)`, node `H(0x01 ‖ l ‖ r)`, RFC 6962-style unbalanced trees, proofs.
- `runtime/internal/evidence` — seal writes `seg_N.seal.json` (content hashes) and sets `FS_IMMUTABLE_FL` on raw, index and manifest **through the kernel ioctl** (`immutable_linux.go`); the state is what the kernel did: `open | sealed | immutable`, never claimed. `SegmentState`, `Segments`, `ReadIndex` for the committer and verifier.
- `runtime/internal/keys` — ed25519 key files and the trust store; `runtime/internal/checkpoint` — `Commit` (roots for immutable, uncommitted segments; one signed minute checkpoint chained by `prev_checkpoint_hash`), `Daily`, `VerifyAll`, `LocateTamper`, `Export`/`VerifyBundle`.
- `cmd/ulpf-committer` (`commit | daily | keygen`), `cmd/ulpf-verify` (`evidence | bundle | locate`), `ulpf-runtime export`, `ulpf-runtime run --listen udp:…`; Dockerfile targets `runtime`, `committer`, `verify` (distroless, static).
- `runtime/internal/frame/syslog.go` (`Unwrap`, one level, precedence), `udp.go`; pipeline stage order now: raw write → unwrap → route → parse → normalize (`RunFrames` over any `Source`).
- Pack signing: `pack.LoadOptions{TrustDir, AllowUnsigned}`, `--trust`/`--allow-unsigned` flags; `learning/ulpf_learn/signing.py` (`cryptography`); `emit.py` signs and writes 1.2.0 with `provenance.proposal`; `build_vectors.py` signs the golden pack; `keys/` with `README.md`.
- Scripts: `p5-keygen.sh`, `p5-boundary-test.sh`, `p5-witness-test.sh`, `p5-check.sh`, `go-test-pack.sh`.

## 3. Findings and decisions

1. **The P2 store's `chattr` never ran in the runtime image.** The image is distroless: no `chattr`
   binary, so the P2 shell-out silently did nothing there. The flag is now set with the `FS_IOC_SETFLAGS`
   ioctl from Go. Found while designing the boundary test — the reason "real, not a flag check" was the
   right demand.
2. **The committer must own its output directory.** The first boundary run failed with `mkdir /ev/commit:
   permission denied`: the committer (uid 65532) cannot create anything under a root-owned evidence root,
   which is correct behaviour and a design fact — roots and checkpoints live in a directory the committer
   owns and the store never touches (`--commit`; two volumes in the test). Default for development
   remains `<evidence>/commit`.
3. **Busybox `chattr` exits 0 on failure.** The first test version judged "flag cleared" from the exit
   code and mis-reported; the test now checks `lsattr` after the attempt. Recorded because the wrong
   check would have passed a broken boundary.
4. **Immutable files cannot be removed by `docker volume rm`** either — the cleanup needs a capability
   container to clear the flags first. A pleasant proof that the flag is real.
5. **Signing needed no schema change**; 1.2.0 carries `provenance.proposal` (approved at the P4 boundary)
   and, on the event side, `_lineage.envelope`. Both additive; both validators accept 1.0.0–1.2.0.
6. **Contract before signature.** The loader validates the contract, then the signature; a tampered pack
   that also breaks the contract is refused by the contract first. Still fail-closed; the test tampers
   in a contract-valid way so the signature is what refuses.
7. **`ULPF_COMMIT_SEALED=1`** is the committer's development seam for shells that lack the capability
   (the WSL user cannot set the flag): it treats SEALED as committable and warns loudly. It exists so the
   witness test can run without Docker privileges for the store; the boundary test never uses it.

## 4. Agreement is an effort metric, not a correctness metric

Carried from the P4 boundary and stated here the way it reaches a slide: **the system is correct at any
agreement level; the model only moves the effort curve.** A mandatory attribute needs non-model
provenance regardless of what the model said (invariant 4), so a wrong label never ships — it becomes a
question the analyst answers, or a certificate the library resolves. P4's 0.66 agreement (Granite 4.1 8B,
Qwen3.5-9B) therefore means: two thirds of the slots need no analyst attention beyond confirmation; the
model saved that effort. It does not mean two thirds correct, because correctness is not the model's to
decide. P5 adds the other half of the same sentence: what the analyst confirmed is then signed, committed
and verifiable on a machine that never ran ULPF.

## 5. Raised, not absorbed — including trace corrections (standing obligation)

1. **Trace correction — signed pack.** Stage 12's pack now carries `pack.json.sig`, a `provenance.proposal`
   block, `schema_version 1.2.0`, and the runtime refuses an unsigned pack. The trace's Stage 12 shows the
   signing metadata only; it should say the signature is verified before load.
2. **Trace correction — lineage envelope.** When a line arrives inside a syslog envelope, Stage 13's
   `_lineage` gains `envelope` (kind, payload offset/length, header fields) and `offset/length` address
   the complete received bytes, not the payload. File-collected lines (the trace's case) are unchanged.
3. **Trace correction — the store's states.** IMMUTABLE is now what the kernel confirmed; without the
   capability a segment is SEALED and is never committed. The trace's §3.7 lifecycle wording should say so.
4. **Pipeline stats** gain `enveloped`; the runtime image now runs the store as root with
   `CAP_LINUX_IMMUTABLE` for the immutability path (documented in the Dockerfile) — the `nonroot` default
   stays for everything else.
5. **Recorded proposals on CPU** (P4 §4.4) is now enforceable: `provenance.proposal.backend` is in the pack.
6. **Dev private keys are committed** as fixtures (`keys/dev`, documented in `keys/README.md`) so the
   golden signature is reproducible from a clean clone. Demo-grade by decision; a deployment generates
   its own and ships only the public half.

## 6. What was tried and rejected

- **`chattr` via shell-out** — silent no-op in distroless; the ioctl instead.
- **Committer writing under the evidence root** — the kernel and ownership refuse it, correctly; its own
  directory instead.
- **Judging immutability by `chattr`'s exit status** — busybox lies; `lsattr` after the attempt.
- **A read-only mount as "the boundary"** — a mount option is a configuration, not an enforcement the
  committer cannot escape; the volume is mounted rw in the test on purpose and the kernel refuses.
- **Committing SEALED segments in production** — only under the loud development seam; the ordering
  guarantee is the kernel flag, or nothing.

## 7. What the next phase inherits

- **P6:** vendors arrive through syslog (`--listen udp:`) with the envelope unwrapped; the routing DAG
  routes on the payload. The `structure_from_spec` adapter and the per-slot mode are P6's interim tools.
  Packs are signed at promotion; P6's vendor packs must be signed by the dev authority or the loader
  refuses them.
- **P7:** recursive unwrap and relay chains extend `_lineage.envelope` (one level today); gap records
  become checkpoint leaves; TCP/octet-count framing.
- **P8:** the witness ceremony is scripted (`p5-witness-test.sh` is the shape of it); the daily root is
  the exportable artifact; `ulpf-verify` is the tool the second machine runs.
- **Laptop run** (P4) still owed before any latency figure.
