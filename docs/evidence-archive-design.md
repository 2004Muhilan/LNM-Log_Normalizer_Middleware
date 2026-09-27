# Evidence archive and a bounded local evidence buffer — design (proposal, NOT built)

2026-09-27, laptop branch. The sponsor's decisions 2 and 3: ULPF is middleware and keeps only a short local evidence buffer;
a separate, required evidence archive holds raw evidence (CERT-In's 2022 Directions: logs of ICT systems for a rolling 180
days within Indian jurisdiction). This is the design sent for approval before building. Four points need a decision (§6).

## 1. What is shipped, and where

- **Unit:** a *committed* segment — its three files byte-exact (`seg_N.raw`, `seg_N.idx.jsonl`, `seg_N.seal.json`) — plus the
  commit tree's files that cover it (`segments/seg_N.root.json`, every `checkpoints/ckpt_*.json` + `.sig`, every
  `daily/day_*.json` + `.sig`). Never converted: Merkle leaves hash `segment_id ‖ offset ‖ length ‖ raw_hash`, and the
  proofs read the raw file at those offsets.
- **Archive layout** (a directory; later an object store with write-once retention — same keys):
  `<archive>/<store_id>/segments/seg_N.{raw,idx.jsonl,seal.json}` and `<archive>/<store_id>/commit/...` mirroring the local
  commit tree. `store_id` is new (§6.1).
- **Shipper:** a new `ulpf-archiver` loop (or a mode of the committer — §6.3). It copies each file to a temporary name,
  fsyncs, renames, then reads it back and compares SHA-256 with the seal manifest (segments) or with the local bytes
  (checkpoints). A matching read-back is the **receipt**, written locally as `archive/receipts/seg_N.json` (file hashes,
  archive location, time). For an object store the receipt is the store's returned checksum, not our own read-back.
- **Configuration slot:** `--evidence-archive DIR|URL`, separate from `--lake` and from every `--forward` (an analytics lake
  may sit where raw logs may not go). The demo points it at `$APP/evidence-archive`, a folder beside `$APP/lake`.
- **Required:** `ulpf-runtime run` refuses to start without it. `--dev-no-evidence-archive` overrides it and prints a loud
  warning at start and in the run's stats; every gap record written in that mode says the archive was disabled.

## 2. Segment lifecycle (local)

```
OPEN → SEALED → IMMUTABLE (kernel flag, where available) → COMMITTED (a signed checkpoint covers it)
     → SHIPPED (receipt for all three files AND for every checkpoint file covering it)
     → DELETABLE (shipped + grace period elapsed) → DELETED (local copy removed; the archive holds the only copy)
```

The minute checkpoints and the daily roots are never deleted locally until they are shipped. They are small (a few KB a
minute); after shipping they are kept locally too, because the committer's chain (`prev_checkpoint_hash`) and its "already
committed" check read them.

## 3. Delete conditions — all of them, never time alone

A local segment is deleted only when:
1. it is COMMITTED (a signed checkpoint lists its root);
2. a receipt exists for each of its three files, and the receipt's hashes equal the seal manifest's;
3. a receipt exists for every checkpoint file that lists it;
4. the grace period since the receipt has elapsed (`--evidence-grace`, default 15 min: recent "Prove it" lookups stay local);
5. no reader has it open for a proof in progress (a lease file per export).

Deletion clears `FS_IMMUTABLE_FL` (this needs `CAP_LINUX_IMMUTABLE`, which only the store holds — so the **runtime** deletes,
not the archiver), then unlinks the three files and records it in `archive/deleted.jsonl` (segment, time, receipt hash).
Nothing deletes an unshipped segment, whatever its age.

## 4. The hard cap (archive down)

- `--evidence-buffer-cap` (bytes of local segments not yet deletable). Alarm at a high-water mark (`--evidence-buffer-warn`,
  default 80 %): one `evidence_buffer_high` gap record, re-armed below half of it — exactly as the spool does.
- **At the cap: stop accepting, keep everything.** One `evidence_buffer_full` gap record, committed, written from a small reserve
  kept for records. Older evidence is never deleted to make room. When shipping resumes and space is freed below the mark, one
  `evidence_buffer_resumed` record states how long intake stopped and what each transport did meanwhile:
  - **HTTP receive:** 503 with `Retry-After`; nothing is accepted that is not written (the sender keeps it).
  - **TCP syslog:** stop reading; the kernel's receive window fills and the sender blocks or drops **on its side**.
  - **UDP syslog:** datagrams cannot be refused: they are read and discarded, and the count and bytes are recorded in the
    `evidence_buffer_full` / `_resumed` records. Their content is gone and is never parsed or delivered.
  - **Directory pull:** files stay in the drop directory.
- **Sizing formula** (documented beside the flag): `cap ≥ ingest rate × bytes per event × tolerated archive outage`. The
  measured 842 bytes per event at one billion a day (11,574 events/s) is 9.7 MB/s: **35 GB for one hour, 842 GB for a day**.
  This is the same shape as the spool's `rate × tolerated outage`.

## 5. Reading from the archive — "Prove it", the verifier, export

- **One lookup in `internal/evidence`:** `Open(store_id, segment_id, file)` returns the local file if present, else the
  archived file after checking it against the seal manifest's hash (and the manifest against the committed segment root).
  Every reader below goes through it instead of `os.ReadFile(dir/…)`:
  - `export`, `ulpf-verify evidence|locate|gaps`, `reconstruct`, `renormalize` (invariant 8 corrections re-derive from raw);
  - `demo/apps/trace.py` ("Prove it"), `demo/apps/system.py`'s raw lookups, `learning/tools/drift.py`.
- **Finding an event by id** (today: a scan of every local index) uses a small local catalogue, `event_id → segment_id` per
  committed segment, kept forever (about 40 bytes per event). Otherwise, a lake row's `segment_id` + `offset` + `raw_hash`
  (+ `store_id`) addresses the archive directly.
- **"Prove it"** on a deleted segment:
  1. fetch the raw file, index and seal from the archive;
  2. re-hash the event's bytes;
  3. rebuild the leaves;
  4. verify the Merkle path to the segment root, the checkpoint root and the signature.

  The page says "from the archive" rather than "from the local buffer".
- **`ulpf-verify evidence`** verifies against the archive when the local copy is gone, and reports locally held and archived
  segments separately. A segment missing from both places is a finding, as it is today.
- **What protects what, stated plainly:**
  - P5's kernel immutability protects **only the local buffer**.
  - In the archive, protection is the Merkle proofs and the signed checkpoints: any change is detected, not prevented.
  - Prevention there needs write-once storage (object lock or WORM), which the deployment supplies. The demo's folder has
    none.

## 6. Conflicts and decisions — raised, not absorbed

1. **Segment ids are not globally unique.** `seg_00000` restarts per evidence directory, and after every local segment is
   deleted the store would restart numbering. The committer's "already committed" check and export/gaps match by bare segment
   id. Needed:
   - a **`store_id`**, generated once per evidence directory and kept in a file there;
   - archive keys under it;
   - segment numbering continued from the archive's highest number, never from zero.

   Lake rows and SIEM documents cannot say which store a `segment_id` belongs to, so `_lineage` needs a `store_id`: an
   additive change to the normalized-event contract (a minor version). **Your decision: accept the contract change?**
2. **Deletion needs the capability to clear the immutable flag.** Only the store holds it, and P5 kept the store unable to
   sign and the committer unable to alter evidence. Proposal:
   - the runtime (store) deletes;
   - the archiver/committer ships, with no capability.

   The immutable flag, set in P5, is then cleared by the same privileged process that set it, only under the §3 conditions.
   **Confirm this is acceptable.**
3. **The committer becomes a continuously running service.** Today it runs only on demand ("Prove it", step 6). A segment must
   be committed before it can be shipped and deleted. Proposal: `ulpf-committer commit --every 10s` runs always, with
   shipping added as `--archive DIR`, keeping one unprivileged process that reads evidence and holds the signing key.
   **Or a separate `ulpf-archiver`: your choice. I recommend adding it to the committer.**
4. **"Stop accepting" cannot be uniform** (§4). UDP cannot be refused. Its datagrams at the cap are counted and discarded
   (recorded, never parsed or delivered). **Accept that for UDP, or require UDP to be relayed through TCP in deployments?**

Not a conflict, but noted: the demo runs unprivileged, so its segments stay SEALED, not IMMUTABLE, and its committer runs with
`ULPF_COMMIT_SEALED=1`. Deletion in the demo therefore just unlinks, and the demo labels this.

## 7. Tests that would prove it (when built)

- Archive down: the buffer fills, the alarm fires, intake stops at the cap. Nothing is deleted, every received event is in
  the evidence, and nothing downstream lacks evidence.
- Archive back: segments ship, receipts match, deletion occurs only after the grace period, and intake resumes with one
  `_resumed` record.
- Segments are never deleted if unshipped, if a receipt hash mismatches, or if uncommitted.
- "Prove it" and `ulpf-verify` work on a segment deleted locally. A byte changed in the archive fails the proof.
- `ulpf-runtime run` without `--evidence-archive` exits non-zero. With the development override it runs and warns.
