# Throughput — "billions of events per day", measured (2026-09-27, re-measured with group commit)

The problem statement says the framework must be suitable for billions of events per day. One billion a day is
**11,574 events per second** on average. This is where ULPF is, on one machine, measured.

**The answer in one paragraph** (details in the sections below).
- **One process, end to end** — ingest, the evidence log, the archive, OpenSearch and the Parquet lake, all on one
  8-core desktop — does **2.7–3.1k events/s**, both destinations acknowledging.
- **Four processes on the same ports, with 8 senders,** reach **5,269/s**: 0.46 billion a day, extrapolated. Every row is
  in Parquet at 3,233/s.
- **Every run in the scaling matrix was exactly-once and kept each sender on one process.**
- **The limit is the machine's CPU,** shared by everything: about 1.5 ms of CPU per event in all. One billion a day on
  average is therefore about **17 cores of this kind (extrapolated)**, which means more than one machine. Scaling across
  machines was not measured.
- **Parse alone** does 10.4k/s per process.
- **The lake writer** was profiled and fixed: 1,660 → 4,448 events/s.
- Nothing here was measured on the laptop.

**Machine:**
- AMD Ryzen 7 2700X, 8 cores / 16 threads, 25 GB visible to WSL2 (kernel 6.6.87.2), Windows 11.
- Evidence, spool and lake on the WSL2 ext4 virtual disk.
- OpenSearch 2.19.2 in Docker Desktop (512 MB heap, security plugin disabled). Go 1.27.1.
- Commit `b3eb8bf` plus group commit (this change). Runtime defaults `--commit-events 256`, `--commit-wait 10ms`.

**Input:**
- The four-vendor mixed capture: Cisco ASA, Palo Alto PAN-OS, FortiGate and Squid behind a syslog relay.
- It keeps the adversarial and not-onboarded lines it was built with: 98 distinct lines, 9 % quarantined.
- It is repeated to the sample size. Routing across four packs is part of what is measured; the content repeats, which a real
  stream would not.

**Method:** every measurement runs three times; the **median** is reported with the three runs beside it. Harness:
`scripts/bench/throughput.py`; raw results: `docs/metrics/throughput.json`.

"Per day" below is an **extrapolation**: the measured rate held for 24 hours, with the same mix, no peaks and the same
hardware. Real traffic has peaks several times its average: size for the peak, not the average.

## Invariant 3, as amended: group commit

**No event is parsed or delivered until the batch containing its raw bytes is durable on disk** (sponsor decision,
2026-09-27; plan §2 row 3, §11 row 65).
- **How a frame is committed:** it is hashed and staged. A batch is committed when it reaches 256 frames or its oldest
  frame has waited 10 ms, whichever comes first. The commit is one write plus an fsync of the segment and one of the index.
  Only then are the batch's frames routed, parsed, normalized, spooled and delivered, in arrival order.
- **On a crash:** only frames received and not yet committed are lost, and none of them was parsed or delivered.
- **What stays durable before the next step:** gap records and every other annotation, as before.
- **Commits forced before other steps:** a reload, a closed connection and a silence sweep commit what is staged first. So a
  `pack_activated` leaf still precedes every event interpreted under the new pack.
- **HTTP receive:** answers 202 only after the commit.
- **Tests:**
  - the kill-test: death after a committed batch leaves every committed frame byte-exact and only earlier batches in the output;
  - a property test: nothing is written downstream while a frame is staged;
  - a lone frame is committed within the wait;
  - HTTP 202 follows the commit, and a failed commit answers 503.

## The numbers

| # | what | sample | events/s (median; runs) | events per CPU-second | CPU / memory | per day (extrapolated) |
|---|---|---|---|---|---|---|
| 1 | **parse**: framing → route → parse → normalize → JSON; no evidence, no egress; 1 process | 196,000 | **10,431** (10,431 · 10,681 · 10,412) | 10,125 | 1.0 core; 127 MB | 0.90 billion |
| 1 | parse, 4 processes | 784,000 | **37,514** (37,514 · 36,929 · 38,093) | 9,150 | 4.1 cores; 127 MB each | 3.24 billion |
| 1 | parse, 8 processes | 1,568,000 | **62,289** (62,661 · 62,289 · 61,417) | 7,611 | 8.2 cores (SMT) | 5.38 billion |
| 2 | **with the evidence log** (the real binary, group commit, 256 frames per commit); ext4 | 89,061 | **5,232** (5,373 · 5,138 · 5,232) | 3,978 | 1.3 cores; 130 MB | **0.45 billion** |
| 2b | the same with the evidence on tmpfs (the fsync cost removed, to isolate it) | 89,061 | 6,528 (6,576 · 6,528 · 6,488) | 4,066 | 1.6 cores | 0.56 billion |
| 2c | **before**: an fsync per event (`--commit-events 1`, as built until today), same commit, ext4 | 6,000 | 195 (139 · 195 · 265) | 1,400 | 0.14 core busy | 16.8 million |
| 3 | **into OpenSearch through the bulk sink** alone (`ulpf-runtime forward`, 100 documents per request) | 151,451 | **3,799** (4,311 · 3,792 · 3,799) | OpenSearch: 2,580 per OS CPU-second | forwarder 10.8 CPU-s; OpenSearch 58.7 CPU-s, 1.76 GB peak | 0.33 billion |
| 3b | into the **Parquet lake** alone (the lake writer, 100-event batches) | 151,451 | **1,670** (1,670 · 1,688 · 1,633) | 599 | ~2.8 cores (DuckDB is multi-threaded); ~1 GB | 0.14 billion |
| 4 | **end to end**: ingest → evidence (ext4, group commit) → spool → OpenSearch AND the lake, until both acknowledged every event | 200,000 | **1,507** (1,551 · 1,507 · 1,501) | — | runtime 75.7, lake writer 348, OpenSearch 49 CPU-s; OpenSearch 1.79 GB | 130 million |

In every end-to-end run OpenSearch held exactly the 181,634 normalized events and the lake the same 181,634 rows, with 0
rejected. **OpenSearch acknowledged the last event at 56–62 s; the lake at 126–130 s.**

Before group commit (the previous measurement, same machine, commit `a56cc87`): evidence 215/s, end to end 143/s.

## What it says

- **Group commit moves the evidence log from 195 to 5,232 events/s per stream: 27×.** It now runs at 80 % of the tmpfs figure,
  so the disk is no longer what limits it. The limit is CPU: 3,978 events per CPU-second on the evidence path, against 10,125
  for parse alone. The extra cost per event is:
  - the SHA-256 of the raw bytes;
  - the index record as JSON;
  - the normalized output and the quarantine record;
  - the continuity accounting.
- **Cores for one billion a day with the evidence log on:**
  - 11,574 ÷ 3,978 = **2.9 cores on average, as about 2.2 runtime processes of this speed**;
  - with a peak factor of 3, about 9 cores (7 streams).

  Parse alone needs 1.1–1.3 cores (11,574 ÷ 9,150–10,125); about 4 at a 3× peak. The runtime is one stream per process, so
  "more cores" means more runtime instances, sharded by source or listener. Several streams writing evidence to one disk
  at once was not measured.
- **End to end is now 1,507/s (10.5× the 143/s before), and the lake writer sets it.**
  - OpenSearch received everything in less than half the time.
  - The lake writer alone does 1,670/s, and end to end is 90 % of that. Its cost is per FILE: the fixed schema from the pinned
    tables (~3,600 schema elements) is written per file, and a flush writes one file per (class, event day). This corpus
    spans 9 event days: 162 files for 151,451 rows alone, 225–234 end to end.
  - At one billion a day it needs ~7 writers, or larger files and a faster writer.
  - OpenSearch through one bulk forwarder does 3,799/s, so about 3 forwarders for 11,574/s; not measured.
- **The runtime's own CPU end to end is 75.7 CPU-s for 200,000 events**, against ~50 for the evidence path alone at the same
  count. The difference is the forwarders polling and re-reading the spool: a directory listing and a file open per poll per
  destination. This is an optimisation target, not a ceiling at these rates.

## Scale-out across processes, end to end with the evidence archive on (2026-09-27)

**Harness:** `scripts/bench/scale.py`; raw results in `docs/metrics/scale.json`. The first run is kept in
`~/ulpf-bench/scale-run1.json`; it is not used, because its timing favoured several processes (below).

**Setup.** P runtime processes share one TCP port with SO_REUSEPORT. Each has:
- its own evidence store, **with the archive on**: a committer per store every 2 s, shipping to one shared archive, and
  deletion after a 10 s grace;
- its own spool;
- a bulk forwarder into the one OpenSearch;
- its own lake writer (1,000-event batches, production rotation), all writing into one lake root.

**Senders.** G independent generators: separate processes, each sending from its own address (127.0.0.10+g) over one TCP
connection. Together they send 120,000 events per run: the 89 parseable lines of the four-vendor capture (the 9
quarantined lines left out, so every event is expected in both destinations), repeated.

**Three times per run, all measured from the first byte sent:**
- **both acknowledged**: every event is in the SIEM, and durably staged by the lake writer (its acknowledgement point);
- **SIEM**: when the SIEM alone had every event;
- **in Parquet**: when every row was also written to a Parquet file.

The first run of the matrix measured only *both acknowledged*. With one process, the lake's conversion to Parquet happened
during the run, because the staged bytes passed the rotation size. With several processes, each writer staged less and
converted after the clock stopped. That favoured the multi-process numbers, so the matrix was run again, timing each point.

**Checked in every run:**
- **exactly-once**: events generated = SIEM documents = lake rows = distinct lake event ids = evidence records;
- **affinity**: every sender's events were all handled by one process, read from every store's evidence, local and archived.

**Both held in all 36 runs.** Machine: the Ryzen 7 2700X (8 cores / 16 threads), with everything on it: OpenSearch (one
node, 512 MB heap), the runtimes, committers and lake writers, and the Python generators.

| events/s, median of 3 (the three runs) | 1 generator | 2 generators | 4 generators | 8 generators |
|---|---|---|---|---|
| **1 process** — both acknowledged | 2,740 (2,429 · 2,740 · 2,741) | 2,912 (2,695 · 2,933 · 2,912) | 2,801 (2,744 · 2,879 · 2,801) | 3,104 (3,184 · 2,633 · 3,104) |
| 1 process — in Parquet | 2,138 | 2,245 | 2,167 | 2,381 |
| **2 processes** — both acknowledged | 2,788 (2,770 · 2,946 · 2,788) | 4,755 (5,089 · 2,817 · 4,755) | 3,117 (2,767 · 3,117 · 4,592) | 3,174 (3,174 · 4,276 · 3,069) |
| 2 processes — in Parquet | 2,215 | 2,907 | 2,448 | 2,421 |
| **4 processes** — both acknowledged | 2,665 (2,665 · 2,652 · 2,707) | 4,101 (4,679 · 4,024 · 4,101) | 4,181 (4,432 · 4,115 · 4,181) | **5,269** (3,476 · 5,823 · 5,269) |
| 4 processes — in Parquet | 2,077 | 2,681 | 2,721 | **3,233** |

**What it says.**
- **One process with the evidence log, the archive and both destinations on does 2.7–3.1k events/s end to end.**
  - Extrapolated: 0.24–0.27 billion a day acknowledged, 0.18–0.21 billion until Parquet.
  - The parse path alone (above) is 3.6× that. The difference is the rest of the path on the same machine: evidence, the
    spool, the forwarders, the archive's committer, OpenSearch and the lake.
- **More processes help only as far as the kernel spreads the senders.** It hashes each connection, so a few senders
  spread unevenly:
  - two senders on two processes landed on the same process in one run of three;
  - four senders on two processes landed all on one process in one run;
  - **one sender always stays on one process.**

  The best cell, 4 processes and 8 senders, reached **5,269 events/s both acknowledged (0.46 billion a day extrapolated)
  and 3,233/s in Parquet (0.28 billion)**.
- **The limit is the machine.** At 4 processes × 8 senders, one run of 120,000 events cost:
  - 69 CPU-s in the runtimes (1,740 events per runtime CPU-second, including forwarding and archiving);
  - 43 CPU-s in OpenSearch;
  - the lake writers' conversion (1,969 events per CPU-second, measured alone);
  - 3 CPU-s in the committers.

  About 1.5 ms of CPU per event in all. **One billion a day on average is therefore about 17 cores of this machine's kind**
  (an extrapolation, before any peak factor), plus a second OpenSearch node. The design is one stream per process and N
  processes per machine, so that is several machines of this size. Scaling across machines was **not measured**.
- **Disk:** the largest run peaked at 629 MB of run files: evidence, archive, spool, lake and index.

### Process death

Setup: 2 processes, 4 generators each sending 500 events/s (2,000/s in total, below capacity), 120,000 events. The process
holding the most connections was killed with SIGKILL at 40 % of the stream.
- **The senders moved.**
  - All four were on process 1, which was killed at 24.5 s.
  - Each saw its connection reset, reconnected once (a new source port), and the kernel placed it on process 2.
  - **Their per-source state on process 2 starts fresh**: sequence-gap counters, silence tracking and the peer binding.
    The console's drift detection is keyed by the sender's address and does not move, but the runtime's per-peer
    continuity does.
- **What the dead process had accepted.**
  - It had committed 49,056 events to its evidence store; 556 of them were not yet delivered.
  - Restarted on its own evidence and spool, it resumed both cursors and delivered them.
  - It also **recovered 256 frames** (one batch) that it had committed to its evidence log and never interpreted: the
    crash fell between the commit and the interpretation. They were interpreted before any new intake, with their original
    ids, and recorded as `interpretation_recovered` (new in this change: `TestRestartInterpretsWhatWasCommittedButNotInterpreted`).
- **Nothing accepted was lost or duplicated:** the 119,456 events accepted (committed to some evidence store) = SIEM
  documents = lake rows = distinct lake ids.
- **Lost in flight: 544 events** (0.45 %). The senders had handed them to their kernel, but no process ever committed them.
  They sat in socket buffers when the process died, or were staged but not yet committed (at most 10 ms). Plain TCP syslog
  has no application acknowledgement, so a sender cannot know.
  - **This grows with overload.** In the first run the senders offered 6,000/s against about 2,800/s, and 52,288 events
    were queued in socket buffers when the process died, all lost.
  - HTTP receive answers 202 only after the commit, so its sender keeps what was not accepted.
  - Strict deployments send over HTTP, or over a relay that keeps its own queue.

**Two limits, stated plainly:**
1. **One very busy sender cannot be split across processes.** One connection, one process: the kernel hashes the flow,
   and any other spread would break per-sender ordering and per-source state. A sender that outgrows one process needs
   several connections, or a relay that fans out.
2. **A sender that moves to another process starts there with fresh per-source state**, whether it moved because its
   process died or because it reconnected. The kernel hashes the connection, not the sender's address, so a new
   connection may land elsewhere.

**Disk during the scaling work.**
- The budget was 6 GB per run, with a 40 GB free-space floor on `/` and `/mnt/c`, checked every half second by the guard,
  which never tripped.
- Every run was bounded at 120,000 events and cleaned up afterwards: its directory, its archive and its OpenSearch indices.
- The largest run peaked at 629 MB. The matrix ran twice (72 runs, plus two death runs), writing about 40 GB in all, never
  more than 0.63 GB at a time.
- Free space on `/` was 969.9 GB before and after.
- **The WSL2 virtual disk grew 0.16 GB** over the whole batch — the matrix twice, the lake runs and three gate runs
  (75.884 → 76.04 GB). Docker Desktop's disk did not grow (84.65 GB).

**Directory pull** has no kernel to spread it. `--pull-shard i/N` makes process i take only the files whose source key
(the name before the first `_`) hashes to i. Every file of one source goes to one process, and no two processes read or
rename the same file (`TestPullShardsPartitionBySource`).

## The lake writer — profiled, then fixed (2026-09-27)

After group commit, the lake writer (1,670 events/s alone) set the end-to-end pace. It was **profiled before anything was
changed**: `scripts/bench/lake_profile.py`, in-process on 152,914 rows of the four-vendor capture's normalized output.

| Where the time goes | Seconds | Share |
|---|---|---|
| **Ingest:** 100-event batches, each with an fsync of the staging file and of the state (1,529 batches, ~12 ms each) | 17.9 | 39 % |
| **Grouping:** Python `json.loads` per row, grouped by (class, event day) | 4.9 | 10 % |
| **Conversion to Parquet** (9 files) | 23.7 | 51 % |

The conversion is dominated by the **wide write**:
- The same COPY writing only the lineage columns takes 3.5 s; the ~3,600-element schema costs the rest.
- **Every file pays a fixed ~0.45 s** (the fastest single COPY) to set up and write that schema.
- The benchmark run wrote 162 files, rotating every 30 s per class per event day, so the fixed cost alone was roughly
  73 s of its 92 s.

Both suspects were real, and they multiply: many small files × a fixed cost per file set by the width.

**Writer settings tried on the largest class** (142,604 rows, one file):

| Setting | Rows/s |
|---|---|
| zstd, as built | 10,424 |
| snappy | 9,136 |
| uncompressed | 9,716 |
| row groups of 1 M | 9,371 |
| **`preserve_insertion_order=false`** | **16,805** |

Row order inside a lake file carries no meaning here: exactly-once rests on the spool high-water marks and the file names.

**Fixed:**
- **Production rotates on size**: 128 MiB staged, or 5 minutes at most. The demo keeps its 10-second rotation on the
  command line.
- **DuckDB no longer preserves insertion order** inside a file.
- **ULPF sends the lake 1,000-event batches** (`?batch=1000` on the destination URL; an fsync pair per batch, the same
  acknowledgement rule).
- **One lake writer per ULPF process**, all into one lake root (`--writer-id`).
- **The full fixed schema is kept**, as decided.

**Before and after, the same 152,914 rows, three runs each** (`scripts/bench/lake_bench.py`, `docs/metrics/lake-bench.json`):

| | Events/s (median; runs) | Files | Lake writer CPU-s | Events per CPU-second | Parquet / JSONL |
|---|---|---|---|---|---|
| before (100-event batches, 8 MiB / 30 s rotation, order preserved) | **1,660** (1,598 · 1,869 · 1,660) | 162 | 261 | 586 | 24.0 % |
| after | **4,448** (4,664 · 4,434 · 4,448) — **2.7×** | 18 | 78 | 1,969 | **4.8 %** |

Acknowledged ingest after the fix (every batch staged and fsynced) runs at 8,224/s; the conversion is the rest. Fewer,
larger files also compress far better: Parquet is 4.8 % of the JSONL.

## Efficiency of the integrations (requirement g)

| | figure | from |
|---|---|---|
| events per second into OpenSearch through the bulk sink | **3,799/s** median (one forwarder, 100 documents per request) | run 3 |
| OpenSearch cost | 2,580 documents per OpenSearch CPU-second (3,700 end to end); 1.76–1.79 GB peak with a 512 MB heap | runs 3, 4 |
| OpenSearch index size | **659 bytes per document** (618–654 end to end), 0.34 of the same event as JSON (1,919 bytes) | runs 3, 4 |
| **Parquet lake vs the same events as JSONL** | **24.7 %** (4× smaller; 151,451 events, 162 files) | run 3b |
| the same, end to end (more, smaller files: 225–234) | 28 % (98 MB vs 348 MB for 181,634 events) | run 4 |

## Disk per million events (sizing)

| what | per million events | retained? |
|---|---|---|
| evidence log (raw bytes + index) | **0.84 GB** (844 bytes per received event) | yes, locally today; see `docs/evidence-archive-design.md` for the bounded buffer and the archive |
| normalized JSONL in the spool | **1.92 GB** per million normalized (1,919 bytes each) | transient: freed as destinations acknowledge (bounded by the cap) |
| OpenSearch index | **0.62–0.66 GB** per million normalized | yes, in the SIEM |
| Parquet lake | **0.45–0.54 GB** per million normalized (larger files: less) | yes, in the lake |
| total retained (evidence + SIEM + lake) | **≈ 2.0 GB per million events**, so one billion a day is ≈ 2 TB a day | |

## Disk during the measurement

- **Guard:** an 8 GB budget per run and a 40 GB free-space floor on `/` and on `/mnt/c`, checked every half second by a guard
  thread that kills the run if either is crossed. It never tripped.
- **Largest run:** 621 MB of files (end to end: evidence, spool, lake).
- **Bounds:** evidence runs sized to ~30 s of the calibrated rate (89,061 events); end to end capped at 200,000 events.
- **Cleanup:** every run had its own directory, deleted afterwards along with the OpenSearch indices it created
  (`ulpf-bench-*`) and its index template.
- **Free space:** `/` 970.5 GB before and after. `/mnt/c` went from 347.7 to 346.7 GB; the Docker disk did not grow, so this is
  other Windows activity, not the runs.
- **Virtual disks: the WSL2 ext4 disk did not grow (75.884 GB before and after), and neither did Docker Desktop's disk (84.65
  GB).** The space freed by the previous measurement was reused.

## Not measured, stated

- Network ingest (every run read a file).
- Several streams sharing one disk.
- Several bulk forwarders.
- OpenSearch beyond one node and a 512 MB heap.
- The laptop.
- Other batch sizes: only the defaults (256 / 10 ms) and 1 were measured.

The input repeats 98 lines, which keeps caches warmer than real traffic would. The before-and-after for the fsync per event
(run 2c) uses 6,000 events and has the widest spread (139–265/s).
