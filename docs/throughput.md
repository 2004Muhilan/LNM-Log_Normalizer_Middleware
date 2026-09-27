# Throughput — "billions of events per day", measured (2026-09-27, re-measured with group commit)

The problem statement says the framework must be suitable for billions of events per day. One billion a day is
**11,574 events per second** on average. This is where ULPF is, on one machine, measured.

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
