# Throughput — "billions of events per day", measured (2026-09-27)

The problem statement says the framework must be suitable for billions of events per day. One billion a day is
**11,574 events per second** on average. This is where ULPF actually is, on one machine, measured.

**Machine:** AMD Ryzen 7 2700X, 8 cores / 16 threads, 25 GB visible to WSL2 (kernel 6.6.87.2), Windows 11; evidence,
spool and lake on the WSL2 ext4 virtual disk; OpenSearch 2.19.2 in Docker Desktop (512 MB heap, security plugin
disabled); Go 1.27.1; commit `a56cc87` plus this change. **Input:** the four-vendor mixed capture (Cisco ASA, Palo Alto
PAN-OS, FortiGate, Squid behind a syslog relay, with the adversarial and not-onboarded lines it was built with: 98 distinct
lines, 9 % quarantined), repeated to the sample size — routing across four packs is part of what is measured; the content
repeats, which a real stream would not. **Method:** every measurement three times, the **median** reported, the three runs
beside it. Harness: `scripts/bench/throughput.py`; raw results: `docs/metrics/throughput.json`.

"Per day" below is an **extrapolation**: the measured rate held for 24 hours, the same mix, no peaks, the same hardware.
Real traffic has peaks several times its average; size for the peak, not the average.

## The numbers

| # | what | sample | events/s (median; runs) | events per CPU-second | CPU / memory | per day (extrapolated) |
|---|---|---|---|---|---|---|
| 1 | **parse**: framing → route → parse → normalize → JSON; no evidence, no egress; 1 process | 196,000 | **10,595** (10,589 · 10,763 · 10,595) | 10,330 | 1.0 core; 128 MB | 0.92 billion |
| 1 | parse, 4 processes | 784,000 | **38,778** (38,757 · 38,865 · 38,778) | 9,468 | 4.1 cores; 128 MB each | 3.35 billion |
| 1 | parse, 8 processes | 1,568,000 | **62,261** (62,043 · 62,261 · 62,627) | 7,581 | 8.2 cores (SMT) | 5.38 billion |
| 2 | **with the evidence log** (the real binary): raw bytes hashed and written first, two fsyncs per event; ext4 | 20,000 | **215** (258 · 185 · 215) | 1,593 | 0.14 core busy — the rest is waiting on fsync; 128 MB | **18.6 million** |
| 2b | the same with the evidence on tmpfs (the fsync cost removed, to isolate it) | 20,000 | 5,806 (5,803 · 5,806 · 5,932) | 4,021 | 1.4 cores | 0.50 billion |
| 3 | **into OpenSearch through the bulk sink** alone (`ulpf-runtime forward`, 100 documents per request) | 151,451 | **3,851** (3,785 · 4,443 · 3,851) | OpenSearch: 3,243 per OS CPU-second | forwarder 10.9 CPU-s; OpenSearch 46.7 CPU-s, 1.73 GB peak | 0.33 billion |
| 3b | into the **Parquet lake** alone (the lake writer, 100-event batches) | 151,451 | **1,736** (1,587 · 1,806 · 1,736) | 593 | ~2.9 cores (DuckDB is multi-threaded); ~1 GB | 0.15 billion |
| 4 | **end to end**: ingest → evidence (ext4) → spool → OpenSearch AND the lake, until both acknowledged every event | 20,000 | **143** (118 · 143 · 144) | — | runtime 47.7, lake writer 70.5, OpenSearch 18.4 CPU-s; OpenSearch 1.83 GB | 12.3 million |

In every end-to-end run both destinations had acknowledged the last event within 0.2 s of the runtime finishing ingest,
and OpenSearch held exactly the 18,163 normalized events, the lake the same 18,163 rows, 0 rejected.

## What it says

- **The core — parsing and normalization — is suitable for billions a day.** One process does ~10,600 events/s (0.92 billion
  a day, extrapolated); it scales across processes almost linearly on physical cores (4 processes: 38,778/s, 3.35 billion a day
  measured on 4 cores). **Cores for one billion a day on average: 1.1–1.2** (11,574 ÷ 9,468–10,330 events per core-second);
  with a peak factor of 3, about 4. The runtime is one stream per process, so "more cores" means more runtime instances
  (sharded by source or listener) — that is the scaling model measured here, not threads inside one process.
- **With the evidence log as built today, it is not.** Invariant 3 fsyncs the raw segment and its index before every event is
  parsed: on this disk that is ~4.6 ms per event, **215 events/s per stream, 18.6 million a day**. CPU is not the limit (0.14
  core busy); the fsync latency is. Removing the fsync (tmpfs) gives 5,806/s — 27× — so the durability design, not the
  code, sets the ceiling. **To reach one billion a day as built, ~54 streams each with its own fsync path would be needed**
  (whether this disk sustains 54 parallel fsync streams was not measured). The fix is **group commit** — fsync once per batch
  of events (or per few milliseconds) and hold the batch until then — which keeps "durable before parsed" and should approach
  the tmpfs figure; it changes invariant 3's wording ("fsyncs before returning", per event). **A decision for you; not built.**
- **End to end (143/s) is set by the same fsync**, not by the destinations: both kept up. Behind it, the next ceilings are:
  - **the lake writer, 1,736/s alone** — Python and DuckDB, and a cost per FILE: the fixed schema from the pinned tables
    (~3,600 schema elements) is written and read per file, and a flush writes one file per (class, event day); this corpus
    spans 9 event days, so 153 files for 151,451 rows. It uses ~1 GB and ~3 cores. At one billion a day it would need ~7
    writers, or larger files and a faster writer;
  - **OpenSearch through one bulk forwarder, 3,851/s** — about 3 forwarders (and ~3.6 OpenSearch cores) for 11,574/s, not
    measured.
  - The runtime itself spent 47.7 CPU-s on 20,000 events end to end, against 12.6 CPU-s without egress: the forwarders poll
    and re-read the spool (a directory listing and a file open per poll per destination). An optimisation target, not a
    ceiling at these rates.

## Efficiency of the integrations (requirement g)

| | figure | from |
|---|---|---|
| events per second into OpenSearch through the bulk sink | **3,851/s** median (one forwarder, 100 documents per request) | run 3 |
| OpenSearch cost | 3,243 documents per OpenSearch CPU-second; 1.73–1.83 GB peak with a 512 MB heap | runs 3, 4 |
| OpenSearch index size | **589 bytes per document** (532 in the end-to-end runs) — 0.32 of the same event as JSON (1,844 bytes) | runs 3, 4 |
| **Parquet lake vs the same events as JSONL** | **23.5 %** (4.3× smaller: 68.2 MB vs 290.2 MB for 151,451 events, 153 files) | run 3b |
| the same with small files | 54 % (18.7 MB vs 34.8 MB for 18,163 events in 45–54 files) — the fixed schema costs ~390 KB per file | run 4 |

## Disk per million events (sizing)

| what | per million events | retained? |
|---|---|---|
| evidence log (raw bytes + index) | **0.84 GB** (842 bytes per received event) | yes — it is the evidence |
| normalized JSONL in the spool | **1.84 GB** per million normalized (1,844 bytes each) | transient: freed as destinations acknowledge (bounded by the cap) |
| OpenSearch index | **0.53–0.59 GB** | yes, in the SIEM |
| Parquet lake | **0.45 GB** with production-size files; up to 1.03 GB with small ones | yes, in the lake |
| total retained (evidence + SIEM + lake) | **≈ 1.9 GB per million events** — one billion a day is ≈ 1.9 TB a day | |

## Disk during the measurement

Budget 8 GB per run and a 40 GB free-space floor on `/` and on `/mnt/c`, checked every half second by a guard thread that
kills the run if either is crossed (it never tripped; the largest run peaked at 76 MB of files — the event counts were small
because the evidence path is slow). Every run in its own directory, deleted afterwards with the OpenSearch indices it created
(`ulpf-bench-*`) and its index template. Free space: `/` 970.6 GB before and after; `/mnt/c` 346.6 → 345.4 GB.
**Virtual disks:** the WSL2 ext4 disk grew **0.59 GB** (75.29 → 75.88 GB; it does not shrink on its own — `wsl --shutdown`
then `Optimize-VHD` or `diskpart compact vdisk` gives it back); Docker Desktop's disk (OpenSearch's data) did not grow.

## Not measured, stated

Network ingest (all runs read a file); several streams sharing one disk's fsync; several bulk forwarders; OpenSearch beyond
one node and a 512 MB heap; the laptop. The input repeats 98 lines, which keeps caches warmer than real traffic.
