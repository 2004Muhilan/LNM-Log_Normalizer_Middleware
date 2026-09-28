# Throughput — "billions of events per day", measured (2026-09-27, re-measured with group commit)

The problem statement says the framework must be suitable for billions of events per day. One billion a day is
**11,574 events per second** on average. This is where ULPF is, on one machine, measured.

**The answer** (2026-09-28, with the work pinned to cores; details in "What ULPF itself can handle" below). Every run
here has the evidence log and the evidence archive on, and was exactly-once with every sender on one process.
- **One ULPF process sustains 5,310 events/s for 10 minutes on 1.44 cores:** 3,691 events per ULPF core-second.
- **Processes scale, but not linearly on one machine.** With 1, 2, 4 and 6 processes the matrix reached 5.4k, 9.5k, 13.9k
  and 15.8k events/s: 100 %, 88 %, 64 % and 49 % of the one-process figure per process. The two limits:
  - CPU sharing: two threads on a core;
  - disk waits: ~25–33 %, measured on tmpfs.

  With few senders, the kernel's hashing left processes idle.
- **One billion a day is 11,574 events/s. ULPF alone held it:** four processes (16 or 32 senders) and six processes kept
  every 30-second slice above it for the whole 3-minute window, **on ~5.5 logical CPUs busy within six cores** (four
  processes, 13.6–14.0k/s).
- **End to end on this one machine it does not.** With real OpenSearch and the real lake sharing the 8 cores, 10 minutes:
  - ULPF 7,011/s on its 2 cores, which were saturated;
  - OpenSearch kept pace on 2.4 CPUs;
  - the lake reached 6,522/s on 5.2 CPUs, about 40 s behind at the end.

  **The storage cost twice ULPF's CPU.** In production the SIEM and the lake run on their own machines.
- **The lake writer is the slowest part:** ~2,200 rows per core-second, against ULPF's ~3,700 events. One writer per process
  cannot keep pace with its process.
- The earlier numbers (2.7–3.1k end to end, 5,269/s with 4 processes, "17 cores") shared 8 cores between everything and
  are superseded by these; they are kept below for the process death and the limits.
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

## What ULPF itself can handle — pinned cores, replay senders (2026-09-28)

The scale-out matrix below measured the whole stack sharing 8 cores: generators, ULPF, OpenSearch and the lake writers.
It cannot say what ULPF itself handles. This section does, on the same machine, with the work pinned to cores.

**Harness:** `scripts/bench/capacity.py` (runs), `scripts/bench/replay.py` (senders), `scripts/bench/capacity-batch.sh`
(A then B), `scripts/bench/capacity_report.py` (the tables); raw results, every run with its per-second series:
`docs/metrics/capacity.json`. The binaries were a frozen copy built from this commit (`ULPF_BENCH_BIN`).

**Machine.** AMD Ryzen 7 2700X, 8 cores / 16 threads, 25.2 GB visible to WSL2, NVMe SSD (Crucial P3) under the WSL2 ext4
virtual disk; Windows 11. WSL2 shows 16 logical CPUs as 8 cores of 2 threads: **CPUs 2k and 2k+1 are core k**. They are
virtual processors. Hyper-V runs each pair on one physical core, but which physical core may change, and Windows shares
the machine. "Cores" below means these cores; "threads" the logical CPUs.

**Pinned.** Every process is started under `taskset` on a fixed set of logical CPUs; OpenSearch's container gets
`docker update --cpuset-cpus`; the harness pins itself to the senders' core. The layout is stated beside every table.

**Senders.** One light process (`replay.py`), one thread per sender, **each sender from its own loopback address**
(127.0.1.1 … 127.0.1.S) and source port. Every sender replays pre-built files of **five device formats, interleaved one line
of each in turn**, as a relay carries several devices, from its own offset:
- the four-vendor capture split by device: Cisco ASA (50 distinct lines, 177 bytes on average), PAN-OS (20, 469 bytes),
  FortiGate (13, 707 bytes), Squid (6, 158 bytes) — the 9 quarantined lines left out, so every event is expected in both
  destinations;
- the demo generator's format (flowtap, positional; 2,000 distinct lines, 71 bytes), with the pack the demo onboarded.

So routing across five packs is part of every run; the four vendors' content repeats, which real traffic would not.
Syslog over TCP, octet counting; frames prebuilt into chunks of 256, one `sendall()` per chunk. **The senders cost at most
0.01 core** in every run.

**ULPF, as in production.**
- Evidence log with group commit (256 frames / 10 ms).
- The evidence archive on in every run: a committer per store every 2 s, deletion after 10 s grace.
- A spool per process.
- Two destinations per process, **1,000 events per batch** (`?batch=1000`):
  - the SIEM: in A and B, the gate's fake bulk receiver in a measurement mode (below), one per process; in C, OpenSearch;
  - the lake: one lake writer per process, the production rotation (128 MiB / 5 min), one lake root.

**What a number means.** The senders push as fast as ULPF takes (TCP backpressure), so the kernel's socket buffers are
full all through the run: several MB per connection, several hundred thousand events in all.
- **The window** opens after a warm-up (15 s; 30 s for A) and closes when the senders stop. **Events/s is what ULPF
  committed to its evidence log in the window** (the index bytes each second, scaled by the exact final count).
- What the buffers still held at the end is taken in after the window. It counts for exactly-once, not for any rate.
- **Sustained** means every 30-second slice of the window is within 10 % of the median slice.
- A destination **kept pace** if its backlog at the window's end is under 10 seconds of intake.

**Checked in every run.**
- **Exactly-once:** events sent = accepted (evidence records, local buffer and archive) = SIEM documents = distinct SIEM ids
  = lake rows = distinct lake event ids, and nothing quarantined.
- **Affinity:** every sender's records are in one process's evidence, with no reconnect.

**CPU** per component, from `/proc/<pid>/stat` (all threads) and OpenSearch's cgroup:
- ULPF: runtimes and committers;
- the lake writers;
- the SIEM: the stand-in, or OpenSearch;
- the senders.

### Found by the calibration, fixed before anything was measured

The calibration runs showed three things that would have made every number wrong:
1. **The fake bulk receiver sent its headers and its body in two writes. With Nagle on, every request waited ~40 ms for
   the client's delayed ACK**, which capped the SIEM forwarder at ~20 requests/s (2,087 events/s) while the receiver sat
   idle. A test-receiver artefact, not ULPF: fixed with `disable_nagle_algorithm` (`demo/siem/fake_bulk.py`). Its new
   measurement mode (`--ids FILE`) counts and records ids instead of keeping millions of documents in memory; its type
   checks are the SIEM's work, not ULPF's.
2. **ULPF's forwarder cut every batch at 256 KiB, whatever `?batch=N` said**: about 134 normalized events, so
   `?batch=1000` to the lake was never 1,000. Fixed: `?batch=N` brings a byte bound of N × 4 KiB (256 KiB–32 MiB),
   `egress.BatchBytesFor`, tested (`TestBatchOfNIsNEventsNotTheDefaultByteBound`). A real defect, found by measuring.
3. **The socket buffers.** Megabytes per connection, so the senders' own count ran up to 1.2 million events ahead of ULPF.
   With one format per sender, the mix ULPF processed drifted as the buffers drained: the 71-byte lines pile up by the
   hundred thousand. Hence the interleaved streams and the window measured from ULPF's evidence, not from the senders.

"CPU" in the tables is CPU-seconds per second: logical CPUs busy. Two busy threads on one core count as 2.

### A — one process, ULPF only, 10 minutes

Machine as above. **Layout:**
- ULPF on cores 0–3 (CPUs 0–7): more than one process can use;
- the lake writer on cores 4–6 (CPUs 8–13);
- the senders, the SIEM stand-in and the harness on core 7 (CPUs 14–15).

**Run:** 32 senders (32 addresses), one run. **The window is 30–600 s (569.5 s), with 3,023,959 events in it and 3,800,320 in
the run.**

| what | value |
|---|---|
| **events/s, one ULPF process, sustained** | **5,310** |
| every 30-second slice | 4,995 – 5,786 (19 slices, all within 10 % of the median) |
| **ULPF CPU** (runtime + committer) | **1.44** |
| **events per ULPF core-second** | **3,691** |
| SIEM stand-in | kept pace (5,310/s acknowledged), 0.05 CPU |
| lake writer | 4,376/s on 2.0 CPU; **did not keep pace**: 612,390 behind at the window's end, waiting in the spool |
| senders | 0.001 CPU |
| exactly-once | sent 3,800,320 = accepted = SIEM (3,800,320 distinct) = lake rows (3,800,320 distinct); 0 quarantined |
| affinity | 32 senders, one process, no reconnect |
| disk | 5.62 GB at the peak (budget 10 GB) |

**Per day: 0.46 billion (extrapolated).** One process does not reach one billion a day. It uses 1.44 CPUs however many it is
given, because a process's path is largely one stream.

### B — scaling, ULPF only: 1, 2, 4, 6 processes × 8, 16, 32 senders

**Layout, the same in every cell:**
- ULPF on cores 0–5 (CPUs 0–11);
- all the lake writers on core 6 (CPUs 12–13);
- the senders, the SIEM stand-ins and the harness on core 7.

**Runs:** 3 minutes each, window 15–180 s (165 s), three runs per cell, median. Efficiency = events/s per process ÷ the
one-process figure with the same senders. The sample is the events in the window, median of three.

| processes | senders | events/s: median (runs) | per process | efficiency | ULPF CPU | events per ULPF core-second | senders per process (min–max, each run) | sample |
|---|---|---|---|---|---|---|---|---|
| 1 | 8 | **5,338** (5,338 · 5,319 · 5,362) | 5,338 | 100 % | 1.47 | 3,636 | 8 | 876,498 |
| 1 | 16 | **5,399** (5,382 · 5,399 · 5,462) | 5,399 | 100 % | 1.47 | 3,684 | 16 | 886,487 |
| 1 | 32 | **5,408** (5,535 · 5,408 · 5,384) | 5,408 | 100 % | 1.44 | 3,789 | 32 | 888,507 |
| 2 | 8 | **9,524** (9,477 · 9,524 · 9,575) | 4,762 | 89 % | 2.86 | 3,316 | 4–4, 3–5, 3–5 | 1,565,696 |
| 2 | 16 | **9,490** (9,529 · 9,490 · 9,455) | 4,745 | 88 % | 2.84 | 3,342 | 4–12, 4–12, 8–8 | 1,560,104 |
| 2 | 32 | **9,529** (9,752 · 9,529 · 9,470) | 4,764 | 88 % | 2.80 | 3,434 | 14–18, 14–18, 11–21 | 1,567,490 |
| 4 | 8 | **13,626** (13,626 · 11,820 · 14,250) | 3,407 | 64 % | 5.50 | 2,588 | 1–3, **0**–3, 1–3 | 2,241,531 |
| 4 | 16 | **13,611** (13,608 · 14,009 · 13,611) | 3,403 | 63 % | 5.44 | 2,561 | 2–7, 2–6, 2–5 | 2,240,420 |
| 4 | 32 | **13,953** (14,250 · 13,909 · 13,953) | 3,488 | 64 % | 5.50 | 2,538 | 4–13, 6–9, 5–10 | 2,289,478 |
| 6 | 8 | **13,708** (13,478 · 14,087 · 13,708) | 2,285 | 43 % | 5.55 | 2,434 | **0**–3 in all three | 2,259,099 |
| 6 | 16 | **15,788** (15,788 · 16,028 · 14,633) | 2,631 | 49 % | 7.52 | 2,132 | 2–5, 2–5, **0**–5 | 2,600,301 |
| 6 | 32 | **15,824** (15,464 · 15,824 · 16,059) | 2,637 | 49 % | 7.49 | 2,079 | 1–9, 2–9, 3–7 | 2,610,990 |

**All 36 runs:**
- exactly-once, with the sample sizes above in the windows and 1.1–3.5 million events per run;
- affinity held, with no reconnect;
- the SIEM stand-in kept pace in every run, on 0.05–0.29 CPU.

**Where it stops holding, and why.**
- **1 → 2 processes: 88–89 %.** Close to linear.
- **4 processes: 63–64 %, and 6 processes: 49 %.** Two things, separated by a diagnostic: the same cells with every store on
  tmpfs (RAM; `diag-tmpfs` in the JSON), 90 s, 16 senders.

  | | on the SSD (B) | on tmpfs | events per ULPF core-second, SSD / tmpfs |
  |---|---|---|---|
  | 1 process | 5,399/s on 1.47 CPU | **7,138/s** on 1.82 CPU | 3,684 / 3,914 |
  | 6 processes | 15,788/s on 7.52 CPU | **21,055/s** on 9.83 CPU | 2,132 / 2,142 |

  - **Disk waits cost ~25–33 % at every scale.** On tmpfs each process keeps more CPU busy, yet the work per CPU-second is
    the same. The fsyncs of group commit, the archive's copy, the spool and the lake staging all share one virtual disk.
  - **CPU sharing costs the rest.** Events per ULPF CPU-second fall from ~3,700 (one process) to ~2,100 (six processes),
    on tmpfs as on the SSD. With four or six processes, the six ULPF cores run two busy threads each, and two threads
    on one core are each slower than one alone. Last-level cache is also shared: the 2700X has two 8 MB halves.
  - **So on this machine the cores are the ceiling.** Six processes use 7.5 of 12 logical CPUs on the SSD and 9.8 on tmpfs.
- **Kernel balancing, with few senders.** The kernel hashes each connection to one process, and nothing moves it.
  - 8 senders on 6 processes left 2 processes idle in every run, so 6 × 8 performed like 4 × 8.
  - 8 senders on 4 processes left one idle once (11,820/s against 13.6–14.3k).
  - An uneven spread otherwise costs little (2 processes with 4 and 12 senders: 9,490/s), because each process is capped
    by its own path, not by how many senders it has. **An idle process is capacity lost.**
- **The lake writer never kept pace in B.** All the writers shared one core, by design, so that ULPF had six:
  - one writer on it did 3.3k/s;
  - six writers on it together did only 1.3k/s, contending.

  The spool absorbed the difference (peak 1.5–1.6 GB per million events accepted), and the lake was drained after each
  window on every core, to check exactly-once. That drain is not a throughput figure.

### C — end to end, the best configuration from B (6 processes, 32 senders), 10 minutes

**Real OpenSearch** (2.19.2, one node, **2 GB heap**, the demo's index template, no Dashboards) and **the real lake**: six lake
writers.

**Layout:**
- ULPF on cores 0–1 (CPUs 0–3);
- OpenSearch on cores 2–3 (CPUs 4–7, `docker update --cpuset-cpus`);
- the lake writers on cores 4–6 (CPUs 8–13);
- the senders and the harness on core 7.

**Run:** one run. **The window is 30–599 s (569 s), with 3,989,155 events in it and 4,875,520 in the run.** A 90-second probe
first found each part's rate.

| what | events/s | CPU (logical CPUs busy) | kept pace? |
|---|---|---|---|
| **ULPF: intake, evidence, archive, both forwarders** | **7,011** (30-second slices 6,378–7,623) | **3.61 of its 4**: saturated. **This is the bottleneck of this layout.** | — |
| **SIEM: OpenSearch** | **7,012** acknowledged | **2.43** of its 4 | **yes** (1,224 behind at the end) |
| **lake: six lake writers** | **6,522** acknowledged | **5.22** of its 6 | no: 279,020 behind (40 s), the next limit |
| senders | — | 0.004 | |

- **Exactly-once:** 4,875,520 sent = accepted = OpenSearch documents = lake rows = distinct lake ids; 0 quarantined.
- **Affinity:** 32 senders, each on one process, with 764,928–856,576 events per process.

**The CPU split, labelled.**
- **Of 11.3 CPUs busy, ULPF used 3.61 (32 %); the SIEM and the lake used 7.65 (68 %).**
  - ULPF: 0.51 ms of CPU per event, runtime and committer.
  - OpenSearch: 0.35 ms.
  - The lake writers: 0.74 ms.
- **The SIEM's and the lake's cost is theirs, not ULPF's.** In production the SIEM runs on its own machines, and so can
  the lake.
- On this one machine, end to end is **7.0k/s (0.61 billion a day, extrapolated)**. Adding cores to ULPF would move the
  bottleneck to the lake writers, then to OpenSearch.

### One billion a day (11,574 events/s): the answer

- **ULPF alone held it, measured.** These cells stayed above 11,574/s in **every 30-second slice of every run**, for the full
  3-minute window, with the evidence log and the archive on:
  - four processes with 16 or 32 senders: 13.6–14.3k/s;
  - six processes with 8, 16 or 32 senders: 13.5–16.1k/s.
- **The one miss:** four processes with 8 senders, in the run where the kernel left a process idle (one slice at 11,088).
- **Cores it needed:**
  - four processes at 13.6–14.0k/s: **~5.5 logical CPUs busy**, on the six ULPF cores (12 threads) of the layout;
  - six processes at 15.8k/s: 7.5 logical CPUs busy.
- **Not measured:** a 10-minute ULPF-only run at that rate. At 14k/s the lake writers' backlog alone would have passed the
  disk budget: ~13 GB of spool in 10 minutes. A holds 5.3k/s for 10 minutes and C holds 7.0k/s for 10 minutes; neither
  reaches 11,574 on its own.
- **End to end on one 8-core machine it is not reached:** 7.0k/s, with ULPF's share of the cores saturated.
- **By extrapolation** from the measured per-core figures, 11,574/s end to end needs about:
  - ULPF: 3.1 CPUs at one process's efficiency (3,691 per CPU-second), and 4.5 at the four-process efficiency (2,550);
  - the lake writers: ~5 cores (~2,200 rows per CPU-second, A);
  - OpenSearch: ~4 logical CPUs (2,890 documents per CPU-second, C).

  That is roughly 12–14 logical CPUs in all: **more than this machine, with the SIEM and the lake on the same box**. With
  the SIEM and the lake on their own machines, which is how they run in production, ULPF's part fits on six cores.
  Clearly an extrapolation: multi-machine was not measured.

### Disk: sizing and during the runs

**Per million events, by component**, this five-format mix (the average raw line is 316 bytes):

| component | per million events | from |
|---|---|---|
| evidence archive (raw bytes + index) | **0.84 GB** | every run |
| evidence local buffer, at its peak | 0.04–0.09 GB | bounded: shipped and deleted after 10 s grace |
| spool | **~1.9 KB per event waiting**. At the peak: 0.05 GB per million (C, destinations near pace), 0.4–0.7 (one process, lake behind), 1.5–1.6 (6 processes, one lake core) | transient |
| Parquet lake | **0.12 GB** (this mix; the four-vendor capture alone: 0.45–0.54) | every run |
| OpenSearch index | **0.75 GB** | C |
| SIEM stand-in ids file | 0.03 GB | harness only |
| **retained: evidence + SIEM + lake** | **≈ 1.7 GB per million**, so ≈ 1.7 TB a day at one billion | |

**During the runs:**
- **Before the batch:**
  - free space: 970.1 GB on `/` and 359.4 GB on C:;
  - the WSL2 disk 81.645 GB, Docker's 90.893 GB.
- **Limits:**
  - per-run budget, set from an estimate built on the per-million figures: A 10 GB, B 14 GB, C 16 GB;
  - free-space floor: 100 GB on `/` and on C:;
  - the batch stops if either virtual disk grows 20 GB past the start.
- **The watcher**, every second, covered:
  - the evidence buffers and the archive;
  - the spools and the lake;
  - the SIEM ids and the OpenSearch index;
  - free space and both virtual-disk files.

  **It never tripped.** B's six-process cells were at first refused by the estimate: 36,000/s assumed, 20.7 GB. They were run
  with the measured 20,000/s (11.1 GB estimated; the peak was 9.5 GB).
- **Peaks:**
  - A 5.62 GB;
  - B 9.53 GB (6 processes, 32 senders);
  - C 10.10 GB (OpenSearch 4.1 GB of it);
  - the tmpfs diagnostic 6.45 GB, in RAM.
- **Cleanup:** every run's directory and every `ulpf-cap-*` index were deleted after the run; the tmpfs directory, the index
  template and the OpenSearch container afterwards.
- **After the batch:**
  - **the WSL2 virtual disk grew 3.69 GB** (81.645 → 85.336 GB), all of it in the calibration probes and run A: ext4 put the new files on
    blocks the disk file had never held. It did not grow after run A: the rest reused the same space.
  - Docker's disk did not grow (90.893 GB).
  - Free space: `/` 970.1 GB, unchanged; C: 355.9 GB, the 3.5 GB of the WSL disk's growth.
- **What was written:** 97 million events in the 42 recorded runs (plus the calibration probes), never more than
  10.1 GB at a time.

### Not measured, stated

- More than one machine; OpenSearch beyond one node.
- A 10-minute ULPF-only run at four or six processes (the disk budget).
- UDP and HTTP intake at these rates (TCP only).
- Real traffic: the content repeats.
- The laptop.

## Scale-out across processes, end to end with the evidence archive on (2026-09-27)

*Superseded for capacity by the section above: here everything shared the 8 cores. Kept for the process death,
the limits and directory pull.*

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
  acknowledgement rule). **Correction, 2026-09-28:** until then the forwarder also cut every batch at its default 256 KiB,
  about 134 normalized events, so ULPF never sent the lake more than that per batch. The before-and-after below is not
  affected (its harness posted 1,000-row batches itself); the scale-out matrix above ran with ~134-event batches. Fixed:
  `?batch=N` now brings a byte bound of N × 4 KiB (at least 256 KiB, at most 32 MiB), tested
  (`TestBatchOfNIsNEventsNotTheDefaultByteBound`).
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
