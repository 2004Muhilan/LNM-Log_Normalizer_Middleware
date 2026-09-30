# A real device: FortiGate 7.4.12 (2026-09-29)

The first real device ULPF has read. It is a FortiGate VM (FortiOS 7.4.12 build 2902) on the free permanent evaluation
licence, serial `FGVMEVXFB-07ZH02`. It runs under Containerlab and vrnetlab in its own WSL distro, and sends ULPF its
syslog over TCP. A small container behind it makes real allowed and denied connections.

**This page covers:**
- how the lab runs, and the rules that protect the licence;
- the network between the two WSL distros;
- whether the corpus-built FortiGate pack parses the real device, end to end, and on Proof of Derivation;
- live format drift on the device;
- what was found and what is raised;
- memory, disk and teardown.

Everything under "Results" was measured on the desktop (Ryzen 7 2700X, WSL2). Nothing was run on the laptop.

## The licence: rules

There is one free evaluation per account, and it is bound to this VM.
- **Only `docker start` / `docker stop` on `clab-fortigate-fgt`.** Never `containerlab deploy` or `containerlab destroy`: they
  create a new firewall with a new serial number.
- **Keep the VM's UUID.** vrnetlab gives the VM a new random UUID on every container start, but the licence was activated
  with `e9fbd16d-8991-4beb-8ec9-66767115dd38`. `demo/devices/fortigate/patch-vrnetlab.py` pins it inside the container's
  `/vrnetlab.py` (container writable layer; idempotent; a `UUID` environment variable would still win).
  - After the pin, QEMU starts with `-uuid e9fbd16d-…`; the container log shows it on every boot.
  - The licence stayed Valid across the pinned restarts. **It has never been tried across a UUID change, and should not be.**
- **Keep 1 vCPU and 2 GB RAM.** The licence is invalid with 2 CPUs; the lab file pins `QEMU_SMP: "1"`.
- **Keep within 3 interfaces and 3 policies.** The lab uses 2 of each: port1 (management) and port2; `allow-web` and
  `deny-rest`.
- **Take backups before anything risky.** Stop the container first, then copy the overlay disk:
  - `/home/clab/fgt-backup/20260929-174823` — the licensed state as handed over, before any change: the 200 MB
    `fortios-v7.4.12-overlay.qcow2` (sha256 `5066df30…`) and the original `vrnetlab.py` and `launch.py`;
  - `/home/clab/fgt-backup/20260929-180720-tz-sshkey` — after the time zone and the SSH key (sha256 `21686583…`).
- **Keep the Containerlab distro running.** It stops when nothing runs in it, and the FortiGate with it. `start.sh` leaves a
  keep-alive process (`ulpf-fortigate-keepalive`).
- **Automation uses SSH with a key, never the password.** The Containerlab distro's public key is on `admin`
  (`ssh-public-key1`), installed by the operator from the web UI's CLI. `admin`/`admin` is unchanged, because vrnetlab logs
  in with it on start. The serial console (port 5000) is not used: vrnetlab's own automation stalls there, which is why
  Docker reports the container `unhealthy` although the VM is up.

## Start it

```bash
wsl -d Containerlab -- bash /mnt/c/VSCode/sih-2026/SIH26156/laptop-commit-pull/demo/devices/fortigate/start.sh
```

This is `docker start` with the lab around it:
1. applies the vrnetlab patch (UUID pinned; one data NIC);
2. starts the FortiGate and the two small containers;
3. links the FortiGate's `eth1` to the client with a veth pair — exactly what containerlab does for a topology link;
4. waits for SSH, then prints `get system status` and **stops if the licence is not Valid**;
5. starts the traffic.

The FortiOS configuration it expects is `fortigate-base.conf`, applied once over SSH: port2, the two addresses, the two
policies, syslog and its filter.

**Why a patch for vrnetlab's launcher: it crashed the VM.** On 2026-09-29 at 13:47 UTC the FortiGate container died with
exit 1, ~70 minutes after a start. It was not out of memory: vrnetlab's `launch.py` had crashed on a `ScrapliTimeout`, and
it is the container's main process, so the VM went down with it. The cause is its scripted console login:
- it waits for the default prompt `FortiGate-VM64-KVM #`, but this VM's hostname is `fgt` (vrnetlab set it on the first
  boot), so the prompt is never recognised;
- it then types the username into an already-open session ("Unknown action 0"), which is also why Docker showed
  `unhealthy`;
- it waits for a `Password:` whose first letters it had already consumed in an earlier read;
- after ~68 minutes the read times out.

`patch-vrnetlab.py` now also patches `/launch.py`:
- a login prompt means the VM is up, and **nothing is typed on the serial console**. The login only set the hostname, which
  the VM keeps in its own configuration;
- the login pattern must be the last thing shown on the console, and the configured prompt is recognised too.

After the patch the container reports `healthy` ("Startup complete … (ULPF: console login skipped)"). The licence stayed
Valid across the crash and the three restarts that found and fixed it.

On every start, FortiOS itself reboots once ("Disk usage changed, please wait for reboot…"), because vrnetlab re-creates
the log disk. This is expected and harmless.

A third backup was taken before those restarts: `/home/clab/fgt-backup/20260929-201614-configured` (sha256 `b28c76b5…`),
the configured VM with port2, the policies and syslog.

**Why a patch for port2.** vrnetlab gives the VM one data NIC per container interface `ethN` present at start, and waits
for as many as `CLAB_INTFS` says. This container was created with `CLAB_INTFS=0`, and the environment cannot change without
re-creating the container. The patch makes vrnetlab wait for `eth1`, for at most 120 s: a plain `docker start` without the
link still boots, without port2. The VM then has `port2` (virtio, PCI 00:04.0).

## Fixed first

- **Time zone:** `set timezone "Asia/Kolkata"` (it was `US/Pacific`). NTP is synced to FortiGuard (offset ~0.8 s). The logs
  carry `tz="+0530"` and IST `date`/`time`.
  - Checked in ULPF: the normalized `time` equals the device's own `eventtime` (nanoseconds, UTC) in 254 of 254 events.
  - Live: ingest minus device time over one minute (55 events) was −1.1 to +0.7 s, median −0.1 s. The negative values are
    the device clock running ~0.8 s ahead of WSL's.
- **Automatic firmware upgrades: already disabled** (`config system fortiguard` → `auto-firmware-upgrade disable`). It
  stays on 7.4.12.
- **The CLI pager** `--More--` is off (`config system console` → `set output standard`) so that scripted reads are whole.

## The network between the two distros

```
fgt-client 10.10.1.10 ──veth── eth1 ═ port2 10.10.1.1 [ FortiGate VM ] port1 10.0.0.15 (DHCP from QEMU user-mode NAT)
                                                                    │ QEMU NAT
                                              container eth0 172.20.20.2
                                                                    │
            clab bridge 172.20.20.1 ── fgt-server 172.20.20.10 (HTTP :80)
                    │
     ULPF (Ubuntu distro) listening on *:6515  ← syslog/TCP from 172.20.20.2
```

- **All WSL2 distros share one network namespace.** Ubuntu and Containerlab show the same `eth0` (172.23.220.11), the
  same Containerlab bridge `br-b0445c627a82` (172.20.20.1) and the same namespace inode. The two Docker engines are
  separate, but their bridges live in this one namespace.
  - So ULPF, in the Ubuntu distro, is reachable from the FortiGate at `172.20.20.1` directly: no port proxy, no routing.
  - The syslog leaves the VM through QEMU's user-mode NAT, so ULPF sees it from the container's address,
    **`172.20.20.2`**: that is the device's identity in ULPF (`demo/apps/inventory.json`).
- **Docker Desktop is not involved.** OpenSearch and the model run there, and ULPF reaches them on `127.0.0.1` as before.
- **The web UI:** `https://localhost:8443`, through the operator's Windows `netsh portproxy` to the distro's `eth0`
  (172.23.220.11 today; it can change when WSL restarts).

**ULPF's listener.** The runtime takes one `tcp:` listener and one `http:` listener, no more (`--listen repeated: one tcp:
and one http: listener are supported together`). So there is no separate device port.
- With `ULPF_REAL_DEVICES=1`, `demo/start-demo.sh` binds the demo's one syslog/TCP listener on `0.0.0.0:6515` instead of
  `127.0.0.1:6515`.
- The generator and the relay still use loopback; the FortiGate reaches it on the bridge.
- Off by default. The System page states it.

**FortiOS gotcha.** A non-default syslog port makes FortiOS ask "Confirm to use port 6515 instead? (y/n)" at **`end`**, on
every commit of `config log syslogd setting`. Unanswered, or answered by the next command, it silently falls back to 514,
and ULPF hears nothing. The scripts send `y` after `end`.

**Framing:** `mode reliable` is TCP with RFC 6587 octet counting (`292 <189>date=…`). The device reconnects within seconds
after a configuration change, but backs off for minutes after refused connections. `syslog-format.sh` restarts it by
re-committing.

## Traffic

`traffic.sh` runs in `fgt-client`, in a loop every ~2 s:
- **allowed by `allow-web`** (port2 → port1, NAT): HTTP to 172.20.20.10:80, and ping (QEMU's NAT does not answer the ping,
  but the session is logged as accepted);
- **denied and logged by `deny-rest`:** SSH, Telnet, SMB, RDP, TCP/8080 to the server, and DNS to 8.8.8.8.

The device logs forward traffic (`accept`, `deny`, `close`, `timeout`, `server-rst`), local traffic, and system events for
every admin login and configuration change.

## Results

### 1. Does the corpus-built FortiGate pack parse the real device?

**The pack.** `fortigate-fw-01` v1.0 was built from Elastic's corpus samples: FortiOS 6.x-era `type=traffic` key=value
lines, relayed with an RFC 3164 header. It has one family, `fortigate-traffic` (class 4001).

**The test.** A raw capture of the real device's output in each syslog format (`capture.py`), replayed byte for byte into
the real runtime with the demo's packs, with no learning (`analyze.py`):

| format | frames | parsed | quarantined, and why |
|---|---|---|---|
| **default** | 264 | **254 (96 %)** | 10 `type=event` system events: "anchor value in the declared domain but no onboarded family owns it (fortigate-type=event)" — **the pack has no event family** |
| csv | 82 | 0 | 82 at `routing_drift`: "anchor **panos-log-type** located `devid=FGVMEVXFB-07ZH02` outside its declared domain" — **attributed to the PAN-OS pack** |
| cef | 182 | 0 | 182 unknown signature: the router sees the CEF header (`cef|kv||41`), but no family is onboarded |
| json | 172 | 0 | 172 unknown signature (`rfc3164|json||0`), no family onboarded |

**Where it parses.** In the default format the pack parses the real device's `traffic` logs, both forward and local, with
field-level correctness checked on all 254:
- **time:** equal to `eventtime`, in all 254 events;
- **addresses and ports:** `src_endpoint.ip`/`port` and `dst_endpoint.ip`/`port` equal the raw values in every event;
- **the device:** its name and serial go to `device.name`/`device.uid`;
- **policy and action:** `firewall_rule` carries the policy name and id; `accept`/`close`/`server-rst` map to action 1 and
  `deny` to 2;
- **nothing is lost:** keys the corpus never had (`srcserver`, `mastersrcmac`, `poluuid`, `crscore`, …) are carried in
  `unmapped`.

**Where it doesn't:**
- **no event family** (`type=event`: admin logins, configuration changes);
- **the source's time zone:** `source_timezone` is `unresolved`, although the device says `tz="+0530"`. The event time is
  right anyway, because it comes from the absolute `eventtime`.
- **none of the other four formats.**

### 2. End to end: OpenSearch, the lake, "Prove it" and Proof of Derivation

The demo ran with `ULPF_REAL_DEVICES=1`: two processes, the real evidence archive, OpenSearch 2.19.2 and Dashboards, and the
Parquet lake.
- The kernel put the FortiGate's connection on process 2, and the vendor relay on process 1.
- **Delivery:** 747 FortiGate events normalized = **747 documents in OpenSearch** (`device.uid = FGVMEVXFB-07ZH02`); **738
  lake rows** at that moment, the rest staged behind the 10 s rotation.
- **"Prove it" on a real-device event** (a DNS query to 8.8.8.8 from 10.10.1.10, denied by `deny-rest`). Every step passed:
  - the SIEM document, `_id` = ULPF's event id;
  - the raw bytes: 760 of them, re-hashed equal to the evidence index and the document's lineage;
  - the commit: `ckpt_000008`, then the Merkle proof;
  - **Proof of Derivation:** the logged pack `fortigate-fw-01` v1.0 (transparency log entry 3, witness-cosigned), re-run on
    the raw bytes, reproduces the SIEM document field for field. It was checked offline by `ulpf-verify`.
- The draft certificate is printable from the same view.

### 3. Real drift: default → csv → cef → json, switched live on the device

`syslog-format.sh` changes FortiGate's `set format` over SSH, and nothing else changes. Three minutes per format; the
System console's state was recorded every 30 s.

**The first pass found a console limit.** Its trigger needs 10 matching quarantines within the last 60 events **of all
sources**. The recorded four-vendor relay sends ~8 events/s and the FortiGate ~1/s, so no FortiGate format ever reached the
threshold: no job at all in csv or cef. With the relay switched off on the System page (an operator policy), the triggers
fired.

| format | what ULPF did | heals automatically? | asks the operator? |
|---|---|---|---|
| csv | every line quarantined at `routing_drift` as **drift of the PAN-OS pack**, bytes kept | no | **no**: the console acts only on `routing` and `parse` stages, so no job starts and nothing is flagged |
| cef | quarantined (unknown signature, CEF header recognised); **onboarding started** (jobs 4, 5) | no | no, as run: the **prepared answer sheet** (policy ON) answered positions. **Both jobs were blocked at promotion by the acceptance policy** ("8 of 24 samples fail to parse"; "4 of 16") |
| json | quarantined (unknown signature, `rfc3164|json`); **onboarding started** (jobs 1–3) | no | no: all three **failed** in drafting, before any question |
| default again | parsed by the corpus pack, as before | — | — |

- **Why "onboard", not "heal":** the console heals only families it onboarded itself, for the same source. The FortiGate's
  default family came in the static vendor pack, so every new format counts as a new format for a known source.
- **What was promoted: nothing.** No FortiGate pack was hot-loaded, and no new transparency-log entry was made. Every
  format change stayed quarantined with its bytes kept: nothing was lost and nothing was guessed.

### 4. The System page

The FortiGate appears in "Applications sending logs" as **FortiGate firewall (real device, Containerlab)** with a **REAL
DEVICE** tag, and the line "FortiGate-VM64-KVM FortiOS 7.4.12 build 2902 · serial FGVMEVXFB-07ZH02". This comes from the
operator's inventory entry for `172.20.20.2` (`real_device`). The ingress line says the listener is also reachable by real
devices on the bridge.

## Findings, and what is raised (not changed)

*As of 2026-09-29. Findings 1–5 were fixed on 2026-09-30, after a decision: see "Fixed, and the live test again" below.*

A real device not matching our code is a finding. **Nothing below was changed. Each is raised for a decision.**

1. **The learning plane does not unwrap the envelope the runtime unwraps** (`learning/ulpf_learn/draft.py`). The runtime's
   router strips `<PRI>`, RFC 3164 headers and the CEF header before classifying the payload. The drafter strips only LEEF.
   - FortiGate JSON (`<189>{…}`) is drafted as **CSV** (it counts commas) and refused: "csv samples of [42, 43, 44] cells".
   - FortiGate CEF (`<189>Sep 29 … fgt CEF:0|…`) is drafted as **whitespace positional text** (46 positions).
   - *Proposed:* a Python twin of the runtime's unwrap chain (syslog PRI / RFC 3164 / RFC 5424, CEF), applied before
     `surface()`, with cross-stack vectors like the existing ones.
2. **The prepared answer sheet is not scoped to a source** (`demo/apps/system.py`). The sheet was written for the demo
   generator's positional fields; the console applied it to the FortiGate's CEF positions by name (`pos_1 → time`,
   `pos_2 → action_id`, …).
   - Only the acceptance policy stopped a wrong pack.
   - *Proposed:* apply prepared answers only to the source (`source_id`) they were prepared for.
3. **FortiGate "csv" is comma-separated key=value** (`date=…,time=…,devname="fgt",…`). The router classifies it as CSV, and
   the PAN-OS anchor claims it as PAN-OS drift. The console then ignores `routing_drift` for learnable sources.
   - *Proposed:* comma-separated key=value as a key=value surface in the router (and its Python twin);
   - *and* treat `routing_drift` of a learnable source as a trigger.
4. **The console's trigger window is shared by all sources** (the last 60 events). A busy source starves another's
   detection: with the relay on, the FortiGate never triggered.
   - *Proposed:* a window per source.
5. **The corpus FortiGate pack has no `type=event` family**, and leaves `source_timezone` unresolved although the device
   sends `tz=`.
   - *Proposed:* onboard the event family from the real device once 1 is decided;
   - *and* resolve the zone from `tz=`.
6. **The runtime takes one `tcp:` listener.** The demo binds `0.0.0.0:6515` for real devices, rather than a second port.
   - *Possible:* repeatable `tcp:` listeners.

## Fixed, and the live test again (2026-09-30)

### What was fixed

1. **Onboarding sees the payload routing sees.**
   - `learning/ulpf_learn/envelope.py` has `chain()`, a twin of `frame.UnwrapChain`: up to two syslog envelopes (RFC 5424,
     then RFC 3164 with FortiGate's bare-`<PRI>` form), then one LEEF or CEF header.
   - The drafter, induction and the promoted samples all use it. A drafted family's L1 is the innermost envelope, the key
     the router matches.
   - **One vectors file holds both sides:** `learning/tests/envelope_vectors.json`, 16 vectors, including real FortiGate
     lines in every format, a two-deep relay chain, LEEF 1.0/2.0 and CEF. Go (`TestChainVectorsSharedWithTheLearningPlane`)
     and Python (`test_envelope_chain.py`) agree on all 16.
   - Tested with the captured FortiGate lines (`learning/tests/fixtures/fortigate/`):
     - JSON drafts as **JSON behind `rfc3164`**, not CSV;
     - CEF drafts from its **extension, behind `cef`**, not positional;
     - a CEF sample whose value holds unquoted spaces is **refused, with that reason**.
2. **Drift is attributed by source binding.**
   - A peer (ingest channel + host) is **bound** to a source once its lines were parsed by that source's packs. Those
     include vendor packs of the vendor the operator's inventory declares: `fortigate-fw-01` binds the FortiGate at
     172.20.20.2.
   - Unroutable lines of a bound peer are that source's drift: "format drift of FortiGate firewall (bound source)" on the
     page, with a drift alert.
   - The router's note ("anchor panos-log-type located … outside its declared domain") is shown only as a surface
     observation, "not an attribution: this peer is bound to FortiGate".
   - `routing_drift` of a learnable source is now a trigger, like `routing`. Where the router says an anchor value is in
     its domain but no family owns it, the job is a **new family of a known source**.
3. **The trigger window is per source:** the last 60 events **of each source**, keyed by source. With the relay sending 8/s,
   the FortiGate's 1/s now triggers.
4. **A prepared answer sheet is bound to its source** (`PREPARED_SHEETS["flowtap-01"]`). Any other source gets "no prepared
   sheet for fortigate-lab-01 … never applied to another device's fields", and the operator is asked.
5. **The FortiGate's system events were onboarded live** (below).
   - To make that possible, an operator's answer may carry a **value map onto an enum attribute**: `status` → `status_id`
     with success=1, failed=2 (`respond --lookup`; a value-map box on the page).
   - It uses the `lookup` transform the vendor tables already use: no contract change. The map is recorded in the
     assertion's evidence.
6. **`tz=` is used** (parser-pack **1.4.0**, additive: `time.timezone_field`).
   - Where the event states a valid offset, its normalized event says `source_timezone: "+05:30"` with
     `timezone_confidence: declared`.
   - Where it doesn't, the pack's defaults stand. normalized-event is unchanged.
   - The FortiGate vendor table declares `timezone_field: tz`, and the vendor packs were rebuilt. **All 254** real
     default-format events now say `+05:30`/declared (they said `null`/unresolved).
   - Tested: `TestTheSourcesOwnOffsetIsUsedWhereTheEventStatesIt`, `TestUTCOffset`.

### Live, on the real FortiGate, after the fixes

**Setup:**
- driver `demo/devices/fortigate/live_drift.py`; its report and the console's jobs are in
  `docs/metrics/fortigate-live-drift.json`;
- the demo with `ULPF_REAL_DEVICES=1`, the model (Qwen 3.5 4B on the GPU) and the evidence archive;
- **the four-vendor relay left ON** (8 events/s);
- auto-onboard ON, prepared answers ON.

| what the device did | ULPF's attribution | what happened | result |
|---|---|---|---|
| default format, traffic | — | parsed by the vendor pack while the relay ran | **parsed** |
| **system events** (admin login/logout: 14 SSH sessions) | **new family of a known source**, bound by `fortigate-fw-01` | job-1: drafted as key=value behind `<PRI>` (24 fields); the model proposed **OCSF Authentication (3002)** in 97 s; no prepared sheet. **The operator's answers were given through the page's API by the driver, on the operator's behalf:** eventtime→time, user→user.name, status→status_id (success=1, failed=2), action→activity_id (login=1, logout=2), logdesc→message, srcip/dstip→endpoints. Promoted, verified by the Go engine, **hot-loaded** | **onboarded, then parsed** (after the operator was asked) |
| `csv` | FortiGate drift (bound); the PAN-OS anchor's note shown as not an attribution | job-2: drafted as CSV, 44 columns; asked | **asked the operator.** But the drafted structure is positional CSV of `key=value` cells: FortiGate csv is comma-separated key=value (raised below) |
| `cef` | FortiGate drift (bound) | job-3 **refused**: "a CEF extension value runs to the next key= and may hold unquoted spaces (FortiGate: dstcountry=United States)". Job-4, from samples that happened to hold no such value, drafted key=value behind CEF, 41 fields; asked | **quarantined with the reason, then asked the operator** on a family that would refuse the spaced values (raised below) |
| `json` | FortiGate drift (bound) | job-5: drafted as JSON behind `<PRI>`, 48 named fields; asked; nothing carried over | **asked the operator** |
| default again | — | parsed by the vendor pack | **parsed** |

**Nothing healed automatically, and that is the policy as settled.**
- Automatic healing (autoheal-1.1) covers a changed format **within** a family this console onboarded, for the same source
  and the same L1/L2.
- A syslog format switch changes the surface, and earlier answers carry over only under the §4.4 key: same source,
  identical L1–L3.
- So every new FortiGate format asked the operator. The JSON keys are the default format's keys (srcip, dstip, action, …),
  and a cross-surface key would have healed most of them; that is raised below, not done.

**Proof of Derivation on a live-onboarded event.** An admin login, parsed by the pack onboarded minutes earlier:
- it is in OpenSearch (`ulpf-ocsf-3002`) and in the lake (`ulpf_authentication`);
- "Prove it" passes every step. Proof of Derivation re-ran `fortigate-lab-01-rfc3164-kv-24` v1.0 (transparency-log entry
  1583, "onboarded") on the raw bytes and reproduced the document field for field.

### Raised, not done — each needs a decision

1. **Cross-surface propagation.** Carrying answers by field name across surfaces of the same source would have healed most
   of FortiGate's JSON automatically: json → kv, and csv once 2 is done. It changes the §4.4 propagation key, an
   architecture decision.
2. **A comma-separated key=value surface** in the router (`detectL2`) and its Python twin. FortiGate csv is `k=v,k=v,…`,
   read today as CSV of `key=value` cells whose count varies by log type (42–44).
3. **CEF extension values with unquoted spaces.** The kv op splits on whitespace. CEF needs a value that runs to the next
   `key=`: a parser-spec (1.2.0 → 1.3.0) option.
4. **Drafting from samples that miss a feature.** Job-4's CEF samples held no spaced value, so its drafted family would
   refuse later lines that do (then a parse-drop drift job follows). A wider or later hold-out before promotion would
   catch it.
5. **The runtime's quarantine record keeps the router's anchor observation verbatim.** The attribution by binding is the
   console's. Should the runtime carry the peer binding itself?
6. **One model, jobs in series.** Job-2 (csv) took 4½ minutes to reach its questions behind the other jobs.

## Memory and disk

**Memory,** with everything running on the desktop: the FortiGate, the demo (two processes and two lake writers),
OpenSearch and Dashboards, and the model. The WSL VM had **17.5 GB available of 24 GB**. By container:

| container | memory |
|---|---|
| FortiGate VM | 1.38 GB |
| OpenSearch | 1.55 GB |
| model | 2.89 GB |
| Dashboards | 0.17 GB |

**Disk:**
- Containerlab distro's virtual disk: 3.30 GB, of which 387 MB is the two backups.
- ULPF's and Docker's virtual disks did not grow: 85.32 GB and 90.89 GB.
- Raw captures and analysis: `~/ulpf-fortigate`, 1.2 MB.
- Free space on C: fell 3.5 GB since the last measurement, while none of the three virtual disks grew. That is Windows,
  not this work.

## Teardown

```powershell
powershell -ExecutionPolicy Bypass -File demo\devices\fortigate\teardown.ps1              # elevated; asks you to type DELETE
powershell -ExecutionPolicy Bypass -File demo\devices\fortigate\teardown.ps1 -KeepBackup C:\fgt-backup
```

**It removes:**
- the traffic containers, the FortiGate container and both images;
- the `Containerlab` distro (`wsl --unregister`): containerlab, vrnetlab, the lab and the backups;
- the `portproxy` rule on 127.0.0.1:8443;
- `~/ulpf-fortigate`.

**It is irreversible for the licence.** `-KeepBackup` copies the licensed disk out first. It was written, not run.

### Reverting nested virtualization

Nested virtualization (needed for `/dev/kvm` inside WSL) was enabled in `%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
nestedVirtualization=true
```

To revert:
1. Delete the `nestedVirtualization=true` line. If `[wsl2]` is left empty, delete the file.
2. Run `wsl --shutdown`, so that WSL starts again without it.

Other distros do not need it; the teardown leaves the file alone, on purpose. The Containerlab distro's own
`/etc/wsl.conf` (`chown root:kvm /dev/kvm`) goes with the distro.

## Files

`demo/devices/fortigate/`:

| file | what it is |
|---|---|
| `start.sh` | starts the lab (`docker start`, the link, the traffic) |
| `patch-vrnetlab.py` | the UUID pin and port2 |
| `fortigate-base.conf` | the FortiOS configuration |
| `traffic.sh` | the traffic loop |
| `syslog-format.sh` | live format switch |
| `capture.py` | raw capture |
| `analyze.py` | the pack test |
| `teardown.ps1` | removal |

Demo changes:
- `ULPF_REAL_DEVICES` in `demo/start-demo.sh`;
- the relay stays on loopback when bound on all addresses, and the ingress label says so (`demo/apps/system.py`);
- the inventory entry `172.20.20.2` (`demo/apps/inventory.json`);
- the REAL DEVICE label (`demo/ui/system.html`).

## Gate

Both configurations pass, with the FortiGate lab running beside them:
- `bash scripts/gate.sh`: 762 s;
- `bash scripts/gate.sh --laptop`: 812 s.

Three earlier runs failed on timing checks under load (`docs/laptop-branch.md` §15), each passing on the next run.

After the real-device fixes (2026-09-30), both configurations passed on the first run, with the FortiGate lab running:
- `gate.sh`: 738 s;
- `gate.sh --laptop`: 819 s.

## Answers carried across formats by name (2026-09-30, the user's decision)

The user decided that, for a **self-describing** format — JSON, key=value, where every value is labelled with its field's
name — earlier resolved answers of the same source carry over **by name**. The name is the evidence. Everything else
keeps the structure-based §4.4 key.

This is recorded as a change to the settled propagation key (`learning/ulpf_learn/propagation.py`, docstring):

    same source_id + same family (the source's family keys, FortiGate type=traffic) + same field name + same value class

**What makes it safe:**
- **The family part.** FortiGate's `action` is a session verdict in traffic logs and login/logout in event logs.
- **The value class.** A field whose values changed class changed meaning; the flowtap test's protocol is an example.
- **One family per onboarding.** Mixed samples are split by the family key, the largest family is kept, and the rest stay
  quarantined for their own job.
- **The OCSF class.** An answer carries only into the class it was given for. When the model proposes another class for a
  family with earlier answers, the family's class, which rests on evidence, wins. The step is logged as
  `class_from_earlier_answers`.

**Where the answers come from:**
- earlier onboardings of the source record their answers at promotion;
- the source's **bound vendor pack** (the FortiGate's `fortigate-fw-01`) is seeded by the console with
  `ulpf_learn seed-propagation`. The value class of each key is observed on the lines that pack parsed from this device,
  taken out of the evidence store with `raw_hash` checked.

**Healing:** a drifted format whose fields carried by name heals like a known family (autoheal-1.1). What rests on evidence
is promoted at once; the rest is withheld (carried unmapped) and asked.

**Console fixes that came with it:**
- the active family key now includes the source and the family, so two devices' JSON, or one device's traffic and event
  JSON, never replace each other;
- an answer "carried unmapped by name" counts as evidenced.

**Live re-run, relay on** (`docs/metrics/fortigate-live-drift-json.json`):

1. The FortiGate's system events were onboarded again as a new family of the bound source: `type=event`, pack
   `fortigate-lab-01-rfc3164-kv-24-event`. The driver answered on the operator's behalf.
2. `default` → `json` gave job-2, drift of the FortiGate (bound):
   - 13 samples, family `type=traffic`;
   - 47 answers seeded from `fortigate-fw-01` (value classes observed on 48 of the device's own default-format lines);
   - the model proposed 4001; **47 of 52 fields carried by name**;
   - pack `fortigate-lab-01-rfc3164-json-52-traffic` v1.0 promoted and hot-loaded, `auto-healed` in the transparency log,
     with nobody asked.
3. **Result: healed automatically in part.** The JSON traffic parsed at once: 35 of the 40 latest events, the other 5 in
   flight.
4. **The 5 withheld fields** — `sentdelta`, `rcvddelta`, `durationdelta`, `sentpktdelta`, `rcvdpktdelta` — appear only
   in a session's interim updates.
   - Three of them are in no documentation table.
   - Two are in the table, but no default-format line in the window carried them, so they had no observed value class.

   They are carried unmapped and asked; nothing is guessed.
5. `json` → `default`: parsed by `fortigate-traffic` again.

The first attempt of this run failed on a syntax slip in the new CLI line. The second ran with the old drift path, which
asked for all fields when any was open; it was changed to heal in part as above. The run reported here is the third.

## The final demo (2026-09-30)

The FortiGate is now driven from the System page (`bash demo/start-demo.sh devices`):
- connect / disconnect its syslog;
- a live format switch;
- admin logins.

Every action goes through `demo/devices/lab.sh` (SSH with the key; the `y` after `end` is always sent). The pre-flight
checks the licence and reconnects its syslog automatically. The hidden `ulpf-clab-keepalive` session keeps the distro up
without a window; teardown stops it.

Routing is now among the packs bound to the sending device, so its JSON heal no longer collides with Suricata's.
See `docs/laptop-branch.md` §19.
