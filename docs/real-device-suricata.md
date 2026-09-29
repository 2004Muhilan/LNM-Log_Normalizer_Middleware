# A second real device: Suricata IDS on the FortiGate's wire (laptop branch, 2026-09-30)

Suricata 7.0.7 (Alpine 3.20's package) runs in Docker in the `Containerlab` WSL distro, beside the FortiGate lab
(`docs/real-device-fortigate.md`). It needs no VM and no licence. It sends its EVE JSON alerts to ULPF over TCP syslog.
Evidence: `docs/metrics/suricata-live.json`.

## The setup — `demo/devices/suricata/`

```
fgt-client 10.10.1.10 ──eth1── [port2  FortiGate  port1] ── clab bridge ── fgt-server 172.20.20.10
     │  (same network namespace)
  fgt-ids: Suricata -i eth1  ──/dev/log (shared volume)──  fgt-ids-syslog: rsyslog 172.20.20.11 ──TCP 6515──▶ ULPF
```

- **Same traffic as the FortiGate.** `fgt-ids` shares `fgt-client`'s network namespace and sniffs `eth1`, the client's
  end of the FortiGate's port2 link. It sees exactly the connections the FortiGate filters and logs. The traffic loop
  (`demo/devices/fortigate/traffic.sh`) now also makes one web request, allowed by the FortiGate, carrying a path
  traversal and a `sqlmap` user agent.
- **Offline rules.** `local.rules` holds five rules and is the only rule file (`-S`). There is no `suricata-update` and
  no feed. The rules:

  | sid | Matches |
  |---|---|
  | 9000001 | Telnet SYN |
  | 9000002 | RDP SYN |
  | 9000003 | SMB SYN |
  | 9000004 | `/etc/passwd` in the URI |
  | 9000005 | `sqlmap` user agent |

  Each one is triggered on purpose by the traffic loop.
- **EVE through syslog.** `ulpf-suricata.yaml` is loaded with `--include` on top of Alpine's default configuration. It
  sets alerts only, `filetype: syslog`, facility local5, and restates the default port groups (an included `vars`
  replaces the whole node). Suricata's syslog(3) writes to `/dev/log`, which is the socket of `fgt-ids-syslog`.
  rsyslog forwards it as RFC 3164 lines with RFC 6587 octet counting, for example:
  `<174>Sep 29 17:05:55 suricata-ids suricata[1]: {EVE JSON}`.
- **Why a forwarder.** `fgt-client`'s only route runs through the FortiGate, which would deny the syslog connection and
  log it.
- **Checksums.** `-k none`: the veth pair hands packets over before their checksums are filled in.
- **Start and remove.**
  - Start: `wsl -d Containerlab -- bash demo/devices/suricata/start.sh`, after the FortiGate lab.
  - Remove: `demo/devices/fortigate/teardown.ps1` now removes both containers, the volume and the image first.
- **Inventory.** `172.20.20.11` maps to `suricata-lab-01`, "Suricata IDS (real sensor, Docker)", vendor OISF,
  `family_keys: ["event_type"]`, and a `real_device` block. The System page shows the REAL DEVICE tag, the version, and
  no serial.

## Live, 2026-09-30 — `demo/devices/suricata/live_onboard.py`

1. **An unknown source.** Every alert from 172.20.20.11 was quarantined, bytes kept.
   - The console's job took 11 samples from the evidence store, with `raw_hash` checked.
   - It drafted the JSON: 20 fields, family `event_type=alert`, one family per onboarding.
   - The local model (Qwen3.5-4B) proposed a class in 49 s.
   - **The model proposed 4001 Network Activity, not 2004 Detection Finding.** The page gives the operator no way to
     overrule a proposed class.
2. **The operator's answers**, given through the page's API by the driver on the operator's behalf, and recorded as
   such:
   - `timestamp` → time
   - `src_ip` / `src_port` → `src_endpoint.*`
   - `dest_ip` / `dest_port` → `dst_endpoint.*`
   - `proto` → `connection_info.protocol_name`
   - `action` → `action_id` (allowed=1, blocked=2)
   - `signature` → message

   The other 12 fields were carried unmapped. Pack `suricata-lab-01-rfc3164-json-20-alert` v1.0 was signed, logged in
   the parser transparency log, verified by the Go engine and hot-loaded.
3. **Parsed from then on:** the 120 latest Suricata events all parsed under the new pack. The 20 labelled "format drift
   (bound source)" were alerts quarantined before the pack loaded.
4. **The same attack, two devices.** At ULPF's normalized output (`run-*/out.jsonl`), all 95 Suricata alerts from
   10.10.1.10 match a FortiGate event on the same connection: the same source port and destination port. By
   destination port:

   | Port | Matches |
   |---|---|
   | 445 | 26 |
   | 3389 | 26 |
   | 23 | 25 |
   | 80 | 18 |

   Example: FortiGate `deny` 10.10.1.10:33755 → 172.20.20.10:445 (`fortigate-fw-01`), and Suricata "ULPF LAB SMB
   connection attempt" on the same connection. Both carry `src_endpoint.ip` = 10.10.1.10 in class 4001.
5. **Where it stops — the finding:** see the next section.
6. **"Prove it" on a real Suricata alert (`ev_06GEW7FP8MB9ZF5Q7YBVZ9D214`):**
   - the raw bytes, read back from the evidence archive and re-hashed: OK;
   - the signed checkpoint: OK;
   - the Merkle proof: OK;
   - the SIEM document and the lake row: **missing**, for the same reason.

   The console's own round trip did not report within 180 s, so the trace was run directly with `demo/apps/trace.py`.

## Findings

**1. Suricata's time is ISO 8601 with a `+0000` offset. ULPF derives no coercion for it and promotes the pack anyway.**

EVE writes `"timestamp":"2026-09-29T17:05:55.512348+0000"`, an ISO 8601 offset without a colon. The effects:
- **No coercion derived.** The learning plane's `coercion_for` recognises RFC 3339 only (`+00:00`), so an operator's
  "this is `time`" produced no timestamp coercion.
- **Promoted anyway.** The acceptance engine accepted a pack whose mandatory `time` is text.
- **The runtime passes the text through.** It emitted `time` as that text, with lineage `event_time` 0.
- **OpenSearch rejects every Suricata document.** Its `time` field is `date`/`epoch_millis`
  (`mapper_parsing_exception`); the console counted 110 rejections.
- **The lake writer broke,** and fell silent: finding 2.

The parser-spec contract can already express this timestamp. The `pattern` kind with `%Y-%m-%dT%H:%M:%S.%f%z` exists in
both Go and Python. So the fix would be in the learning plane only: `coercion_for` would recognise the ISO 8601 basic
offset. The acceptance engine should also refuse a mandatory timestamp attribute that has no timestamp coercion.

**Raised, not changed:** this changes ULPF's code for what a real device sent. Until it is decided:
- the cross-vendor OpenSearch search returns FortiGate only;
- Suricata's events reach neither OpenSearch nor the lake as normalized rows. Their raw bytes are in the evidence store
  and the archive, provably.

**2. One text `time` stopped a lake writer. Fixed.**

Lake writer 1's rotation thread raised a `TypeError` on the text `time` and died. From then on it acknowledged batches
(HTTP 204) but could never write them — FortiGate's rows included — so the lake lost data silently.

Now:
- a row whose `time` is not epoch milliseconds is **refused into `_writer-N/rejected.jsonl` with its reason**, and
  counted as `rows_rejected`; the rest of the rotation is written;
- the rotator survives any failed rotation.

Test: `test_a_row_whose_time_is_text_is_refused_with_its_reason_and_the_rest_are_written`. This doesn't bend ULPF toward
Suricata: the writer refuses a malformed row instead of losing everyone's.

**3. The model's class, and no way to overrule it.**

OCSF 1.3 Detection Finding (2004) would be the right class for an IDS alert. There, the addresses live only in
`evidences[]`, an array that ULPF's mapping cannot write (the enumerator excludes array attributes). As 2004, Suricata's
attacker address could not be `src_endpoint.ip` at all.

The model chose 4001, and the page offers no way to change a proposed class. Suricata's `action: allowed` also means
"the sensor did not block", not "the connection was allowed". The driver's lookup mapped it to action_id 1, which reads
like the opposite of the FortiGate's `deny` on the same connection. Raised: operator class override, array attributes,
and the IDS action semantics.

**4. Optional keys.**
- Alerts carry keys that depend on the alert. For example, `tx_id` and `app_proto` appear only on application-layer
  alerts.
- The draft's union covered what the 11 samples held, and every later alert parsed.
- A rule firing on a new protocol would add keys and drift. That is JSON, so under the new cross-format rule the
  answers already given carry over by name, and only the new keys are asked.

## Gate

**Gate, on the desktop, with the FortiGate and Suricata running:**
- `bash scripts/gate.sh`: **PASS in 845 s** (Go 132 tests, 0 skipped; Python 113).
- `bash scripts/gate.sh --laptop`: **PASS in 841 s**. This is the laptop's configuration on the desktop, not the laptop.

**The runs that failed first, in order:**
1. CRLF line endings from my edit script, which the pre-flight refused; plus the apps-check startup race.
2. The old apps-check expectation, now superseded by the decision; plus the dropped SIGHUP in the container stage.
3. The dropped SIGHUP again, and the lake writer read as DOWN.

Each cause is fixed above; none by loosening a check.
