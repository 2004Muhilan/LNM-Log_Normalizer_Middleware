# Reference corpus

Fixtures are fetched into `corpus/cache/` (git-ignored) by `corpus/tools/fetch_corpus.py`, which
pins the upstream commit and records every file's sha256, size, line count and event-family
inventory in `corpus/catalogue.json`. **No fixture content is committed or redistributed.**

## Licence verdict

| Source | Files | Licence | Verdict |
|---|---|---|---|
| `elastic/beats` `x-pack/filebeat/module/{cisco/asa, fortinet/firewall, panw/panos}/test` (branch `main`) and `squid/log/test` (branch `7.17`, the module was removed later) | 48 (`.log` + `-expected.json`) | **Elastic License 2.0** (per the repository's root `LICENSE.txt`: everything under `x-pack/` is ELv2) | **Use locally as test data: permitted.** ELv2 allows use, copying and modification; its three limitations (managed-service provision, licence-key circumvention, notice removal) do not apply to running parser tests against fixtures. **Redistribution: not done.** ELv2 is not OSI open source, and ELv2 content inside the repository or a submission bundle would attach ELv2 terms to that artefact. Fixtures therefore stay in the local cache, reproducible from the catalogue, and the submission attributes the source without embedding it. |
| `logstash-plugins/logstash-patterns-core` `spec/patterns/{firewalls_spec.rb, squid_spec.rb}` | 2 | **Apache-2.0** | **Identified fallback.** Real ASA samples for 8 message ids (`%ASA-4-402117 402119 419001 419002 733100`, `%ASA-6-302013 602303 713172`) with expected grok captures, plus Squid native samples. Redistributable with attribution if a bundled corpus is ever required. |
| `SEKOIA-IO/intake-formats` | — | **No licence file** in the repository | **Rejected.** All rights reserved by default; not usable even as a fallback. |

Attribution to carry in the submission: "Test corpus derived from Elastic Beats module test
fixtures (Elastic License 2.0) and logstash-patterns-core specs (Apache License 2.0); used for
evaluation only, not redistributed."

## Coverage and gaps (from `catalogue.json`)

- **Cisco ASA/FTD:** 268-line `asa.log` (7 families), `additional_messages.log` (76 families in 102
  lines — the long tail), `sample.log` (26), `non-canonical.log` (hostnames instead of IPs, odd
  headers), `asa-fix.log`, `not-ip.log`, `hostnames.log`, `dap_records.log`. Header variants:
  `Oct 10 2018 12:34:56 host CiscoASA[999]:`, `May  5 17:51:17 dev01:`, `Jul 15 13:38:14 1.2.3.4 :`,
  `Apr 15 2014 09:34:34 EDT: %ASA-session-5-...`.
- **Palo Alto PAN-OS:** TRAFFIC (end/start/deny/drop; 46-, 65-, 75- and 105-cell layouts across
  versions), THREAT (url/data/file/spyware), SYSTEM, CONFIG, GLOBALPROTECT, USERID, HIPMATCH; one
  RFC 5424 octet-counted file; one 10.x file with RFC 3339 nanosecond timestamps.
- **FortiGate:** traffic (forward/local/multicast/sniffer), utm (10 subtypes), event (6 subtypes),
  one NUL-terminated file.
- **Squid:** native `access.log` (100 lines) and a generated non-default logformat (100 lines,
  two structural families: 97 fourteen-slot lines and 3 shorter ones).
- **Not reached by the corpus:** IDS/IPS and WAF products beyond FortiGate's utm/ips subtype and
  PAN-OS THREAT (the scope names IDS/IPS and WAFs as device classes; no Snort/Suricata or WAF
  fixtures were fetched — Beats' `suricata` module exists under the same ELv2 terms if needed);
  VPN gateways only as ASA/FortiGate VPN events; no IPv6 endpoints in any ASA line; no PAN-OS lines
  with doubled-quote escapes (the convention is declared in the draft but unexercised); no
  FortiGate values with escaped quotes.
- **Reference output caveat:** `-expected.json` files are Elastic's ECS interpretation, one
  parser's opinion; per the plan they are used for *agreement* measurement via the P6 crosswalk,
  never called accuracy. They also carry no traffic-volume distribution (P8 replay mix).
