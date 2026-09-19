# NOTICE — what is in this bundle and where it came from

This is a direct send to a teammate for a replayed demonstration, not a public release.

## ULPF (this project)

`serve.py`, `ui/`, `real/run-real.sh`, `real/sender.py`, `real/bin/*` (static Linux builds of the ULPF
runtime, committer and verifier), `real/root/contracts`, `real/root/ocsf/pinned` (pinned OCSF 1.3.0 class
tables derived from the OCSF schema, Apache License 2.0), and everything under `capture/` that the system
produced (sessions, certificates, packs, evidence records, checkpoints, terminal output). The dev signing
keys under `real/keys/` are demo-grade keys generated on the machine that built this bundle; they sign nothing outside this
demo.

## Elastic Beats module test fixtures — Elastic License 2.0

`capture/state/p6/mixed.log`, `capture/state/step1/capture.log`, the `samples/` directories inside the
packs under `capture/state/p6/source-packs/` and `capture/state/packs/`, the event streams and evidence
records derived from them, and the terminal output that echoes them contain log lines taken from the
test fixtures of the Elastic Beats Filebeat modules `cisco/asa`, `panw/panos` and `fortinet/firewall`
(repository `elastic/beats`, path `x-pack/filebeat/module/…/test`, commit `3b91674eedf9ecb1cb3bfece3fb65c4857f8a955`),
which are licensed under the **Elastic License 2.0**. The licence text is in `ELASTIC-LICENSE.txt` and
travels with this bundle, as ELv2 requires; the licence's limitations (no managed service, no licence-key
circumvention, no notice removal) are not affected by this use.

Attribution, as carried by the project: "Test corpus derived from Elastic Beats module test fixtures
(Elastic License 2.0) and logstash-patterns-core specs (Apache License 2.0); used for evaluation only,
not redistributed." — the project repository does not embed these fixtures; this bundle does, with the
notice, for the demonstration only. Do not republish the bundle.

## Squid sample lines

The six Squid lines in the golden pack and the eleven-column fixture are the project's own (derived from
the worked trace), not Elastic content.

## OCSF

Pinned class tables under `real/root/ocsf/pinned` are derived from the OCSF schema (Apache License 2.0),
with the source hashes recorded alongside them.
