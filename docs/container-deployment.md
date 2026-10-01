# The container deployment — ULPF as a product (2026-10-01)

The problem statement: *"The solution may be packaged in a container for making it platform independent."* ULPF's parts
already had images (runtime, committer, verifier, the learning plane with the model inside); the demo ran them as host
processes. Now the demo runs from containers, every runtime process is its own container, and processes are added and
removed from the System page while events flow.

## Decisions (the user's, 2026-10-01)

| Decision | Chosen | Why |
|---|---|---|
| Platform and networking | **Linux with Docker Engine; the runtime on host networking.** Docker Desktop: evaluation only, and the System page warns | the sender's address must reach the runtime intact (measured below) |
| Who starts and stops containers | **a separate scaler container** holds the Docker socket; the console never does | least privilege; the console is the operator-facing web app |
| Packs and keys | **release key** for the shipped packs; **install keys** generated per installation; shipped packs **logged in each installation's own transparency log** on first start | verifiable origin; no development key in a product; "only what is in the log loads" holds everywhere |

### The measurement behind the networking decision

A sender on the lab's Containerlab bridge at `172.20.20.50` connected to a small TCP listener in a container that prints the peer address (
2026-10-01):

| Listener | Engine | Address seen |
|---|---|---|
| host networking | Linux Docker Engine (the `Containerlab` distro, Debian 12, Docker 27.5.1) | **172.20.20.50** — intact |
| published port (`-p 6602:6602`) | same engine | **172.17.0.1** — Docker's gateway |
| host networking | Docker Desktop | not reachable from the lab at all |
| published port | Docker Desktop | **172.17.0.1** |

Through a published port, the FortiGate and Suricata would both arrive as `172.17.0.1`: one sender, and the source binding
(each line routed only among its device's packs) would mix them. So ULPF's containers use host networking, on a Linux
engine; on this desktop that is the `Containerlab` distro's engine (only `docker run`/`docker build` there — never
`containerlab deploy` or `destroy`).

## What runs

| Container | Image | Started by | Privileges |
|---|---|---|---|
| `init` (one-shot) | `ulpf-app` | Compose | root + `CAP_LINUX_IMMUTABLE` (wipes a state whose sealed evidence is immutable); no network |
| `witness` | `ulpf-witness` (distroless, 8 MB) | Compose | nonroot; reads only its own key |
| `scaler` | `ulpf-scaler` | Compose | **the Docker socket** — and nothing else of ULPF's |
| `opensearch`, `dashboards` | upstream | Compose | published on 127.0.0.1 only; security plugin OFF (demo only) |
| `siem-setup` (one-shot) | `ulpf-app` | Compose | — |
| `console` | `ulpf-app` | Compose | root in its container (chowns the committer's directory); no capability, no socket |
| `generator` (generator mode) | `ulpf-app` | Compose | — |
| **per runtime process *i*:** `runtime-i` | `ulpf-runtime` (distroless, 13 MB) | **the scaler** | root + `CAP_LINUX_IMMUTABLE` only; host network (`SO_REUSEPORT` on the shared ingress ports) |
| `committer-i` | `ulpf-committer` (distroless, 6 MB) | the scaler | nonroot, **no network**, no capability |
| `lake-i` | `ulpf-app` | the scaler | loopback |

The scaler's template fixes the image, program, mounts, user, capability and network of each part; the console chooses the
unit number and the program's arguments. The committer and the store are now separate containers — the P5 privilege
boundary as the plan described it — and the runtime's capability makes the kernel immutable flag real: the committer no
longer runs with `ULPF_COMMIT_SEALED=1` (the development seam the host-process demo needs).

Volumes (`<project>-state|packs|keys|trust|tlog|siem`): the state, the shipped packs, the installation's private keys
(never in an image), the trust store, the transparency log, the SIEM's data.

## Adding and removing a runtime process

**Add** (System page *Add a process*, or `deploy/ulpf.sh scale add`): a new unit — runtime, committer, lake writer —
with its own evidence store, loaded with every active pack, on the same ingress ports. Limits: one process per CPU Docker
reports; refused below 512 MiB of available memory. The kernel spreads NEW connections; an open connection stays where it is.

**Remove** (the highest-numbered process; never the last one):
1. refused while a destination is DOWN (its spool would be left behind);
2. wait until every destination has what the process parsed;
3. stop its runtime: it drains its spool for a last moment and **seals** its open segment;
4. wait until its committer has shipped every sealed segment to the evidence archive;
5. stop the committer and the lake writer. The process stays on the page as **retired**: its evidence is kept and *Prove it*
   works on its events. Its open connections close; senders reconnect and the kernel puts them on another process.

The outcome line states what is left behind, if anything ("N parsed event(s) not delivered — kept in its spool, M
segment(s) not shipped — kept locally"), from the runtime's own exit summary (events emitted; per destination, events
delivered and spool bytes undelivered).

## Packs and keys

- `scripts/release-packs.sh` (on the release machine): the golden Squid pack and the three vendor packs, `pack.json` and the
  specs they reference — **not** `samples/` or `certificates/`, which carry Elastic-licensed corpus lines — with the signing
  block naming `ulpf-pack-release`, signed with `keys/release/ulpf-pack-release.json` (git-ignored; never in a build
  context, an image or a bundle). Only the public key, `keys/trust/ulpf-pack-release.pub.json`, is committed. The packs and
  their signatures travel inside the `ulpf-app` image, not in git.
- `init`, first start: generates the installation's own pack authority, committer, transparency-log and witness keys into
  the keys volume; copies the shipped packs into the packs volume and **appends each to this installation's transparency
  log** (`hand-written` / `vendor-onboarded`), verifies the proof and the signature.
- The pack authority an installation signs its onboarded and healed packs with keeps the id `ulpf-pack-authority-dev`
  (the learning plane writes that id into every pack it emits); renaming it is a change to the emitter, not made here.

## Commands

```bash
bash scripts/release-packs.sh              # the release machine only: packs/release (needs the corpus and the release key)
bash deploy/ulpf.sh build                  # every image (Go and Python), from this repository
bash deploy/ulpf.sh up generator           # or: up devices  (fresh state; KEEP=1 keeps it)
bash deploy/ulpf.sh scale add              # or: scale remove — same as the System page buttons
bash deploy/ulpf.sh status | down | purge
bash deploy/ulpf.sh export                 # deploy/dist/ulpf-<version>.tar.gz: every image + compose + this script
bash deploy/ulpf.sh import ulpf-latest.tar.gz   # on another Linux host, offline: then `up`
bash deploy/check.sh                       # the gate's lane C
```

## Measured (desktop, 2026-10-01)

- `deploy/check.sh` (the gate's lane C, project `ulpf-check`): **PASS in 140 s.** Onboarding live; a third process added in
  0.9 s, taking connections and refusing an unlogged pack; processes 3 and 2 removed in 7.3 s and 4.7 s, each "0 parsed
  event(s) not delivered, 0 segment(s) not shipped"; removing the last one refused; 365 parsed = 365 SIEM documents = 365
  lake rows, 0 rejected; Prove it with Proof of Derivation on an event of the retired process; sealed segments carry the
  immutable flag; no private key in the app image; nothing left after `purge`.
- **The final demo from containers, two consecutive runs, all eight steps WORKED, no nudge**
  (`docs/metrics/final-demo-containers-{1,2}.json`, the seven steps plus 4b: add a process while both devices send, remove
  it). Add 0.7 s / 1.2 s, remove 4.8 s / 5.0 s, nothing left behind; drift healed 45 / 47 fields by name. Run 1: both
  devices' connections on process 1; run 2: the FortiGate on process 1, Suricata on process 2.
- The gate with lane C: **PASS in 923 s** (lane C runs after the other lanes: beside them it coincided with `/mnt/c`
  failures in other lanes). The offline bundle (`export`): 1.4 GB, seven images, 2.5 min; `import` loads it.
- Images: `ulpf-runtime` 13.1 MB, `ulpf-committer` 6.2 MB, `ulpf-witness` 8.2 MB, `ulpf-app` 245 MB, `ulpf-scaler` 124 MB;
  all built in 51 s from a warm cache.

## Stated limits

- **Supported: Linux with Docker Engine.** On Docker Desktop the sender's address is rewritten; the page warns, the binding
  cannot work there.
- The model is not containerised on this desktop: the Linux engine has no GPU runtime, so the model keeps running on Docker
  Desktop (`demo/llama-server.sh`), reached at `127.0.0.1:8081` (measured reachable from a host-network container). The
  Compose file has a `model` profile for a host whose Docker reaches its GPU — not run here.
- The scaler holds the Docker socket: whoever controls it controls the host's Docker. It listens on loopback and accepts only
  its template; it is not authenticated.
- Restarting with a kept state (`KEEP=1`) is not exercised by the check; the demo and the check start fresh.
- Built and run on the desktop only; nothing here was run on the laptop.
