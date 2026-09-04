# DSL sufficiency check — what was exercised, what broke, what was found

Run: `bash scripts/check-drafts.sh` (validates every draft against the frozen contract; runs the
regex-family drafts against the real corpus under RE2; checks the csv/kv/positional drafts against
corpus structure). This is not a parser — see the boundary note at the end.

## Drafts

| Draft | Ops exercised | Corpus result |
|---|---|---|
| `asa-302013.json` — Built TCP connection | sequence; `regex` (14 named groups); empty-capture `regex` separator (`:? `, because one corpus line omits the colon after the message id); `optional` user suffix; optional named groups inside the main regex (`(?:\((?P<src_user>...)\))?`) | **62/62** full match |
| `asa-302014.json` — Teardown TCP/UDP with free-text tail | as above plus an **opaque** tail capture for the teardown reason and *two* user encodings (`/port(LOCAL\user)` and bare ` user1 ` tokens) | **81/81** |
| `asa-106023.json` — Deny with every trailing element optional | chained `optional` regex steps (ICMP type/code in both `(type 3, code 0)` and `type 3, code 0,` forms; `by access-group "..."`; `[0x.., 0x..]`); optional ports; `protocol 47` two-token protocol; parenthesised host annotations | **65/66** — the miss is `... [0x0, 0x0]"` with a stray trailing quote: a malformed fixture line that a strict spec must reject (evidence path, not parse path) |
| `asa-305011.json` — NAT translation build/teardown | two message ids in one family; optional duration | **93/93** |
| `asa-106100.json` — ACL hit-count | the `%ASA-session-5-106100` tagged message-id variant; hostnames in place of IPs; alternation `first hit|N-second interval`; `enum` coerce with `reject` | **27/27** |
| `asa-733100.json` — threat-detection prose | opaque bracketed object with internal padding; negative integers | **5/5** |
| `panos-traffic.json` — PAN-OS TRAFFIC CSV | `csv` with `"` quoting and doubled-quote escape, `extra_fields: opaque`, `missing_fields: allow`; 65 declared cells incl. opaque FUTURE_USE cells; **ordered `formats` list** for `%Y/%m/%d %H:%M:%S` vs RFC 3339; `enum` coerce on the type cell; `ip` coerce with `opaque` fallback for empty NAT cells | contract ok; quoted-aware cell counts 46 / 65 / 75 / 105 across PAN-OS versions confirm the extra/missing policies are load-bearing; 10 corpus lines have a quoted cell containing a comma |
| `fortigate-traffic.json` — FortiGate KV | `kv` with `whitespace_run` pair separator, `"` quoting, backslash escape, `order: any`, `unknown_keys: opaque`; 73 declared keys; **`epoch_auto`** for `eventtime` | contract ok; every key occurrence in the 13 traffic lines (519) is declared; eventtime spans 1.55e9 (seconds) to 1.59e18 (nanoseconds) in the same file set |
| `squid-custom-logformat.json` — Squid under a non-default logformat | `positional` with **direct slots** (`quoted` slots inside a whitespace-delimited line), a bracketed timestamp as `literal`/`regex`/`literal`, a **nested `positional` inside quoted content**, `pattern` timestamp coerce with a single-digit hour | contract ok; **97/100** lines match the 14-slot layout; the 3 others are a shorter structural family of the same capture (different arity) — the §1.3 family-discovery case, deliberately *not* handled by optional middle slots |

## Op-set verdict

**Every family drafts cleanly with the ten ops. No op is missing.** Two *capabilities inside
existing ops* were missing and are added pre-freeze (flagged in the P1 report for confirmation):

1. `coerce.formats` — an ordered list of timestamp formats, first-parses-wins. Without it PAN-OS
   8.x/9.x (`2018/11/30 16:09:07`) and 10.x (`2021-05-26T16:27:07.000000Z`) need two specs for
   one family.
2. `timestamp_format.kind = epoch_auto` — magnitude-selected epoch precision. Without it FortiOS
   pre-6.2 (`eventtime=1592961368`) and 6.2+ (`eventtime=1587230049761513222`) need two specs.

Both are deterministic and expressible in both stacks; neither is a new op.

## What the check deliberately did not prove

Regex drafts were *executed* (composed into one anchored RE2 pattern and matched against every
corpus line of the family), so their match claims are measured. The csv/kv/positional drafts were
validated against the contract and checked against corpus structure (cell counts, key coverage,
slot layout via a checking regex), but **executing them end to end needs the P2 compiler**. That is
a phase boundary, not something to reach across: the first P2 test should replay these nine drafts
over `corpus/cache` and compare against the counts above.

## Things learned about the corpus that the specs must respect

- ASA interface names can contain spaces (`NP Identity Ifc`) — interfaces are `[^:]+`, not `\S+`.
- ASA emits user tags in two shapes, sometimes glued to the port with no separator.
- ASA message ids carry an optional tag (`%ASA-session-5-...`) and, in one fixture, no colon.
- PAN-OS field counts grow monotonically with version and only append; the declared 65-cell 8.1
  layout is prefix-compatible with 46-cell (older) and 75/105-cell (newer) lines.
- FortiGate NUL-terminated lines exist (`event-nul.log`); that is a framing concern (P7), not a KV one.
- No corpus line exercises PAN-OS doubled-quote escapes or FortiGate escaped quotes; both are
  declared per vendor convention and remain unexercised until a sample appears.
