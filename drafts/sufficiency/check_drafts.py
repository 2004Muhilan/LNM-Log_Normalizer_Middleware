#!/usr/bin/env python3
"""Sufficiency-check harness for the hand-drafted vendor specs. NOT a parser.

What it does, and only this:
  1. Validates every draft against the frozen parser-spec contract (schema + RE2 + semantic rules).
  2. For ASA drafts, whose root is a sequence of regex/literal/optional(regex) steps, concatenates the
     steps into one anchored RE2 pattern and reports the full-match rate against the real corpus
     lines of that family (payload = bytes from the message id onward). This exercises the regexes
     exactly as the runtime would compile them; it does not build the runtime.
  3. For the csv/kv/positional drafts, reports structural statistics from the corpus that the draft
     must be consistent with (quoted-aware CSV cell counts, KV key coverage, quoted-slot layout).
Executing csv/kv/positional drafts end to end requires the P2 compiler; that is reported as such.
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "learning"))
import re2  # noqa: E402
from ulpf_contracts import validate_document  # noqa: E402

DRAFTS = ROOT / "drafts" / "sufficiency"
CACHE = ROOT / "corpus" / "cache"


def corpus_lines(*rels):
    out = []
    for rel in rels:
        out += [l for l in (CACHE / rel).read_bytes().split(b"\n") if l.strip()]
    return out


def asa_payloads(lines, ids):
    pat = re.compile(rb"(%(?:ASA|FTD|PIX)-(?:[a-z]+-)?\d-(\d{6}).*)$")
    for l in lines:
        m = pat.search(l)
        if m and m.group(2).decode() in ids:
            yield m.group(1).rstrip(b"\r")


def compose(steps) -> str:
    """Concatenate a sequence of regex / literal / optional(regex|sequence) steps into one RE2 pattern."""
    parts = []
    for s in steps if isinstance(steps, list) else [steps]:
        op = s["op"]
        if op == "regex":
            parts.append(s["pattern"])
        elif op == "literal":
            parts.append(re.escape(s["text"]))
        elif op == "optional":
            parts.append("(?:" + compose(s["step"]) + ")?")
        else:
            raise ValueError(f"compose() only handles regex/literal/optional, got {op}")
    return "".join(parts)


def check_asa(name, ids, files):
    spec = json.loads((DRAFTS / name).read_text())
    errs = validate_document("parser-spec", spec)
    pattern = "^(?:" + compose(spec["root"]) + ")$"
    rx = re2.compile(pattern.encode())
    payloads = list(asa_payloads(corpus_lines(*files), ids))
    hits = [p for p in payloads if rx.fullmatch(p)]
    misses = [p for p in payloads if not rx.fullmatch(p)]
    print(f"{name:22s} contract={'ok' if not errs else errs}  corpus lines={len(payloads):3d}  full-match={len(hits):3d}  miss={len(misses)}")
    for m in misses[:5]:
        print("      MISS:", m.decode("utf-8", "replace")[:160])
    return not errs and not misses


ASA_FILES = ["beats-cisco-asa/asa.log", "beats-cisco-asa/additional_messages.log", "beats-cisco-asa/sample.log",
             "beats-cisco-asa/asa-fix.log", "beats-cisco-asa/non-canonical.log", "beats-cisco-asa/hostnames.log", "beats-cisco-asa/not-ip.log"]


def check_panos():
    spec = json.loads((DRAFTS / "panos-traffic.json").read_text())
    errs = validate_document("parser-spec", spec)
    declared = len(spec["root"]["fields"])
    counts = {}
    quoted_comma = 0
    for rel in ["beats-panw-panos/traffic.log", "beats-panw-panos/pan_inc_traffic.log", "beats-panw-panos/pan_inc_traffic_ietf.log",
                "beats-panw-panos/traffic_nanos_time.log", "beats-panw-panos/global_protect.log", "beats-panw-panos/threat.log"]:
        for l in corpus_lines(rel):
            m = re.search(rb"(?:^|\s)(\d+,\d{4}[/-]\d\d[/-]\d\d[ T][\d:.]+Z?,.*)$", l)
            if not m:
                continue
            payload = m.group(1).decode("utf-8", "replace")
            cells = next(csv.reader(io.StringIO(payload), delimiter=",", quotechar='"', doublequote=True))
            if any("," in c for c in cells):
                quoted_comma += 1
            key = (rel.split("/")[1], cells[3])
            counts.setdefault(key, {}).setdefault(len(cells), 0)
            counts[key][len(cells)] += 1
    print(f"panos-traffic.json     contract={'ok' if not errs else errs}  declared cells={declared}")
    for (f, t), dist in sorted(counts.items()):
        print(f"      {f:28s} {t:14s} cells-per-line={dict(sorted(dist.items()))}")
    print(f"      lines with a quoted cell containing a comma: {quoted_comma}  (naive split would miscount these)")
    print("      declared 65 = PAN-OS 8.1 TRAFFIC layout; >65 handled by extra_fields=opaque, <65 by missing_fields=allow; "
          "THREAT/GLOBALPROTECT counts shown only to confirm they are distinct families (separate specs).")
    return not errs


def check_fortigate():
    spec = json.loads((DRAFTS / "fortigate-traffic.json").read_text())
    errs = validate_document("parser-spec", spec)
    declared = set(spec["root"]["keys"])
    unknown = {}
    total_keys = 0
    lines = corpus_lines("beats-fortinet-firewall/traffic.log")
    quoted_with_space = quoted_with_eq = 0
    for l in lines:
        keys = re.findall(rb'(?:^|\s)([a-z_0-9]+)=', l)
        total_keys += len(keys)
        for k in keys:
            if k.decode() not in declared:
                unknown[k.decode()] = unknown.get(k.decode(), 0) + 1
        for v in re.findall(rb'="([^"]*)"', l):
            quoted_with_space += b" " in v
            quoted_with_eq += b"=" in v
    print(f"fortigate-traffic.json contract={'ok' if not errs else errs}  lines={len(lines)} declared keys={len(declared)} key occurrences={total_keys} "
          f"undeclared={dict(unknown) or 'none'}  quoted values with spaces={quoted_with_space}, with '='={quoted_with_eq}")
    eventtimes = [int(v) for l in lines for v in re.findall(rb'eventtime=(\d+)', l)]
    print(f"      eventtime magnitudes: min={min(eventtimes)} max={max(eventtimes)} -> epoch_auto needed (seconds and nanoseconds both present)")
    return not errs and not unknown


def check_squid_custom():
    spec = json.loads((DRAFTS / "squid-custom-logformat.json").read_text())
    errs = validate_document("parser-spec", spec)
    lines = corpus_lines("beats-squid-log/generated.log")
    layout = re2.compile(rb'^(\S+) (\d+) \[([0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{1,2}:[0-9]{2}:[0-9]{2}) ([^\]\s]+)\] "([^"]*)" (\S+) (\S+) (\S+) "([^"]*)" (\S+) (\S+) (\d+) "([^"]*)" "([^"]*)" (\S+)$')
    ok = [l for l in lines if layout.fullmatch(l.rstrip(b"\r"))]
    inner = re2.compile(rb'^(\S+) (\S+) (\S+)$')
    inner_ok = sum(1 for l in ok if inner.fullmatch(layout.fullmatch(l.rstrip(b"\r")).group(5)))
    single_digit_hour = sum(1 for l in ok if re.search(rb":\d:\d\d:\d\d ", l))
    print(f"squid-custom-logformat contract={'ok' if not errs else errs}  lines={len(lines)}  layout-match={len(ok)}  "
          f"quoted request line splits into 3 tokens={inner_ok}  single-digit-hour lines={single_digit_hour}")
    for l in [l for l in lines if l.rstrip(b"\r") not in [o.rstrip(b"\r") for o in ok]][:3]:
        print("      MISS:", l.decode("utf-8", "replace")[:160])
    return not errs and len(ok) == len(lines)


def main():
    results = []
    results.append(check_asa("asa-302013.json", {"302013"}, ASA_FILES))
    results.append(check_asa("asa-302014.json", {"302014", "302016"}, ASA_FILES))
    results.append(check_asa("asa-106023.json", {"106023"}, ASA_FILES))
    results.append(check_asa("asa-305011.json", {"305011", "305012"}, ASA_FILES))
    results.append(check_asa("asa-106100.json", {"106100"}, ASA_FILES))
    results.append(check_asa("asa-733100.json", {"733100"}, ASA_FILES))
    results.append(check_panos())
    results.append(check_fortigate())
    results.append(check_squid_custom())
    print("\nNOTE: csv/kv/positional drafts are checked for contract validity and corpus-structure consistency only; "
          "executing them end to end needs the P2 compiler — the first P2 test should be replaying these drafts over corpus/cache.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
