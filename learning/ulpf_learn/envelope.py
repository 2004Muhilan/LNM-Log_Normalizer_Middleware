"""Syslog envelope unwrap for the learning plane — the Python twin of runtime/internal/frame/syslog.go,
used when an operator's onboarding capture still carries its transport headers (the runtime unwraps at
ingest; the learning plane must see the same payload the parser will see). One level; precedence 5424
then 3164 then none; the same acceptance rules. Kept deliberately small and mirrored, and covered by a
test against the Go unwrap on the same lines."""
from __future__ import annotations

import re

_MONTHS = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
_PRI = re.compile(rb"^<(\d{1,3})>")
_CLOCK = re.compile(rb"^\d{2}:\d{2}:\d{2}$")


def _pri(raw: bytes):
    m = _PRI.match(raw)
    if not m:
        return None, 0
    s = m.group(1)
    if len(s) > 1 and s.startswith(b"0"):
        return None, 0
    v = int(s)
    if v > 191:
        return None, 0
    return v, m.end()


def _field(raw: bytes, pos: int):
    sp = raw.find(b" ", pos)
    if sp <= pos:
        return None, pos
    return raw[pos:sp], sp + 1


def _sd_close(raw: bytes, i: int) -> int:
    q = False
    j = i + 1
    while j < len(raw):
        c = raw[j:j + 1]
        if c == b"\\":
            j += 2
            continue
        if c == b'"':
            q = not q
        elif c == b"]" and not q:
            return j
        j += 1
    return -1


def _u5424(raw: bytes):
    p, pos = _pri(raw)
    if p is None:
        return None
    ver, pos = _field(raw, pos)
    if not ver or len(ver) > 3 or not ver.isdigit() or int(ver) < 1:
        return None
    parts = []
    for _ in range(5):
        v, pos = _field(raw, pos)
        if v is None:
            return None
        parts.append(v)
    ts = parts[0]
    if ts != b"-" and (len(ts) < 19 or not ts[0:1].isdigit() or ts[4:5] != b"-"):
        return None
    if pos >= len(raw):
        return None
    if raw[pos:pos + 1] == b"-":
        pos += 1
    elif raw[pos:pos + 1] == b"[":
        while pos < len(raw) and raw[pos:pos + 1] == b"[":
            c = _sd_close(raw, pos)
            if c < 0:
                return None
            pos = c + 1
    else:
        return None
    if pos >= len(raw) or raw[pos:pos + 1] != b" ":
        return None
    pos += 1
    if pos >= len(raw):
        return None
    if raw[pos:pos + 3] == b"\xef\xbb\xbf":
        pos += 3
    return {"kind": "rfc5424", "payload_offset": pos, "payload_length": len(raw) - pos, "hostname": parts[1].decode(errors="replace"),
            "app_name": parts[2].decode(errors="replace"), "timestamp": ts.decode(errors="replace")}


def _u3164(raw: bytes):
    p, pos = _pri(raw)
    if raw[pos:pos + 3].decode(errors="replace") not in _MONTHS or raw[pos + 3:pos + 4] != b" ":
        if p is not None and pos < len(raw):   # PRI-only form (RFC 3164 §4.3.3); FortiGate
            return {"kind": "rfc3164", "payload_offset": pos, "payload_length": len(raw) - pos, "priority": p, "facility": p // 8, "severity": p % 8}
        return None
    ts_start = pos
    pos += 4
    while pos < len(raw) and raw[pos:pos + 1] == b" ":
        pos += 1
    day, pos = _field(raw, pos)
    if not day or not day.isdigit() or len(day) > 2:
        return None
    tok, n2 = _field(raw, pos)
    if tok is None:
        return None
    if len(tok) == 4 and tok.isdigit():
        pos = n2
        tok, n2 = _field(raw, pos)
        if tok is None:
            return None
    if not _CLOCK.match(tok):
        return None
    ts = raw[ts_start:pos + len(tok)].decode(errors="replace")
    pos = n2
    host, pos = _field(raw, pos)
    if not host:
        return None
    app = ""
    colon = raw.find(b":", pos, min(len(raw), pos + 64))
    if colon > pos:
        tag = raw[pos:colon]
        app_header = tag in (b"LEEF", b"CEF") and raw[colon + 1:colon + 2].isdigit()   # twin of the runtime: an application header is not a tag
        if not app_header and b" " not in tag and b"\t" not in tag:
            app = tag.split(b"[")[0].decode(errors="replace")
            pos = colon + 1
            if raw[pos:pos + 1] == b" ":
                pos += 1
    if pos >= len(raw):
        return None
    out = {"kind": "rfc3164", "payload_offset": pos, "payload_length": len(raw) - pos, "hostname": host.decode(errors="replace"), "app_name": app, "timestamp": ts}
    if p is not None:
        out.update(priority=p, facility=p // 8, severity=p % 8)
    return out


def unwrap(raw: bytes) -> dict:
    return _u5424(raw) or _u3164(raw) or {"kind": "none", "payload_offset": 0, "payload_length": len(raw)}


def payload(raw: bytes) -> bytes:
    e = unwrap(raw)
    return raw[e["payload_offset"]:e["payload_offset"] + e["payload_length"]]


# ---------------------------------------------------------------------------------------------------------------------
# The whole chain (2026-09-30): the twin of frame.UnwrapChain — what the router actually routes. A real FortiGate showed
# why one level is not enough: its JSON arrives as `<189>{…}` and its CEF as `<189>Sep 29 … fgt CEF:0|…|ext`, and a
# learning plane that drafts from the raw line sees a different surface from the one routing sees (JSON drafted as CSV,
# CEF as positional text). Onboarding must see the payload routing sees.

MAX_SYSLOG_DEPTH = 2   # frame.MaxSyslogDepth
_LEEF = re.compile(rb"^LEEF:(\d+)(?:\.\d+)?\|")


def _leef(raw: bytes):
    """Twin of frame.UnwrapLEEF."""
    m = _LEEF.match(raw)
    if not m:
        return None
    pos = m.end()
    fields = []
    for _ in range(4):
        e = raw.find(b"|", pos)
        if e < 0:
            return None
        fields.append(raw[pos:e])
        pos = e + 1
    delim = ""
    if int(m.group(1)) >= 2:
        e = raw.find(b"|", pos)
        if 0 < e - pos <= 4:
            d = raw[pos:e].decode("latin-1")
            h = d[2:] if d.startswith("0x") else d[1:] if d.startswith("x") else None
            if len(d) == 1 or (h is not None and len(h) == 2 and all(c in "0123456789abcdefABCDEF" for c in h)):
                delim, pos = d, e + 1
    if pos >= len(raw):
        return None   # a header with no attributes is not an envelope
    return {"kind": "leef", "payload_offset": pos, "payload_length": len(raw) - pos, "device_vendor": fields[0].decode(errors="replace"),
            "device_product": fields[1].decode(errors="replace"), "signature_id": fields[3].decode(errors="replace"), "leef_delimiter": delim}


def _cef(raw: bytes):
    """Twin of frame.UnwrapCEF: CEF:Version|Vendor|Product|Version|Signature ID|Name|Severity|Extension — pipes in the
    header fields escaped as \\|, a header with no extension is not an envelope, "CEF:" anywhere but at 0 is payload."""
    if not raw.startswith(b"CEF:"):
        return None
    pos = vs = 4
    while pos < len(raw) and raw[pos:pos + 1].isdigit():
        pos += 1
    if pos == vs or pos >= len(raw) or raw[pos:pos + 1] != b"|":
        return None
    pos += 1
    fields = []
    for _ in range(6):
        out = bytearray()
        while True:
            if pos >= len(raw):
                return None
            c = raw[pos:pos + 1]
            if c == b"\\" and raw[pos + 1:pos + 2] in (b"|", b"\\"):
                out += raw[pos + 1:pos + 2]
                pos += 2
                continue
            if c == b"|":
                pos += 1
                break
            out += c
            pos += 1
        fields.append(bytes(out))
    if pos >= len(raw):
        return None
    return {"kind": "cef", "payload_offset": pos, "payload_length": len(raw) - pos, "device_vendor": fields[0].decode(errors="replace"),
            "device_product": fields[1].decode(errors="replace"), "device_version": fields[2].decode(errors="replace"),
            "signature_id": fields[3].decode(errors="replace"), "name": fields[4].decode(errors="replace")}


def chain(raw: bytes) -> dict:
    """Twin of frame.UnwrapChain: up to MAX_SYSLOG_DEPTH syslog envelopes (5424, then 3164, else none), then ONE
    application envelope — LEEF, else CEF — only when the innermost payload STARTS with a well-formed header. Offsets are
    absolute in `raw`; `kinds` is outermost first; `l1` is what the router's L1 key names (the innermost kind, or raw)."""
    envs, off, n = [], 0, len(raw)
    for depth in range(MAX_SYSLOG_DEPTH):
        e = unwrap(raw[off:off + n])
        if e["kind"] == "none":
            break
        e = dict(e, level=depth + 1, payload_offset=e["payload_offset"] + off)
        envs.append(e)
        off, n = e["payload_offset"], e["payload_length"]
    for app in (_leef, _cef):
        e = app(raw[off:off + n])
        if e:
            e = dict(e, level=len(envs) + 1, payload_offset=e["payload_offset"] + off)
            envs.append(e)
            off, n = e["payload_offset"], e["payload_length"]
            break
    kinds = [e["kind"] for e in envs]
    return {"kinds": kinds, "envelopes": envs, "payload_offset": off, "payload_length": n, "l1": kinds[-1] if kinds else "raw"}


def chain_payload(raw: bytes) -> bytes:
    """The bytes the router routes and the parser parses."""
    c = chain(raw)
    return raw[c["payload_offset"]:c["payload_offset"] + c["payload_length"]]
