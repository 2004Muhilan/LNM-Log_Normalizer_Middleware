"""Reference executor for the parser-spec DSL — the learning plane's sandboxed verifier.

It mirrors runtime/internal/dsl exactly: same ops, same precedence (null marker -> class check ->
coerce -> on_failure), same span-map output including which keys are present. The cross-stack
differential test compares its output with the Go engine's byte for byte after JSON normalisation.
It executes declarative data; nothing in a spec is code.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import re2

SCHEMA_VERSION = "1.1.0"

CLASS_RE = {
    "integer": re2.compile(r"^-?[0-9]+$"),
    "float": re2.compile(r"^-?[0-9]+(\.[0-9]+)?$"),
    "ipv4": re2.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$"),
    "ipv6": re2.compile(r"^[0-9A-Fa-f:.]+$"),
    "ip": re2.compile(r"^[0-9A-Fa-f:.]+$"),
    "mac": re2.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"),
    "url": re2.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://[^\s]+|[A-Za-z0-9.\-_\[\]:]+(:[0-9]+)?(/[^\s]*)?)$"),
    "hostname": re2.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"),
    "uuid": re2.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
    "hex": re2.compile(r"^(0x)?[0-9a-fA-F]+$"),
    "word": re2.compile(r"^[A-Za-z0-9_.:\-]+$"),
    "text": re2.compile(r"^[^\x00]*$"),
}


class CompileError(Exception):
    pass


def _unknown_path(p: str, seps: str) -> str:
    """A structured path as a legal span path: every segment [A-Za-z_][A-Za-z0-9_]* (twin of unknownPath)."""
    segs, cur = [], ""
    for ch in p:
        if ch in seps:
            if cur:
                segs.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        segs.append(cur)
    out = []
    for seg in segs:
        b = bytearray(seg.encode("utf-8"))
        for j, ch in enumerate(b):
            if not (ch == 0x5F or 0x61 <= ch <= 0x7A or 0x41 <= ch <= 0x5A or 0x30 <= ch <= 0x39):
                b[j] = 0x5F
        if not b or 0x30 <= b[0] <= 0x39:
            b = bytearray(b"_") + b
        out.append(b.decode("ascii"))
    return "unknown." + ".".join(out)


def _json_unescape(inner: bytes) -> bytes | None:
    """JSON string content -> UTF-8 bytes; None when an escape or the UTF-8 is invalid (twin of jsonUnescape)."""
    def valid(b: bytes):
        try:
            b.decode("utf-8")
            return b
        except UnicodeDecodeError:
            return None
    if b"\\" not in inner:
        return valid(inner)
    out, i, n = bytearray(), 0, len(inner)
    simple = {0x22: 0x22, 0x5C: 0x5C, 0x2F: 0x2F, 0x62: 0x08, 0x66: 0x0C, 0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09}

    def hex4(at):
        h = inner[at:at + 4]
        if len(h) != 4 or any(c not in b"0123456789abcdefABCDEF" for c in h):
            return None
        return int(h, 16)
    while i < n:
        ch = inner[i]
        if ch != 0x5C:
            out.append(ch); i += 1
            continue
        i += 1
        if i >= n:
            return None
        e = inner[i]
        if e in simple:
            out.append(simple[e]); i += 1
        elif e == 0x75:
            r = hex4(i + 1)
            if r is None:
                return None
            i += 5
            if 0xD800 <= r <= 0xDFFF:
                if not (0xD800 <= r <= 0xDBFF) or inner[i:i + 2] != b"\\u":
                    return None
                r2 = hex4(i + 2)
                if r2 is None or not (0xDC00 <= r2 <= 0xDFFF):
                    return None
                i += 6
                r = 0x10000 + ((r - 0xD800) << 10) + (r2 - 0xDC00)
            out += chr(r).encode("utf-8")
        else:
            return None
    return valid(bytes(out))


class Failure(Exception):
    def __init__(self, off: int, step: str, reason: str):
        super().__init__(reason)
        self.off, self.step, self.reason = off, step, reason


def sha256(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def class_ok(cls: str, tok: bytes) -> bool:
    rx = CLASS_RE.get(cls)
    if rx is None or not rx.match(tok):
        return False
    try:
        if cls == "ipv4":
            return isinstance(ipaddress.ip_address(tok.decode()), ipaddress.IPv4Address)
        if cls == "ipv6":
            return isinstance(ipaddress.ip_address(tok.decode()), ipaddress.IPv6Address)
        if cls == "ip":
            ipaddress.ip_address(tok.decode())
    except ValueError:
        return False
    return True


# ----------------------------------------------------------------------------- coercion

EPOCH_S, EPOCH_E = 946684800, 4102444800
MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def parse_pattern(fmt: dict, val: str, env: "Env") -> int:
    p = fmt["pattern"]
    year, month, day, hour, minute, sec, nsec, yday, pm, offset = 1970, 1, 1, 0, 0, 0, 0, 0, -1, None
    i = j = 0

    def digits(lo, hi):
        nonlocal j
        k = j
        while k < len(val) and k - j < hi and val[k].isdigit():
            k += 1
        if k - j < lo:
            raise ValueError(f"expected {lo}-{hi} digits at {j}")
        n = int(val[j:k])
        j = k
        return n

    while i < len(p):
        if p[i] != "%":
            if j >= len(val) or val[j] != p[i]:
                raise ValueError(f"literal mismatch at {j}")
            i += 1
            j += 1
            continue
        tok = p[i + 1]
        i += 2
        if tok == "Y":
            year = digits(4, 4)
        elif tok == "y":
            y = digits(2, 2)
            year = 2000 + y if y < 69 else 1900 + y
        elif tok == "m":
            month = digits(1, 2)
        elif tok in "de":
            while j < len(val) and val[j] == " ":
                j += 1
            day = digits(1, 2)
        elif tok in "HI":
            hour = digits(1, 2)
        elif tok == "M":
            minute = digits(1, 2)
        elif tok == "S":
            sec = digits(1, 2)
        elif tok == "f":
            k = j
            while k < len(val) and k - j < 9 and val[k].isdigit():
                k += 1
            if k == j:
                raise ValueError("expected fraction")
            nsec = int(val[j:k].ljust(9, "0"))
            j = k
        elif tok == "j":
            yday = digits(1, 3)
        elif tok == "b":
            m = MONTHS.get(val[j:j + 3].lower())
            if m is None:
                raise ValueError("bad month abbreviation")
            month = m
            j += 3
        elif tok == "z":
            if j < len(val) and val[j] in "Zz":
                offset = 0
                j += 1
            else:
                if j >= len(val) or val[j] not in "+-":
                    raise ValueError("expected offset")
                sign = -1 if val[j] == "-" else 1
                j += 1
                hh = digits(2, 2)
                if j < len(val) and val[j] == ":":
                    j += 1
                mm = digits(2, 2)
                offset = sign * (hh * 3600 + mm * 60)
        elif tok == "Z":
            k = j
            while k < len(val) and val[k].isalpha():
                k += 1
            if k == j:
                raise ValueError("expected zone name")
            if val[j:k].upper() in ("UTC", "GMT", "Z"):
                offset = 0
            j = k
        elif tok == "p":
            ap = val[j:j + 2].upper()
            if ap == "AM":
                pm = 0
            elif ap == "PM":
                pm = 1
            else:
                raise ValueError("expected AM/PM")
            j += 2
    if j != len(val):
        raise ValueError("trailing bytes after timestamp")
    if pm == 1 and hour < 12:
        hour += 12
    if pm == 0 and hour == 12:
        hour = 0
    tz = timezone.utc
    tzmode = fmt.get("timezone", "")
    if tzmode == "in_value":
        if offset is None:
            raise ValueError("timezone in_value but no offset in value")
        tz = timezone(timedelta(seconds=offset))
    elif tzmode == "source":
        if offset is not None:
            tz = timezone(timedelta(seconds=offset))
        elif env.source_tz is not None:
            tz = env.source_tz
    else:
        if offset is not None:
            tz = timezone(timedelta(seconds=offset))
    if yday > 0:
        dt = datetime(year, 1, 1, hour, minute, sec, nsec // 1000, tz) + timedelta(days=yday - 1)
    else:
        dt = datetime(year, month, day, hour, minute, sec, nsec // 1000, tz)  # raises on invalid dates
    return int(dt.timestamp() * 1000) + (0 if nsec % 1000 == 0 else 0)


def parse_timestamp(fmt: dict, val: str, env: "Env") -> tuple[int, str]:
    kind = fmt["kind"]
    if kind in ("epoch_s", "epoch_ms", "epoch_us", "epoch_ns"):
        n = int(val)
        div = {"epoch_s": 1, "epoch_ms": 1000, "epoch_us": 1000000, "epoch_ns": 1000000000}[kind]
        return (n * 1000 if div == 1 else n * 1000 // div), ""
    if kind == "epoch_s_frac":
        return int(round(float(val) * 1000)), ""
    if kind == "epoch_auto":
        n = int(val)
        sel, ms = "", 0
        for name, mult in (("s", 1), ("ms", 1000), ("us", 1000000), ("ns", 1000000000)):
            if EPOCH_S * mult <= n < EPOCH_E * mult:
                if sel:
                    raise ValueError("epoch_auto: more than one precision")
                sel, ms = name, n * 1000 // mult
        if not sel:
            raise ValueError("epoch_auto: outside every 2000-2100 window")
        return ms, sel
    if kind == "rfc3339":
        v = val.replace("Z", "+00:00") if val.endswith("Z") else val
        # Python accepts up to 6 fractional digits; trim nanoseconds like Go truncates to ms anyway
        m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?([+-]\d\d:\d\d)$", v)
        if not m:
            raise ValueError("not rfc3339")
        frac = (m.group(2) or "")[:7]
        dt = datetime.fromisoformat(m.group(1) + frac + m.group(3))
        return int(dt.timestamp() * 1000), ""
    if kind == "rfc3164":
        # "Jan  2 15:04:05" (no year) or the relay form "Jan  2 2006 15:04:05" (year carried; mirrors Go)
        has_year = False
        try:
            dt = datetime.strptime(val, "%b %d %H:%M:%S")
        except ValueError:
            dt = datetime.strptime(val, "%b %d %Y %H:%M:%S")
            has_year = True
        year = env.ingest_time.year if env.ingest_time else datetime.now(timezone.utc).year
        ay = fmt.get("assume_year")
        if isinstance(ay, int):
            year = ay
        if has_year:
            year = dt.year
        tz = env.source_tz or timezone.utc
        t = datetime(year, dt.month, dt.day, dt.hour, dt.minute, dt.second, 0, tz)
        if env.ingest_time and t > env.ingest_time + timedelta(hours=48):
            t = t.replace(year=year - 1)
        return int(t.timestamp() * 1000), ""
    if kind == "pattern":
        return parse_pattern(fmt, val, env), ""
    raise ValueError(f"unknown timestamp kind {kind}")


def coerce(c: dict, val: str, env: "Env") -> dict:
    to = c["to"]
    if to == "string":
        return {"to": "string", "value": val}
    if to == "int":
        if not re.fullmatch(r"-?[0-9]+", val):
            raise ValueError("not an int")
        return {"to": "int", "value": int(val)}
    if to == "float":
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            raise ValueError("not finite")
        return {"to": "float", "value": f}
    if to == "bool":
        low = val.lower()
        if low in ("true", "1", "yes", "on"):
            return {"to": "bool", "value": True}
        if low in ("false", "0", "no", "off"):
            return {"to": "bool", "value": False}
        raise ValueError("not a bool")
    if to in ("ipv4", "ipv6", "ip"):
        ip = ipaddress.ip_address(val)
        if to == "ipv4" and ip.version != 4 or to == "ipv6" and ip.version != 6:
            raise ValueError(f"not an {to}")
        return {"to": to, "value": str(ip)}
    if to == "mac":
        if not CLASS_RE["mac"].match(val.encode()):
            raise ValueError("not a mac")
        return {"to": "mac", "value": val.lower().replace("-", ":")}
    if to == "enum":
        if val not in c["values"]:
            raise ValueError("not in enum")
        return {"to": "enum", "value": val}
    if to == "timestamp":
        formats = [c["format"]] if "format" in c else c["formats"]
        last = None
        for i, f in enumerate(formats):
            try:
                ms, prec = parse_timestamp(f, val, env)
                out = {"to": "timestamp", "value": ms}
                if "format" not in c:
                    out["format_selected"] = i
                if prec:
                    out["precision_selected"] = prec
                return out
            except (ValueError, OverflowError) as ex:
                last = ex
        raise ValueError(str(last))
    raise ValueError("unknown coerce target")


def decode_bytes(encoding: str, raw: bytes) -> bytes:
    if encoding == "base64":
        return base64.b64decode(raw, validate=True)
    if encoding == "hex":
        return binascii.unhexlify(raw)
    if encoding == "url":
        # strict percent-decoding, as the engine (Go url.PathUnescape): every '%' must start a %XX hex
        # escape; '+' is not a space. urllib.parse.unquote silently kept a bad escape — found by the P4
        # op-coverage matrix.
        out, i = bytearray(), 0
        while i < len(raw):
            if raw[i] == 0x25:
                if i + 3 > len(raw) or not all(c in b"0123456789abcdefABCDEF" for c in raw[i + 1:i + 3]):
                    raise ValueError(f"invalid URL escape {raw[i:i + 3]!r}")
                out.append(int(raw[i + 1:i + 3], 16))
                i += 3
                continue
            out.append(raw[i])
            i += 1
        return bytes(out)
    if encoding == "json-string":
        return json.loads('"' + raw.decode("utf-8") + '"').encode("utf-8")
    if encoding == "c-escape":
        return raw.decode("utf-8").encode("utf-8").decode("unicode_escape").encode("latin-1")
    if encoding == "cef-extension":
        out = bytearray()
        i = 0
        while i < len(raw):
            if raw[i] == 0x5C and i + 1 < len(raw):
                nxt = raw[i + 1]
                if nxt in (0x5C, 0x3D):
                    out.append(nxt)
                elif nxt == ord("n"):
                    out.append(10)
                elif nxt == ord("r"):
                    out.append(13)
                else:
                    raise ValueError("bad CEF escape")
                i += 2
                continue
            out.append(raw[i])
            i += 1
        return bytes(out)
    raise ValueError(f"unknown encoding {encoding}")


def unescape_quoted(inner: bytes, quote: int, escape: str) -> tuple[bytes, bool]:
    if escape == "doubled":
        out, changed, i = bytearray(), False, 0
        while i < len(inner):
            if inner[i] == quote and i + 1 < len(inner) and inner[i + 1] == quote:
                out.append(quote)
                i += 2
                changed = True
                continue
            out.append(inner[i])
            i += 1
        return bytes(out), changed
    if escape == "backslash":
        out, changed, i = bytearray(), False, 0
        while i < len(inner):
            if inner[i] == 0x5C and i + 1 < len(inner):
                out.append(inner[i + 1])
                i += 2
                changed = True
                continue
            out.append(inner[i])
            i += 1
        return bytes(out), changed
    return inner, False


def scan_quoted(buf: bytes, pos: int, end: int, quote: int, escape: str) -> int:
    i = pos
    while i < end:
        if escape == "backslash" and buf[i] == 0x5C and i + 1 < end:
            i += 2
        elif buf[i] == quote:
            if escape == "doubled" and i + 1 < end and buf[i + 1] == quote:
                i += 2
                continue
            return i
        else:
            i += 1
    return -1


# ----------------------------------------------------------------------------- compile

@dataclass
class Env:
    source_tz: timezone | None = None
    ingest_time: datetime | None = None


@dataclass
class Cell:
    field: str
    kind: str
    cls: str | None
    coerce: dict | None
    decode: dict | None
    nulls: list[str]
    then: "Node | None" = None


@dataclass
class Node:
    op: str
    data: dict = field(default_factory=dict)


class Program:
    def __init__(self, spec: dict, raw_bytes: bytes):
        if spec.get("schema_version") not in ("1.0.0", "1.1.0", "1.2.0"):
            raise CompileError(f"unsupported schema_version {spec.get('schema_version')!r}")
        if spec.get("regex_dialect") != "re2":
            raise CompileError("regex_dialect must be re2")
        self.spec_id = spec["spec_id"]
        self.bounds = spec["bounds"]
        self.dsl_hash = sha256(raw_bytes)
        self.nulls = list(spec.get("null_values", []))
        self.fields: list[str] = []
        self._seen: set[str] = set()
        self.root = self._step(spec["root"], 1, "$.root")

    def _cell(self, c: dict, depth: int) -> Cell:
        f = c["field"]
        if f in self._seen:
            raise CompileError(f"duplicate field path {f!r}")
        self._seen.add(f)
        self.fields.append(f)
        if len(self.fields) > self.bounds["max_fields"]:
            raise CompileError("field count exceeds bounds.max_fields")
        if c["kind"] == "opaque" and any(k in c for k in ("class", "coerce", "decode", "null_values")):
            raise CompileError("opaque cell cannot carry class/coerce/decode/null_values")
        if "class" in c and c["class"] not in CLASS_RE:
            raise CompileError(f"unknown token class {c['class']!r}")
        nulls = c["null_values"] if "null_values" in c else self.nulls
        cell = Cell(f, c["kind"], c.get("class"), c.get("coerce"), c.get("decode"), list(nulls))
        if c.get("decode", {}).get("then") is not None:
            cell.then = self._step(c["decode"]["then"], depth + 1, f"decode.then")
        return cell

    def _csvcell(self, c: dict, depth: int):
        if "parse" in c:
            return ("parse", self._step(c["parse"], depth, "parse"))
        return ("cell", self._cell(c, depth))

    def _step(self, raw, depth: int, path: str) -> Node:
        if depth > self.bounds["max_nesting"]:
            raise CompileError(f"{path}: nesting depth {depth} exceeds bounds.max_nesting")
        if isinstance(raw, list):
            return Node("seq", {"steps": [self._step(s, depth, f"{path}[{i}]") for i, s in enumerate(raw)]})
        op = raw["op"]
        if op == "literal":
            return Node("literal", {"text": raw["text"].encode()})
        if op == "regex":
            try:
                rx = re2.compile(("^(?:" + raw["pattern"] + ")").encode())
            except Exception as ex:  # noqa: BLE001
                raise CompileError(f"{path}: regex does not compile under RE2: {ex}") from None
            # google-re2 reports group names as bytes for a bytes pattern; captures are str (found by the
            # P4 drafts adapter — the first time a regex op ran through this executor under test)
            names = {(k.decode() if isinstance(k, bytes) else k): v for k, v in rx.groupindex.items()}
            if set(names) != set(raw["captures"]):
                raise CompileError(f"{path}: named groups != captures")
            caps = {k: self._cell(v, depth + 1) for k, v in raw["captures"].items()}
            return Node("regex", {"re": rx, "pattern": raw["pattern"], "captures": caps, "index": {v: k for k, v in names.items()}})
        if op == "csv":
            return Node("csv", {"delim": raw["delimiter"].encode()[0], "quote": raw["quote"].encode()[0] if raw["quote"] else None,
                                "escape": raw["escape"], "fields": [self._csvcell(f, depth + 1) for f in raw["fields"]],
                                "extra": raw["extra_fields"], "missing": raw["missing_fields"]})
        if op == "kv":
            try:
                krx = re2.compile(("^(?:" + raw["key_pattern"] + ")").encode())
            except Exception as ex:  # noqa: BLE001
                raise CompileError(f"{path}: key_pattern does not compile: {ex}") from None
            keys = {k: self._csvcell(v, depth + 1) for k, v in sorted(raw["keys"].items())}
            return Node("kv", {"pair": raw["pair_separator"], "sep": raw["key_value_separator"].encode()[0],
                               "quote": raw["quote"].encode()[0] if raw["quote"] else None, "escape": raw["escape"], "keyre": krx,
                               "pattern": raw["key_pattern"], "keys": keys, "order": list(keys), "unknown": raw["unknown_keys"],
                               "ordermode": raw["order"], "bare": raw.get("allow_bare_keys", False)})
        if op in ("json", "xml"):   # parser-spec 1.2.0 — twin of runtime/internal/dsl/structured.go
            table = raw["keys"] if op == "json" else raw["paths"]
            for k, v in table.items():
                if "parse" in v:
                    raise CompileError(f"{path}: a {op} entry must be a cell (sub-parsing a structured value is not supported)")
            return Node(op, {"cells": {k: self._cell(v, depth + 1) for k, v in sorted(table.items())}, "unknown": raw["unknown_keys"] if op == "json" else raw["unknown"]})
        if op == "positional":
            slots = []
            for i, s in enumerate(raw["slots"]):
                if "field" in s:
                    slots.append(("cell", self._cell(s, depth + 1)))
                elif "token" in s:
                    slots.append(("token", self._step(s["token"]["parse"], depth + 1, f"{path}.slots[{i}].token")))
                else:
                    slots.append(("step", self._step(s["step"], depth + 1, f"{path}.slots[{i}].step")))
            tail = self._cell(raw["tail"], depth + 1) if raw.get("tail") else None
            return Node("positional", {"delim": raw["delimiter"], "slots": slots, "leading": raw["leading_delimiter"],
                                       "trailing": raw["trailing_delimiter"], "tail": tail})
        if op == "quoted":
            return Node("quoted", {"open": raw["open"].encode()[0], "close": raw["close"].encode()[0], "escape": raw["escape"],
                                   "content": self._cell(raw["content"], depth + 1),
                                   "parse": self._step(raw["parse"], depth + 1, f"{path}.parse") if "parse" in raw else None})
        if op == "optional":
            return Node("optional", {"step": self._step(raw["step"], depth + 1, f"{path}.step")})
        if op == "repeated":
            if raw["min"] > raw["max"]:
                raise CompileError(f"{path}: repeated.min > max")
            if raw["max"] > self.bounds["max_repeat"]:
                raise CompileError(f"{path}: repeated.max exceeds bounds.max_repeat")
            return Node("repeated", {"step": self._step(raw["step"], depth + 1, f"{path}.step"),
                                     "sep": self._step(raw["separator"], depth + 1, f"{path}.separator") if "separator" in raw else None,
                                     "min": raw["min"], "max": raw["max"]})
        raise CompileError(f"{path}: unknown op {op!r}")

    # ------------------------------------------------------------------------- execution

    def parse(self, raw: bytes, env: Env | None = None) -> dict:
        env = env or Env()
        m = {"schema_version": SCHEMA_VERSION, "spec_id": self.spec_id, "dsl_hash": self.dsl_hash,
             "event": {"raw_hash": sha256(raw), "raw_length": len(raw)}, "status": "ok",
             "buffers": [{"id": "raw", "length": len(raw)}], "spans": []}
        if len(raw) > self.bounds["max_event_bytes"]:
            m["status"] = "failed"
            m["failure"] = {"at_offset": self.bounds["max_event_bytes"], "reason": f"event of {len(raw)} bytes exceeds bounds.max_event_bytes {self.bounds['max_event_bytes']}", "step": "$"}
            return m
        x = _Exec(self, env, m, raw, "raw", "")
        try:
            pos = x.run(self.root, 0, len(raw))
            if pos != len(raw):
                raise Failure(pos, "$.root", "trailing bytes not consumed by the spec")
        except Failure as f:
            m["status"] = "failed"
            m["failure"] = {"at_offset": f.off, "reason": f.reason, "step": f.step} if f.step else {"at_offset": f.off, "reason": f.reason}
            m["spans"] = []
            m["buffers"] = m["buffers"][:1]
            return m
        m["spans"].sort(key=lambda s: ((0 if s["buffer"] == "raw" else 1, s["buffer"]), s["start"]))
        check_tiling(m)
        return m


def check_tiling(m: dict) -> None:
    lengths = {b["id"]: b["length"] for b in m["buffers"]}
    by = {b: [] for b in lengths}
    for s in m["spans"]:
        if s["start"] >= s["end"]:
            raise AssertionError("parser bug: empty span")
        by[s["buffer"]].append(s)
    for buf, spans in by.items():
        pos = 0
        for s in sorted(spans, key=lambda s: s["start"]):
            if s["start"] != pos:
                raise AssertionError(f"parser bug: tiling violated in {buf} at {pos}")
            pos = s["end"]
        if pos != lengths[buf]:
            raise AssertionError(f"parser bug: buffer {buf} not fully covered")


def _delim_run(d: dict, buf: bytes, pos: int, end: int) -> int:
    if d.get("whitespace_run"):
        i = pos
        while i < end and buf[i] in (0x20, 0x09):
            i += 1
        return i - pos
    if d.get("char"):
        return 1 if pos < end and buf[pos] == d["char"].encode()[0] else 0
    s = d["string"].encode()
    return len(s) if buf[pos:end].startswith(s) else 0


def _token_end(d: dict, buf: bytes, pos: int, end: int) -> int:
    i = pos
    while i < end and _delim_run(d, buf, i, end) == 0:
        i += 1
    return i


class _Exec:
    def __init__(self, prog: Program, env: Env, m: dict, buf: bytes, buf_id: str, suffix: str):
        self.prog, self.env, self.m, self.buf, self.buf_id, self.suffix = prog, env, m, buf, buf_id, suffix

    def mark(self):
        return len(self.m["spans"]), len(self.m["buffers"])

    def reset(self, s, b):
        del self.m["spans"][s:]
        del self.m["buffers"][b:]

    def literal(self, start, end):
        if end > start:
            self.m["spans"].append({"buffer": self.buf_id, "start": start, "end": end, "kind": "literal", "text": self.buf[start:end].decode("utf-8", "replace")})

    def opaque(self, path, start, end):
        if end > start:
            self.m["spans"].append({"buffer": self.buf_id, "start": start, "end": end, "kind": "opaque", "path": path + self.suffix})

    def emit_cell(self, c: Cell, start: int, end: int, value: bytes, encoding: str, step: str):
        if end <= start:
            return
        if c.kind == "opaque":
            self.opaque(c.field, start, end)
            return
        path = c.field + self.suffix
        for n in c.nulls:
            if value == n.encode():
                sp = {"buffer": self.buf_id, "start": start, "end": end, "kind": "semantic", "path": path, "value": n}
                if encoding:
                    sp["encoding"] = encoding
                sp["declared_null"] = True
                self.m["spans"].append(sp)
                return
        sp = {"buffer": self.buf_id, "start": start, "end": end, "kind": "semantic", "path": path}
        if c.cls and not class_ok(c.cls, value):
            raise Failure(start, step, f"value {value[:40]!r} does not match token class {c.cls}")
        try:
            sp["value"] = value.decode("utf-8")
        except UnicodeDecodeError:
            sp["decode_status"] = "invalid"
        if c.cls:
            sp["class"] = c.cls
        if encoding:
            sp["encoding"] = encoding
        if c.decode:
            try:
                dec = decode_bytes(c.decode["encoding"], value)
            except Exception as ex:  # noqa: BLE001
                if c.decode["on_failure"] == "reject":
                    raise Failure(start, step, f"decode {c.decode['encoding']} failed: {ex}") from None
                self.opaque(c.field, start, end)
                return
            sp["encoding"] = c.decode["encoding"]
            try:
                sp["value"], sp["decode_status"] = dec.decode("utf-8"), "ok"
            except UnicodeDecodeError:
                sp.pop("value", None)
                sp["decode_status"] = "invalid"
            value = dec
            if c.then is not None:
                bid = path + "#decoded"
                self.m["buffers"].append({"id": bid, "length": len(dec), "derived_from": path, "encoding": c.decode["encoding"]})
                sub = _Exec(self.prog, self.env, self.m, dec, bid, self.suffix)
                try:
                    p = sub.run(c.then, 0, len(dec))
                    if p != len(dec):
                        raise Failure(p, step + ".decode.then", "trailing bytes in decoded buffer")
                except Failure:
                    if c.decode["on_failure"] == "reject":
                        raise
                    self.opaque(c.field, start, end)
                    return
        if c.coerce and sp.get("decode_status") != "invalid":
            try:
                sp["coerced"] = coerce(c.coerce, value.decode("utf-8"), self.env)
            except (ValueError, OverflowError) as ex:
                if c.coerce["on_failure"] == "reject":
                    raise Failure(start, step, f"coerce to {c.coerce['to']} failed: {ex}") from None
                self.opaque(c.field, start, end)
                return
        self.m["spans"].append(sp)

    def run(self, n: Node, start: int, end: int) -> int:
        buf = self.buf
        if n.op == "seq":
            pos = start
            for i, s in enumerate(n.data["steps"]):
                try:
                    pos = self.run(s, pos, end)
                except Failure as f:
                    f.step = f"[{i}]{f.step}"
                    raise
            return pos
        if n.op == "literal":
            t = n.data["text"]
            if not buf[start:end].startswith(t):
                raise Failure(start, ".literal", f"expected {t.decode('utf-8', 'replace')!r}")
            self.literal(start, start + len(t))
            return start + len(t)
        if n.op == "regex":
            mt = n.data["re"].match(buf[start:end])
            if not mt:
                raise Failure(start, ".regex", f"no match for /{n.data['pattern']}/")
            caps = []
            for idx, name in n.data["index"].items():
                s, e = mt.span(idx)
                if s < 0 or s == e:
                    continue
                caps.append((start + s, start + e, name))
            caps.sort()
            pos = start
            for s, e, name in caps:
                if s < pos:
                    raise Failure(s, ".regex", "overlapping captures")
                self.literal(pos, s)
                self.emit_cell(n.data["captures"][name], s, e, buf[s:e], "", ".regex." + name)
                pos = e
            mend = start + mt.end()
            self.literal(pos, mend)
            return mend
        if n.op == "positional":
            d = n.data["delim"]
            pos = start
            l = _delim_run(d, buf, pos, end)
            if l:
                if n.data["leading"] == "reject":
                    raise Failure(pos, ".positional", "leading delimiter not allowed")
                self.literal(pos, pos + l)
                pos += l
            for i, (kind, item) in enumerate(n.data["slots"]):
                step = f".positional.slots[{i}]"
                if i > 0:
                    l = _delim_run(d, buf, pos, end)
                    if not l:
                        raise Failure(pos, step, f"expected delimiter before slot {i}")
                    self.literal(pos, pos + l)
                    pos += l
                if kind == "step":
                    try:
                        pos = self.run(item, pos, end)
                    except Failure as f:
                        f.step = step + f.step
                        raise
                    continue
                te = _token_end(d, buf, pos, end)
                if te == pos:
                    raise Failure(pos, step, f"empty token for slot {i}")
                if kind == "cell":
                    self.emit_cell(item, pos, te, buf[pos:te], "", step)
                else:
                    try:
                        p = self.run(item, pos, te)
                    except Failure as f:
                        f.step = step + ".token" + f.step
                        raise
                    if p != te:
                        raise Failure(p, step, "token sub-parse did not consume the whole token")
                pos = te
            tail = n.data["tail"]
            if tail is not None:
                if pos < end:
                    l = _delim_run(d, buf, pos, end)
                    if l:
                        self.literal(pos, pos + l)
                        pos += l
                    self.emit_cell(tail, pos, end, buf[pos:end], "", ".positional.tail")
                    pos = end
                return pos
            l = _delim_run(d, buf, pos, end)
            if l:
                if n.data["trailing"] == "reject":
                    raise Failure(pos, ".positional", "trailing delimiter not allowed")
                self.literal(pos, pos + l)
                pos += l
            return pos
        if n.op == "quoted":
            o, cl, esc = n.data["open"], n.data["close"], n.data["escape"]
            if start >= end or buf[start] != o:
                raise Failure(start, ".quoted", f"expected opening {chr(o)!r}")
            close_at = scan_quoted(buf, start + 1, end, cl, esc)
            if close_at < 0:
                raise Failure(start, ".quoted", "unterminated quote")
            self.literal(start, start + 1)
            inner = buf[start + 1:close_at]
            value, changed = unescape_quoted(inner, cl, esc)
            enc = "" if esc == "none" else "quoted-" + esc
            content = n.data["content"]
            if n.data["parse"] is not None:
                if changed:
                    bid = content.field + self.suffix + "#decoded"
                    self.emit_cell(content, start + 1, close_at, value, enc, ".quoted.content")
                    self.m["buffers"].append({"id": bid, "length": len(value), "derived_from": content.field + self.suffix, "encoding": enc})
                    sub = _Exec(self.prog, self.env, self.m, value, bid, self.suffix)
                    p = sub.run(n.data["parse"], 0, len(value))
                    if p != len(value):
                        raise Failure(p, ".quoted.parse", "trailing bytes in quoted content")
                else:
                    p = self.run(n.data["parse"], start + 1, close_at)
                    if p != close_at:
                        raise Failure(p, ".quoted.parse", "trailing bytes in quoted content")
            else:
                self.emit_cell(content, start + 1, close_at, value, enc, ".quoted.content")
            self.literal(close_at, close_at + 1)
            return close_at + 1
        if n.op == "optional":
            s, b = self.mark()
            try:
                return self.run(n.data["step"], start, end)
            except Failure:
                self.reset(s, b)
                return start
        if n.op == "repeated":
            pos, count, saved = start, 0, self.suffix
            while count < n.data["max"]:
                s, b = self.mark()
                p = pos
                try:
                    if count > 0 and n.data["sep"] is not None:
                        p = self.run(n.data["sep"], p, end)
                    self.suffix = f"{saved}[{count}]"
                    q = self.run(n.data["step"], p, end)
                except Failure:
                    self.suffix = saved
                    self.reset(s, b)
                    break
                self.suffix = saved
                if q == p:
                    self.reset(s, b)
                    break
                pos, count = q, count + 1
            if count < n.data["min"]:
                raise Failure(pos, ".repeated", f"only {count} occurrences, min {n.data['min']}")
            return pos
        if n.op == "csv":
            return self._csv(n, start, end)
        if n.op == "kv":
            return self._kv(n, start, end)
        if n.op == "json":
            return self._json(n, start, end)
        if n.op == "xml":
            return self._xml(n, start, end)
        raise AssertionError(n.op)

    # ------------------------------------------------------------ structured ops (1.2.0), twins of structured.go
    def _walker(self, n: Node, start: int, step: str, seps: str):
        st = {"lit": start, "seen": set()}

        def value(path: str, a: int, b: int, val: bytes, enc: str):
            self.literal(st["lit"], a)
            st["lit"] = b
            c = n.data["cells"].get(path)
            if c is not None:
                if path in st["seen"]:
                    raise Failure(a, step, f"{path!r} occurs more than once")
                st["seen"].add(path)
                self.emit_cell(c, a, b, val, enc, f"{step}[{path}]")
            elif n.data["unknown"] == "reject":
                raise Failure(a, step, f"undeclared {path!r}")
            else:
                self.opaque(_unknown_path(path, seps), a, b)
        return st, value

    def _json(self, n: Node, start: int, end: int) -> int:
        buf = self.buf
        st, value = self._walker(n, start, ".json", ".")
        ws = b" \t\n\r"

        def skip(p):
            while p < end and buf[p] in ws:
                p += 1
            return p

        def string_end(p):   # p at the opening quote; index AFTER the closing quote, or -1
            i = p + 1
            while i < end:
                if buf[i] == 0x5C:
                    i += 1
                elif buf[i] == 0x22:
                    return i + 1
                i += 1
            return -1

        def composite_end(p):
            depth = 0
            while p < end:
                ch = buf[p]
                if ch == 0x22:
                    q = string_end(p)
                    if q < 0:
                        return -1
                    p = q
                    continue
                if ch in b"[{":
                    depth += 1
                elif ch in b"]}":
                    depth -= 1
                    if depth == 0:
                        return p + 1
                p += 1
            return -1

        def obj(pos, path, depth):
            if depth > 32:
                raise Failure(pos, ".json", "nesting deeper than 32")
            pos = skip(pos + 1)
            if pos < end and buf[pos] == 0x7D:
                return pos + 1
            while True:
                if pos >= end or buf[pos] != 0x22:
                    raise Failure(pos, ".json", "expected a key")
                ke = string_end(pos)
                if ke < 0:
                    raise Failure(pos, ".json", "unterminated key")
                key = buf[pos + 1:ke - 1].decode("utf-8", "replace")
                child = key if not path else path + "." + key
                pos = skip(ke)
                if pos >= end or buf[pos] != 0x3A:
                    raise Failure(pos, ".json", f"expected ':' after key {key!r}")
                pos = skip(pos + 1)
                if pos >= end:
                    raise Failure(pos, ".json", f"value missing for {key!r}")
                ch = buf[pos]
                if ch == 0x7B:
                    pos = obj(pos, child, depth + 1)
                elif ch == 0x5B:
                    ve = composite_end(pos)
                    if ve < 0:
                        raise Failure(pos, ".json", f"unterminated array at {child!r}")
                    value(child, pos, ve, buf[pos:ve], "")
                    pos = ve
                elif ch == 0x22:
                    ve = string_end(pos)
                    if ve < 0:
                        raise Failure(pos, ".json", f"unterminated string at {child!r}")
                    val = _json_unescape(buf[pos + 1:ve - 1])
                    if val is None:
                        raise Failure(pos, ".json", f"invalid string escape or UTF-8 at {child!r}")
                    value(child, pos, ve, val, "json-string")
                    pos = ve
                else:
                    ve = pos
                    while ve < end and buf[ve] not in b" \t\n\r,}]":
                        ve += 1
                    if ve == pos:
                        raise Failure(pos, ".json", f"value missing for {key!r}")
                    value(child, pos, ve, buf[pos:ve], "")
                    pos = ve
                pos = skip(pos)
                if pos < end and buf[pos] == 0x2C:
                    pos = skip(pos + 1)
                    continue
                if pos < end and buf[pos] == 0x7D:
                    return pos + 1
                raise Failure(pos, ".json", "expected ',' or '}'")

        pos = skip(start)
        if pos >= end or buf[pos] != 0x7B:
            raise Failure(pos, ".json", "expected a JSON object")
        p = skip(obj(pos, "", 1))
        if p != end:
            raise Failure(p, ".json", "bytes after the JSON object")
        self.literal(st["lit"], end)
        return end

    def _xml(self, n: Node, start: int, end: int) -> int:
        buf = self.buf
        st, value = self._walker(n, start, ".xml", "/@")
        ws = b" \t\n\r"
        stack: list[str] = []

        def text(a, b):
            while a < b and buf[a] in ws:
                a += 1
            while b > a and buf[b - 1] in ws:
                b -= 1
            if a == b:
                return
            if not stack:
                raise Failure(a, ".xml", "text outside the root element")
            value("/".join(stack), a, b, buf[a:b], "")

        pos, root_seen = start, False
        while pos < end:
            lt = buf.find(b"<", pos, end)
            if lt < 0:
                text(pos, end)
                pos = end
                break
            text(pos, lt)
            pos = lt
            if buf.startswith(b"<!--", pos, end):
                e = buf.find(b"-->", pos, end)
                if e < 0:
                    raise Failure(pos, ".xml", "unterminated comment")
                pos = e + 3
            elif buf.startswith(b"<![CDATA[", pos, end):
                e = buf.find(b"]]>", pos, end)
                if e < 0:
                    raise Failure(pos, ".xml", "unterminated CDATA")
                if not stack:
                    raise Failure(pos, ".xml", "CDATA outside the root element")
                if e > pos + 9:
                    value("/".join(stack), pos + 9, e, buf[pos + 9:e], "")
                pos = e + 3
            elif buf.startswith(b"<?", pos, end) or buf.startswith(b"<!", pos, end):
                e = buf.find(b">", pos, end)
                if e < 0:
                    raise Failure(pos, ".xml", "unterminated declaration")
                pos = e + 1
            elif buf.startswith(b"</", pos, end):
                e = buf.find(b">", pos, end)
                if e < 0:
                    raise Failure(pos, ".xml", "unterminated end tag")
                name = buf[pos + 2:e].decode("utf-8", "replace").strip(" \t\n\r")
                if not stack or stack[-1] != name:
                    raise Failure(pos, ".xml", f"end tag </{name}> does not close the open element")
                stack.pop()
                pos = e + 1
            else:
                p = ns = pos + 1
                while p < end and buf[p] not in ws and buf[p] not in b">/":
                    p += 1
                if p == ns:
                    raise Failure(pos, ".xml", "tag without a name")
                if not stack:
                    if root_seen:
                        raise Failure(pos, ".xml", "a second root element")
                    root_seen = True
                if len(stack) >= 32:
                    raise Failure(pos, ".xml", "nesting deeper than 32")
                stack.append(buf[ns:p].decode("utf-8", "replace"))
                closed = False
                while True:
                    while p < end and buf[p] in ws:
                        p += 1
                    if p >= end:
                        raise Failure(pos, ".xml", "unterminated start tag")
                    if buf[p] == 0x3E:
                        p += 1
                        break
                    if buf[p] == 0x2F and p + 1 < end and buf[p + 1] == 0x3E:
                        p += 2
                        closed = True
                        break
                    a_s = p
                    while p < end and buf[p] != 0x3D and buf[p] not in ws and buf[p] != 0x3E:
                        p += 1
                    attr = buf[a_s:p].decode("utf-8", "replace")
                    while p < end and buf[p] in ws:
                        p += 1
                    if p >= end or buf[p] != 0x3D or not attr:
                        raise Failure(a_s, ".xml", "attribute without a value")
                    p += 1
                    while p < end and buf[p] in ws:
                        p += 1
                    if p >= end or buf[p] not in b"\"'":
                        raise Failure(p, ".xml", "attribute value must be quoted")
                    ve = buf.find(bytes([buf[p]]), p + 1, end)
                    if ve < 0:
                        raise Failure(p, ".xml", "unterminated attribute value")
                    if ve > p + 1:
                        value("/".join(stack) + "@" + attr, p + 1, ve, buf[p + 1:ve], "")
                    p = ve + 1
                if closed:
                    stack.pop()
                pos = p
        if stack:
            raise Failure(end, ".xml", f"element <{stack[-1]}> is not closed")
        if not root_seen:
            raise Failure(start, ".xml", "no root element")
        self.literal(st["lit"], end)
        return end

    def _csv(self, n: Node, start: int, end: int) -> int:
        buf, d = self.buf, n.data
        pos, idx, nf = start, 0, len(d["fields"])
        while True:
            step = f".csv.fields[{idx}]"
            cell_start = pos
            enc = ""
            if d["quote"] is not None and pos < end and buf[pos] == d["quote"]:
                close_at = scan_quoted(buf, pos + 1, end, d["quote"], d["escape"])
                if close_at < 0:
                    raise Failure(pos, step, "unterminated quoted cell")
                value, _ = unescape_quoted(buf[pos + 1:close_at], d["quote"], d["escape"])
                enc = "csv-quoted"
                pos = close_at + 1
                if pos < end and buf[pos] != d["delim"]:
                    raise Failure(pos, step, "bytes after closing quote")
            else:
                i = pos
                while i < end and buf[i] != d["delim"]:
                    i += 1
                value = buf[pos:i]
                pos = i
            if idx < nf:
                kind, item = d["fields"][idx]
                if kind == "cell":
                    self.emit_cell(item, cell_start, pos, value, enc, step)
                elif pos > cell_start:
                    if enc:
                        raise Failure(cell_start, step, "cannot sub-parse a quoted cell")
                    try:
                        p = self.run(item, cell_start, pos)
                    except Failure as f:
                        f.step = step + f.step
                        raise
                    if p != pos:
                        raise Failure(p, step, "cell sub-parse did not consume the whole cell")
            else:
                if d["extra"] == "reject":
                    raise Failure(cell_start, step, "more cells than declared")
                self.opaque(f"extra.{idx}", cell_start, pos)
            idx += 1
            if pos >= end:
                break
            self.literal(pos, pos + 1)
            pos += 1
            if pos >= end:
                if idx < nf:
                    idx += 1
                break
        if idx < nf and d["missing"] == "reject":
            raise Failure(pos, ".csv", f"only {idx} cells, {nf} declared")
        return end

    def _kv(self, n: Node, start: int, end: int) -> int:
        buf, d = self.buf, n.data
        pos, last_order = start, -1
        order_idx = {k: i for i, k in enumerate(d["order"])}
        while pos < end:
            l = _delim_run(d["pair"], buf, pos, end)
            if l:
                self.literal(pos, pos + l)
                pos += l
                continue
            km = d["keyre"].match(buf[pos:end])
            if not km or km.end() == 0:
                raise Failure(pos, ".kv", f"expected a key matching /{d['pattern']}/")
            key_end = pos + km.end()
            key = buf[pos:key_end].decode("utf-8", "replace")
            if key_end >= end or buf[key_end] != d["sep"]:
                if d["bare"] and (key_end >= end or _delim_run(d["pair"], buf, key_end, end) > 0):
                    self.literal(pos, key_end)
                    pos = key_end
                    continue
                raise Failure(pos, ".kv", f"expected {chr(d['sep'])!r} after key {key!r}")
            self.literal(pos, key_end)
            self.literal(key_end, key_end + 1)
            vpos = key_end + 1
            enc = ""
            if d["quote"] is not None and vpos < end and buf[vpos] == d["quote"]:
                close_at = scan_quoted(buf, vpos + 1, end, d["quote"], d["escape"])
                if close_at < 0:
                    raise Failure(vpos, ".kv", f"unterminated quoted value for {key!r}")
                value, _ = unescape_quoted(buf[vpos + 1:close_at], d["quote"], d["escape"])
                enc = "quoted-" + d["escape"] if d["escape"] != "none" else "csv-quoted"
                vend = close_at + 1
            else:
                vend = _token_end(d["pair"], buf, vpos, end)
                value = buf[vpos:vend]
            step = f".kv.keys[{key}]"
            if key in d["keys"]:
                if d["ordermode"] == "declared":
                    if order_idx[key] < last_order:
                        raise Failure(pos, step, f"key {key!r} out of declared order")
                    last_order = order_idx[key]
                kind, item = d["keys"][key]
                if kind == "cell":
                    self.emit_cell(item, vpos, vend, value, enc, step)
                elif vend > vpos:
                    if enc:
                        raise Failure(vpos, step, "cannot sub-parse a quoted value")
                    p = self.run(item, vpos, vend)
                    if p != vend:
                        raise Failure(p, step, "value sub-parse did not consume the whole value")
            else:
                if d["unknown"] == "reject":
                    raise Failure(pos, ".kv", f"unknown key {key!r}")
                self.opaque("unknown." + key, vpos, vend)
            pos = vend
        return end


def compile_spec(raw_bytes: bytes) -> Program:
    return Program(json.loads(raw_bytes.decode("utf-8")), raw_bytes)
