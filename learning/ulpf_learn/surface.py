"""Surface facts of a payload — the Python twin of the runtime router's L2–L4 reading
(runtime/internal/route/router.go: detectL2, csvCells, kvPairs, classify). Used by family discovery
(cluster a capture without parsing it) and by tests that check the two stacks read the same surface.
Never a parser: leading bytes, delimiter counts, token classes, anchor locators."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_INT = re.compile(r"^-?[0-9]+$")
_FLOAT = re.compile(r"^-?[0-9]+\.[0-9]+$")
_WORD = re.compile(r"^[A-Za-z0-9_.:\-]+$")
_HOSTP = re.compile(r"^[A-Za-z0-9.\-]+:[0-9]+$")
_KVTOK = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*=")


def classify(tok: str) -> str:
    if _INT.match(tok):
        return "integer"
    if _FLOAT.match(tok):
        return "float"
    if tok.count(".") == 3:
        try:
            ipaddress.IPv4Address(tok)
            return "ipv4"
        except ValueError:
            pass
    if "://" in tok or _HOSTP.match(tok):
        return "url"
    if _WORD.match(tok):
        return "word"
    return "text"


@dataclass
class Surface:
    l2: str
    toks: list[str] = field(default_factory=list)
    cells: list[str] = field(default_factory=list)
    pairs: dict[str, str] = field(default_factory=dict)
    arity: int = 0


def csv_cells(b: bytes) -> list[str]:
    cells, cur, inq = [], [], False
    i = 0
    while i < len(b):
        c = b[i:i + 1]
        if c == b'"':
            if inq and b[i + 1:i + 2] == b'"':
                cur.append(b'"')
                i += 2
                continue
            inq = not inq
        elif c == b"," and not inq:
            cells.append(b"".join(cur).decode("utf-8", "replace"))
            cur = []
        else:
            cur.append(c)
        i += 1
    cells.append(b"".join(cur).decode("utf-8", "replace"))
    return cells


def kv_pairs(b: bytes) -> tuple[dict[str, str], int]:
    out: dict[str, str] = {}
    n, i = 0, 0
    L = len(b)
    while i < L:
        while i < L and b[i] in b" \t":
            i += 1
        start = i
        while i < L and b[i] not in b"= \t":
            i += 1
        if i >= L or b[i] != ord("="):
            while i < L and b[i] not in b" \t":
                i += 1
            continue
        key = b[start:i].decode("utf-8", "replace")
        i += 1
        if i < L and b[i] == ord('"'):
            i += 1
            buf = []
            while i < L and b[i] != ord('"'):
                if b[i] == ord("\\") and i + 1 < L:
                    i += 1
                buf.append(b[i:i + 1])
                i += 1
            i += 1
            val = b"".join(buf).decode("utf-8", "replace")
        else:
            vs = i
            while i < L and b[i] not in b" \t":
                i += 1
            val = b[vs:i].decode("utf-8", "replace")
        n += 1
        out.setdefault(key, val)
    return out, n


def detect(payload: bytes) -> Surface:
    t = payload.lstrip(b" \t")
    if t[:1] in (b"{", b"["):
        return Surface("json")
    toks = payload.decode("utf-8", "replace").split()
    if sum(1 for tk in toks[:6] if _KVTOK.match(tk)) >= 3:
        pairs, n = kv_pairs(payload)
        return Surface("kv", pairs=pairs, arity=n)
    cells = csv_cells(payload)
    if len(cells) >= 9:
        return Surface("csv", cells=cells, arity=len(cells))
    return Surface("tokens", toks=toks, arity=len(toks))


def locate(anchor: dict, payload: bytes, s: Surface, env: dict | None) -> str | None:
    loc = anchor["locator"]
    kind = loc["kind"]
    if kind == "pattern":
        m = re.search(loc["pattern"], payload.decode("utf-8", "replace"))
        return m.group("anchor") if m else None
    if kind == "slot":
        seq = s.cells if s.l2 == "csv" else s.toks if s.l2 == "tokens" else []
        i = loc["slot_index"]
        return seq[i] if i < len(seq) else None
    if kind == "key":
        return s.pairs.get(loc["key"]) if s.l2 == "kv" else None
    if kind == "envelope_header":
        return (env or {}).get(loc.get("header_field")) or None
    return None


def in_domain(anchor: dict, value: str) -> bool:
    d = anchor["expected_value_domain"]
    if d["kind"] == "enum":
        return value in d["values"]
    return re.fullmatch(d["pattern"], value) is not None
