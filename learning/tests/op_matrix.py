"""Op-coverage matrix — the executor-alignment policy (P3 report §5, decided in P4).

Two executors implement one closed op set: `learning/ulpf_learn/dslexec.py` (reference) and
`runtime/internal/dsl` (engine). The corpus differential only exercises what the corpus exercises, so
drift lands first in the newest paths. This module enumerates the contract's own enums — every op,
token class, coerce kind, timestamp kind, timezone mode, decode encoding, on_failure branch, csv/kv/
positional/quoted policy value, both schema versions, spec- and cell-level null_values — and pairs each
value with at least one micro-vector (a valid spec plus success and failure inputs). The test fails when
an enum value has no vector, so a construct cannot enter the schema without a vector both stacks must
pass, and fails when the two executors disagree on any vector's span map.
"""
from __future__ import annotations

import base64

BOUNDS = {"max_event_bytes": 8192, "max_fields": 64, "max_nesting": 6, "max_repeat": 16}


def spec(spec_id: str, root, version: str = "1.1.0", **extra) -> dict:
    d = {"schema_version": version, "spec_id": spec_id, "description": f"op-matrix vector {spec_id}", "regex_dialect": "re2", "bounds": BOUNDS}
    d.update(extra)
    d["root"] = root
    return d


def cell(field: str, cls: str | None = None, **kw) -> dict:
    c = {"field": field, "kind": "semantic"}
    if cls:
        c["class"] = cls
    c.update(kw)
    return c


def opaque(field: str) -> dict:
    return {"field": field, "kind": "opaque"}


def coerce(to: str, on_failure: str = "reject", **kw) -> dict:
    return {"op": "coerce", "to": to, "on_failure": on_failure, **kw}


def ws_positional(slots, leading="reject", trailing="reject", tail=None, delimiter=None) -> dict:
    return {"op": "positional", "delimiter": delimiter or {"whitespace_run": True}, "leading_delimiter": leading, "trailing_delimiter": trailing, "tail": tail, "slots": slots}


def kv(keys, pair_sep=None, unknown="opaque", order="any", escape="backslash", quote='"', **kw) -> dict:
    return {"op": "kv", "pair_separator": pair_sep or {"whitespace_run": True}, "key_value_separator": "=", "quote": quote, "escape": escape,
            "key_pattern": "[a-z_][a-z0-9_]*", "keys": keys, "unknown_keys": unknown, "order": order, **kw}


def csv(fields, quote='"', escape="doubled", extra="opaque", missing="allow") -> dict:
    return {"op": "csv", "delimiter": ",", "quote": quote, "escape": escape, "fields": fields, "extra_fields": extra, "missing_fields": missing}


V: list[dict] = []


def vec(name, sp, ok: list[str], fail: list[str] = ()):
    V.append({"name": name, "spec": sp, "inputs": [s.encode() if isinstance(s, str) else s for s in list(ok) + list(fail)],
              "expect_ok": [True] * len(ok) + [False] * len(fail)})


# ---------------------------------------------------------------- ops: literal, regex, optional, repeated
vec("literal-seq", spec("m-literal", [{"op": "literal", "text": "A"}, {"op": "literal", "text": "B"}], version="1.0.0"), ["AB"], ["AC", "A", "ABC"])
vec("regex-captures", spec("m-regex", {"op": "regex", "pattern": "id=(?P<id>[0-9]+)(?: user=(?P<user>[a-z]+))? tag=(?P<tag>\\S+)",
                                        "captures": {"id": cell("id", "integer"), "user": cell("user", "word"), "tag": opaque("tag")}}),
    ["id=12 user=bob tag=x/y", "id=7 tag=z"], ["id=x tag=z", "id=12 user=bob"])
vec("optional", spec("m-optional", [{"op": "literal", "text": "a"}, {"op": "optional", "step": {"op": "literal", "text": "-opt"}}, {"op": "literal", "text": "z"}]),
    ["a-optz", "az"], ["a-opz"])
vec("repeated", spec("m-repeated", {"op": "repeated", "min": 1, "max": 3, "separator": {"op": "literal", "text": ","},
                                     "step": {"op": "regex", "pattern": "(?P<n>[0-9]+)", "captures": {"n": cell("n", "integer")}}}),
    ["1", "1,22,333"], ["1,2,3,4", "a"])
vec("repeated-min0", spec("m-repeated0", [{"op": "literal", "text": "["}, {"op": "repeated", "min": 0, "max": 2, "step": {"op": "literal", "text": "x"}}, {"op": "literal", "text": "]"}]),
    ["[]", "[x]", "[xx]"], ["[xxx]"])

# ---------------------------------------------------------------- positional: delimiter forms, slot forms, policies, tail
vec("positional-ws", spec("m-pos-ws", ws_positional([cell("a", "word"), {"token": {"parse": {"op": "regex", "pattern": "(?P<x>[a-z]+)/(?P<y>[0-9]+)", "captures": {"x": cell("x", "word"), "y": cell("y", "integer")}}}},
                                                     {"step": {"op": "quoted", "open": '"', "close": '"', "escape": "none", "content": cell("q", "text")}}])),
    ['hello ab/12 "with space"', 'hi\t  cd/3 "x"'], ['hello ab/12 nq', ' hello ab/12 "q"', 'hello ab/12 "q" '])
vec("positional-allow", spec("m-pos-allow", ws_positional([cell("a", "word"), cell("b", "integer")], leading="allow", trailing="allow", tail=cell("rest", "text"))),
    ["a 1", "  a 1 the rest of it  ", "a 1 tail"], ["a x"])
vec("positional-char", spec("m-pos-char", ws_positional([cell("a", "word"), cell("b", "word")], delimiter={"char": "|"})), ["x|y"], ["x|", "x"])
vec("positional-string", spec("m-pos-str", ws_positional([cell("a", "word"), cell("b", "word")], delimiter={"string": "::"})), ["x::y"], ["x:y"])

# ---------------------------------------------------------------- quoted: escape schemes, nested parse
vec("quoted-backslash", spec("m-quoted-bs", {"op": "quoted", "open": '"', "close": '"', "escape": "backslash", "content": cell("s", "text")}), ['"a\\"b"', '"plain"'], ['"open', 'x'])
vec("quoted-doubled", spec("m-quoted-dbl", {"op": "quoted", "open": "'", "close": "'", "escape": "doubled", "content": cell("s", "text")}), ["'it''s'", "'a'"], ["'a"])
vec("quoted-none-parse", spec("m-quoted-parse", {"op": "quoted", "open": "[", "close": "]", "escape": "none", "content": cell("inner", "text"),
                                                   "parse": ws_positional([cell("m", "word"), cell("u", "url")])}), ["[GET http://h/p]"], ["[GET]"])

# ---------------------------------------------------------------- csv: quote/escape/extra/missing, sub-parse cell, null quote
vec("csv-doubled-opaque-allow", spec("m-csv-1", csv([cell("a", "word"), cell("b", "text"), {"parse": ws_positional([cell("c1", "integer"), cell("c2", "integer")])}])),
    ['x,"say ""hi"", ok",1 2', "x,y,3 4,extra1,extra2", "x,y", "x,,1 2"], ["x,y,1 x"])
vec("csv-backslash-reject-reject", spec("m-csv-2", csv([cell("a", "word"), cell("b", "text")], escape="backslash", extra="reject", missing="reject")),
    ['x,"a\\"b"'], ["x,y,z", "x"])
vec("csv-none-noquote", spec("m-csv-3", csv([cell("a", "word"), cell("b", "word")], quote=None, escape="none", missing="reject")), ["x,y"], ["x", "x,y z", 'x,"y"'])

# ---------------------------------------------------------------- kv: separators, quote/escape, unknown keys, order, bare keys
vec("kv-any-opaque", spec("m-kv-1", kv({"src": cell("src", "ipv4"), "msg": cell("msg", "text"), "n": {"parse": {"op": "regex", "pattern": "(?P<v>[0-9]+)", "captures": {"v": cell("v", "integer")}}}})),
    ['src=10.0.0.1 msg="a \\"q\\" b" n=5', 'msg=plain src=1.2.3.4 other=zz n=1'], ["src=notanip n=1"])
vec("kv-declared-reject-doubled", spec("m-kv-2", kv({"a": cell("a", "word"), "b": cell("b", "text")}, unknown="reject", order="declared", escape="doubled", pair_sep={"char": ";"})),
    ["a=x;b='v'", 'a=x;b="it""s"', "b=only"], ["b=1;a=2", "a=1;zz=2"])
vec("kv-none-string-sep-bare", spec("m-kv-3", kv({"a": cell("a", "word"), "flag": cell("flag", "word")}, escape="none", quote=None, pair_sep={"string": ", "}, allow_bare_keys=True)),
    ["a=x, flag", "a=x"], ["a=x, =y"])

# ---------------------------------------------------------------- decode: every encoding, then-step, on_failure
b64 = base64.b64encode(b"k=v m=2").decode()
vec("decode-base64-then", spec("m-dec-b64", ws_positional([cell("h", "word"), cell("payload", "text", decode={"op": "decode", "encoding": "base64", "on_failure": "reject",
                                                                                                                  "then": kv({"k": cell("k", "word"), "m": cell("m", "integer")}, quote=None, escape="none")})])),
    [f"hdr {b64}"], ["hdr !!!notb64!!!"])
vec("decode-hex-opaque", spec("m-dec-hex", ws_positional([cell("p", "text", decode={"op": "decode", "encoding": "hex", "on_failure": "opaque"})])), ["6869", "zz"], [])
vec("decode-url", spec("m-dec-url", ws_positional([cell("p", "text", decode={"op": "decode", "encoding": "url", "on_failure": "reject"})])), ["a%20b%2Fc"], ["%zz"])
vec("decode-json-string", spec("m-dec-json", ws_positional([cell("p", "text", decode={"op": "decode", "encoding": "json-string", "on_failure": "reject"})])), ['a\\nb\\u0041'], ["\\uZZZZ"])
vec("decode-c-escape", spec("m-dec-c", ws_positional([cell("p", "text", decode={"op": "decode", "encoding": "c-escape", "on_failure": "reject"})])), ["a\\tb\\x41"], ["\\x4"])
vec("decode-cef", spec("m-dec-cef", ws_positional([cell("p", "text", decode={"op": "decode", "encoding": "cef-extension", "on_failure": "reject"})])), ["a\\=b\\\\c\\r"], [])

# ---------------------------------------------------------------- coerce: every target, timestamp kinds, timezone modes, formats list, enum, on_failure
vec("coerce-scalars", spec("m-coerce-1", ws_positional([
    cell("s", "word", coerce=coerce("string")), cell("i", "integer", coerce=coerce("int")), cell("f", "float", coerce=coerce("float")),
    cell("b", "word", coerce=coerce("bool")), cell("v4", "ipv4", coerce=coerce("ipv4")), cell("v6", "ipv6", coerce=coerce("ipv6")),
    cell("ip", "ip", coerce=coerce("ip")), cell("mac", "mac", coerce=coerce("mac")), cell("e", "word", coerce=coerce("enum", values=["allow", "deny"])),
    cell("bad", "word", coerce=coerce("int", on_failure="opaque"))])),
    ["x 12 1.5 true 10.0.0.1 fe80::1 192.168.0.1 00:11:22:33:44:55 allow notint", "y -3 2.0 false 1.1.1.1 ::1 ::2 aa-bb-cc-dd-ee-ff deny 7"],
    ["x 12 1.5 maybe 10.0.0.1 fe80::1 192.168.0.1 00:11:22:33:44:55 allow 1", "x 12 1.5 true 10.0.0.1 fe80::1 192.168.0.1 00:11:22:33:44:55 other 1"])
vec("coerce-epochs", spec("m-coerce-ts1", ws_positional([
    cell("a", "integer", coerce=coerce("timestamp", format={"kind": "epoch_s"})), cell("b", "integer", coerce=coerce("timestamp", format={"kind": "epoch_ms"})),
    cell("c", "integer", coerce=coerce("timestamp", format={"kind": "epoch_us"})), cell("d", "integer", coerce=coerce("timestamp", format={"kind": "epoch_ns"})),
    cell("e", "float", coerce=coerce("timestamp", format={"kind": "epoch_s_frac"})), cell("f", "integer", coerce=coerce("timestamp", format={"kind": "epoch_auto"})),
    cell("g", "integer", coerce=coerce("timestamp", on_failure="opaque", format={"kind": "epoch_auto"}))])),
    ["1734567890 1734567890123 1734567890123456 1734567890123456789 1734567890.5 1734567890 1734567890123", "1 2 3 4 5.25 1734567890123456789 12"],
    ["1734567890 1734567890123 1734567890123456 1734567890123456789 1734567890.5 12 1"])
vec("coerce-textual-ts", spec("m-coerce-ts2", ws_positional([
    cell("a", "text", coerce=coerce("timestamp", format={"kind": "rfc3339", "timezone": "in_value"})),
    {"step": {"op": "quoted", "open": "[", "close": "]", "escape": "none", "content": cell("b", "text", coerce=coerce("timestamp", format={"kind": "rfc3164", "assume_year": 2024, "timezone": "utc"}))}},
    {"step": {"op": "quoted", "open": "[", "close": "]", "escape": "none", "content": cell("c", "text", coerce=coerce("timestamp", format={"kind": "pattern", "pattern": "%d/%b/%Y:%H:%M:%S %z", "timezone": "in_value"}))}},
    {"step": {"op": "quoted", "open": "(", "close": ")", "escape": "none", "content": cell("d", "text", coerce=coerce("timestamp", formats=[{"kind": "pattern", "pattern": "%Y/%m/%d %H:%M:%S", "timezone": "source"}, {"kind": "rfc3339", "timezone": "in_value"}]))}},
    {"step": {"op": "quoted", "open": "<", "close": ">", "escape": "none", "content": cell("e", "text", coerce=coerce("timestamp", format={"kind": "rfc3164", "assume_year": "ingest", "timezone": "utc"}))}}])),
    ["2024-01-05T10:00:01Z [Jan  5 10:00:01] [05/Jan/2024:10:00:01 +0000] (2024/01/05 10:00:01) <Feb  3 04:05:06>",
     "2024-01-05T10:00:01.250+02:00 [Jan 15 10:00:01] [5/Jan/2024:6:09:59 -0500] (2021-05-26T16:27:07.000000Z) <Dec 31 23:59:59>"],
    ["notatime [Jan  5 10:00:01] [05/Jan/2024:10:00:01 +0000] (2024/01/05 10:00:01) <Feb  3 04:05:06>",
     "2024-01-05T10:00:01Z [Jan  5 10:00:01] [05/Jan/2024:10:00:01 +0000] (nope) <Feb  3 04:05:06>"])

# ---------------------------------------------------------------- token classes: every class accepts and rejects
vec("classes", spec("m-classes", ws_positional([
    cell("c1", "integer"), cell("c2", "float"), cell("c3", "ipv4"), cell("c4", "ipv6"), cell("c5", "ip"), cell("c6", "mac"), cell("c7", "url"),
    cell("c8", "hostname"), cell("c9", "uuid"), cell("c10", "hex"), cell("c11", "word"), cell("c12", "text")])),
    ["42 3.14 10.1.2.3 2001:db8::1 10.0.0.1 00:11:22:33:44:55 http://ex.org/a?b=c host.example.com 123e4567-e89b-12d3-a456-426614174000 deadBEEF w_ord any/thing:here",
     "-1 -0.5 255.255.255.255 ::1 ::1 aa:bb:cc:dd:ee:ff host:443 h 00000000-0000-0000-0000-000000000000 00 w \"q\""],
    ["4.2 3.14 10.1.2.3 2001:db8::1 10.0.0.1 00:11:22:33:44:55 http://ex.org host 123e4567-e89b-12d3-a456-426614174000 ff w t",
     "42 3.14 999.1.2.3 2001:db8::1 10.0.0.1 00:11:22:33:44:55 http://ex.org host 123e4567-e89b-12d3-a456-426614174000 ff w t",
     "42 3.14 10.1.2.3 2001:db8::1 10.0.0.1 00:11:22:33:44 http://ex.org host 123e4567-e89b-12d3-a456-426614174000 ff w t",
     "42 3.14 10.1.2.3 2001:db8::1 10.0.0.1 00:11:22:33:44:55 http://ex.org host 123e4567-e89b-12d3-a456-426614174000 fg w t"])
for cls, ok, bad in [("uuid", "123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-42661417400"), ("hex", "0aF9", "0aG9"),
                     ("hostname", "a-b.example.org", "-bad.example"), ("ipv6", "fe80::1", "10.0.0.1"), ("url", "https://x/y", "a!b"), ("float", "1.0", "1.x")]:  # url also accepts host[:port][/path] forms and float accepts integers (widening), by design in both stacks
    vec(f"class-{cls}", spec(f"m-class-{cls}", ws_positional([cell("v", cls)])), [ok], [bad])

# ---------------------------------------------------------------- null values: spec-level default, cell override, opt-out; both schema versions
vec("null-values", spec("m-nulls", ws_positional([cell("a", "ipv4"), cell("b", "integer", null_values=["N/A"]), cell("c", "word", null_values=[]), cell("d", "integer", coerce=coerce("int"))]), null_values=["-"]),
    ["- N/A - 5", "10.0.0.1 7 x -"], ["- - - 5", "10.0.0.1 N/A y notint", "1.2.3.4 - x 1"])  # b's override replaces the spec default: '-' is not a null there
vec("v1-0-0-plain", spec("m-v100", ws_positional([cell("a", "word"), cell("b", "integer", coerce=coerce("int"))]), version="1.0.0"), ["x 1"], ["x y"])
