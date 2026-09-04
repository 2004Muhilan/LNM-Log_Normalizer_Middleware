#!/usr/bin/env python3
"""Compute byte offsets, lengths and SHA-256 for the worked-trace Squid lines.

Golden span-map offsets must come from the bytes, not from the trace's illustrative numbers.
This prints a whitespace-run tokenisation (the positional-10 layout) for each line, plus the
sub-splits used by the promoted parser (slot 4 on '/', slot 9 on '/').
"""
import base64
import hashlib
import re
import sys

LINES = [
    b"1734567890.123    345 10.20.14.62 TCP_MISS/200 45231 GET http://example.com/index.html - HIER_DIRECT/93.184.216.34 text/html",
    b"1734567891.874     12 10.20.14.62 TCP_HIT/200 8122 GET http://example.com/logo.png - HIER_NONE/- image/png",
    b"1734567893.201    892 10.20.9.140 TCP_MISS/404 512 GET http://intra.corp.local/missing - HIER_DIRECT/10.30.2.11 text/html",
    b"1734567894.556   1204 10.20.14.62 TCP_MISS/200 331004 GET http://cdn.example.net/video.mp4 - HIER_DIRECT/151.101.1.44 video/mp4",
    b"1734567896.010     78 10.20.31.7 TCP_DENIED/403 1893 CONNECT badsite.example:443 - HIER_NONE/- text/html",
    b"1734567897.443    455 10.20.9.140 TCP_MISS/301 402 GET http://example.com/old - HIER_DIRECT/93.184.216.34 text/html",
]

for n, line in enumerate(LINES, 1):
    print(f"--- line {n}: length={len(line)} sha256={hashlib.sha256(line).hexdigest()}")
    print(f"    base64={base64.b64encode(line).decode()}")
    for m in re.finditer(rb"\s+|\S+", line):
        s, e = m.span()
        tok = m.group()
        kind = "ws" if tok.strip() == b"" else "tok"
        print(f"    [{s:3d}:{e:3d}] {kind:3s} {tok!r}")
        if kind == "tok" and b"/" in tok and not tok.startswith(b"http"):
            i = tok.index(b"/")
            print(f"        sub: [{s}:{s+i}] {tok[:i]!r}  [{s+i}:{s+i+1}] b'/'  [{s+i+1}:{e}] {tok[i+1:]!r}")
