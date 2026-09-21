#!/usr/bin/env python3
"""flowgen — the demo's log GENERATOR: a made-up flow sensor ("flowtap") that emits one line per connection,
continuously, into one of ULPF's ingress connectors — syslog over TCP with RFC 6587 octet counting (`--to host:port`)
or HTTP POST of newline-delimited lines (`--to http://host:port/`). Standard library only.
It sits entirely OUTSIDE the pipeline: it knows nothing about ULPF except a host and a port.

    flowgen.py --to 127.0.0.1:6515 --rate 8 --status gen.json --control gen.control [--drift-after N]
    flowgen.py --sample 24 [--format 2]           # print N lines and exit (tests, the fixture fallback)

THE FORMAT IS DESIGNED BACKWARDS FROM THE CERTIFICATE. Nothing in a line says what a column means:

  v1   1758350000.324 1 tcp 203.0.113.167 34350 10.4.3.103 443 6235241 78320482
       epoch.ms  verdict proto  addr port  addr port  counter counter

  - two bare IPv4 addresses (and their ports), and the sensor sees traffic in BOTH directions, so neither column is
    always the private address: nothing in the bytes says which pair is the initiator   -> endpoint_orientation
  - one bare timestamp: event time? receive time? flow start or flow end?                   -> temporal_role
  - two unlabelled counters: bytes or packets, in or out?                                  -> volume_direction (when proposed)
  - a verdict CODE, 1 = allowed, 2 = denied: a bare small integer nobody can read without being told.

  v2 ("firmware 2.0", --drift / the control file): the protocol becomes its IANA NUMBER and a zone column is appended.
       1758350000.324 1 6 203.0.113.167 34350 10.4.3.103 443 6235241 78320482 dmz
    A different arity and a different third-column class: the onboarded family's signature no longer matches. Eight of
    the ten columns are where they were, with the class they had — including everything the acceptance policy makes
    mandatory — so what the operator already said about them still holds; two columns are new information.
  v3 (control `drift-pad`, --format 3): v1 with ONE TRAILING SPACE. The router tokenises on whitespace and still routes
    the line to the v1 family; the family's parser rejects a trailing delimiter. This is the only kind of change that
    makes the monitor's `parse_success_drop` signal (routed, then refused) fire for a positional family.

Delivery: lines are queued and sent in order. `pause` in the control file closes the connection and lets the backlog
grow; `run` reconnects and sends it. The demo pauses the generator around a ULPF restart (a new pack is loaded by
restarting the runtime) so that no line sits in a socket buffer of a process that is going away: TCP has no
application acknowledgement, and an unplanned receiver crash CAN lose the lines in flight — syslog's limit, not hidden.
"""
import argparse
import collections
import json
import os
import random
import socket
import sys
import time
import http.client

ZONES = ["dmz", "lan", "guest", "mgmt"]


class Flowtap:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.n = 0

    def line(self, fmt: int, now: float, shape: str = "positional") -> str:
        r = self.rng
        self.n += 1
        inside = f"10.4.{r.randint(1, 9)}.{r.randint(2, 250)}"
        outside = f"203.0.113.{r.randint(1, 250)}"
        a, b = (outside, inside) if self.n % 3 == 1 else (inside, outside)   # both directions: no column is "the private one"
        ts = f"{now:.3f}"
        proto = r.choice(["tcp", "tcp", "udp"])
        cols = [ts, r.choice(["1", "1", "1", "2"]), {"tcp": "6", "udp": "17"}[proto] if fmt == 2 else proto, a, str(r.randint(32768, 60999)), b, str(r.choice([443, 80, 53, 22, 8443])),
                str(r.randint(100000, 9000000)), str(r.randint(100000, 90000000))]
        if fmt == 2:
            cols.append(r.choice(ZONES))
        return render(shape, cols) + (" " if fmt == 3 else "")


SHAPES = ["positional", "csv", "kv", "json", "xml", "leef"]


def render(shape: str, c: list) -> str:
    """The SAME nine (v2: ten) values in six file formats — ts verdict proto addr port addr port counter counter [zone].
    The self-describing shapes carry the vendor's own key names; a name is a hint, never evidence of what a field means."""
    zone = c[9] if len(c) > 9 else None
    num = lambda v: v if v.isdigit() else '"' + v + '"'
    if shape == "positional":
        return " ".join(c)
    if shape == "csv":
        return ",".join(c)
    if shape == "kv":
        return " ".join(f"{k}={v}" for k, v in zip(["ts", "verdict", "proto", "src", "spt", "dst", "dpt", "sent", "rcvd", "zone"], c))
    if shape == "leef":
        return "LEEF:1.0|Flowtap|FlowSensor|" + ("2.0" if zone else "1.0") + "|flow|" + "\t".join(f"{k}={v}" for k, v in zip(["devTime", "verdict", "proto", "src", "srcPort", "dst", "dstPort", "bytesOut", "bytesIn", "zone"], c))
    if shape == "json":
        return ('{"ts": %s, "verdict": %s, "proto": %s, "src": {"ip": "%s", "port": %s}, "dst": {"ip": "%s", "port": %s}, "sent": %s, "rcvd": %s' % (c[0], c[1], num(c[2]), c[3], c[4], c[5], c[6], c[7], c[8])
                + (', "zone": "%s"}' % zone if zone else "}"))
    if shape == "xml":
        return ('<flow ts="%s" verdict="%s"><proto>%s</proto><src ip="%s" port="%s"/><dst ip="%s" port="%s"/><sent>%s</sent><rcvd>%s</rcvd>' % tuple(c[:9])
                + ("<zone>%s</zone></flow>" % zone if zone else "</flow>"))
    raise ValueError(shape)


def write_status(path, d):
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser(description="flowgen: the demo's log generator (outside the pipeline)")
    ap.add_argument("--to", help="host:port of a syslog/TCP ingress (RFC 6587 octet counting)")
    ap.add_argument("--rate", type=float, default=8.0, help="lines per second")
    ap.add_argument("--seed", type=int, default=26156)
    ap.add_argument("--format", type=int, choices=[1, 2, 3], default=1)
    ap.add_argument("--shape", choices=SHAPES, default="positional", help="the file format of the lines (laptop branch): the same values as whitespace columns, CSV, key=value, JSON, XML or LEEF")
    ap.add_argument("--drift", action="store_true", help="change the format mid-run (v1 -> v2) after --drift-after lines")
    ap.add_argument("--drift-after", type=int, default=0, help="with --drift: lines of v1 before the change (0 = only when the control file says so)")
    ap.add_argument("--control", help="a file the operator writes: 'drift' switches to v2 now, 'pause' / 'run' hold and release delivery, 'finish' delivers the backlog and exits, 'stop' exits now")
    ap.add_argument("--status", help="JSON status file for the UI")
    ap.add_argument("--max-lines", type=int, default=0)
    ap.add_argument("--sample", type=int, default=0, help="print N lines to stdout and exit")
    a = ap.parse_args()
    gen = Flowtap(a.seed)
    if a.sample:
        t = 1758350000.0
        for i in range(a.sample):
            print(gen.line(a.format, t + i * 0.37 + gen.rng.random() * 0.2, a.shape))
        return 0
    if not a.to:
        ap.error("--to is required")
    is_http = a.to.startswith("http://")
    host, port = (a.to[len("http://"):].rstrip("/") if is_http else a.to).rsplit(":", 1)
    fmt, backlog, sock = a.format, collections.deque(), None
    sent = generated = reconnects = 0
    drift_at = None
    started = time.time()
    next_t = started
    last_line = ""
    recent = collections.deque(maxlen=16)   # the generator page shows the raw lines as they are produced
    paused = finishing = False
    while True:
        now = time.time()
        if a.control and os.path.exists(a.control):
            cmd = open(a.control).read().strip()
            if cmd == "stop":
                break
            if cmd == "drift" and fmt == 1:
                fmt, drift_at = 2, generated
            if cmd == "drift-pad" and fmt == 1:
                fmt, drift_at = 3, generated
            paused = cmd == "pause"
            finishing = cmd == "finish"   # generate nothing more, deliver the backlog, exit
            if paused and sock is not None:
                sock.close()
                sock = None
        if a.drift and a.drift_after and fmt == 1 and generated >= a.drift_after:
            fmt, drift_at = 2, generated
        while now >= next_t and not finishing:
            last_line = gen.line(fmt, next_t, a.shape)
            backlog.append(last_line)
            recent.append(last_line)
            generated += 1
            next_t += 1.0 / a.rate
        if sock is None and not paused:
            try:
                if is_http:
                    sock = http.client.HTTPConnection(host, int(port), timeout=2.0); sock.connect()   # one kept-alive connection: one peer
                else:
                    sock = socket.create_connection((host, int(port)), timeout=1.0)
                reconnects += 1
            except OSError:
                sock = None
        while sock is not None and backlog:
            try:
                if is_http:   # one POST per tick: every queued line, newline-delimited; a 2xx is the receiver's acknowledgement
                    batch = list(backlog)
                    sock.request("POST", "/", body=("\n".join(batch) + "\n").encode(), headers={"Content-Type": "text/plain"})
                    resp = sock.getresponse(); resp.read()
                    if resp.status // 100 != 2:
                        raise OSError(f"HTTP {resp.status}")
                    for _ in batch:
                        backlog.popleft()
                    sent += len(batch)
                else:
                    l = backlog[0].encode()
                    sock.sendall(str(len(l)).encode() + b" " + l)
                    backlog.popleft()
                    sent += 1
            except (OSError, http.client.HTTPException):
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
        write_status(a.status, {"app": "flowgen", "to": a.to, "rate": a.rate, "format": fmt, "generated": generated, "sent": sent, "backlog": len(backlog),
                                "connected": sock is not None, "paused": paused, "connections": reconnects, "drift_at_line": drift_at, "last_line": last_line, "recent": list(recent), "at": now, "pid": os.getpid()})
        if (finishing or (a.max_lines and generated >= a.max_lines)) and not backlog:
            break
        time.sleep(min(0.1, max(0.01, next_t - time.time())))
    if sock is not None:
        sock.close()
    write_status(a.status, {"app": "flowgen", "to": a.to, "rate": a.rate, "format": fmt, "generated": generated, "sent": sent, "backlog": len(backlog),
                            "connected": False, "connections": reconnects, "drift_at_line": drift_at, "last_line": last_line, "recent": list(recent), "at": time.time(), "stopped": True, "pid": os.getpid()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
