#!/usr/bin/env python3
"""Replay senders for the capacity measurement (scripts/bench/capacity.py). Standard library only.

    python3 scripts/bench/replay.py --to 127.0.0.1:7700 --senders 32 --devices devices.json --duration 180 [--rate 0] --status S.json --out R.json

One process, one thread per sender. Sender k connects from its OWN loopback address 127.0.1.(k+1) (an ephemeral source
port of its own) and replays pre-built log files — the device formats in --devices ({"asa": path, "panos": path, ...}),
interleaved one line of each in turn, as a syslog relay carries several devices — over TCP with octet counting (RFC
6587), from its own offset, wrapping around. Interleaved, not one format per sender: the kernel's socket buffers hold
megabytes per connection, so with one format per sender the mix ULPF processes would drift with which buffers drain
first (short lines pile up by the hundred thousand). The frames are built once, before the clock starts, into chunks of
up to 256 frames: the steady state is one sendall() per chunk, so a sender costs almost nothing per event.

  --rate 0   as fast as the receiver takes it (TCP backpressure: the measured rate is the receiver's)
  --rate R   R events/s in total, paced evenly over the senders

Every sender connects first; then all start together. At --duration each stops after its current chunk and closes: a
chunk is counted as sent only when sendall() returned, so "sent" is exact to the frame. The status file (every second)
carries the running total; the out file the per-sender totals, source address and port, and any reconnect.
"""
import argparse
import json
import os
import socket
import threading
import time


def frames_of(path):
    return [b"%d %s" % (len(l), l) for l in open(path, "rb").read().splitlines() if l.strip()]


def chunks_of(frames, start, size, count):
    n, out, i = len(frames), [], start
    for _ in range(count):
        out.append((b"".join(frames[(i + k) % n] for k in range(size)), size))
        i += size
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True); ap.add_argument("--senders", type=int, required=True); ap.add_argument("--devices", required=True)
    ap.add_argument("--duration", type=float, required=True); ap.add_argument("--rate", type=float, default=0)
    ap.add_argument("--status", required=True); ap.add_argument("--out", required=True); ap.add_argument("--base", default="127.0.1.")
    a = ap.parse_args()
    host, port = a.to.rsplit(":", 1)
    devices = json.load(open(a.devices))
    names = sorted(devices)
    per_rate = a.rate / a.senders if a.rate else 0
    size = 256 if not per_rate else max(1, min(256, int(per_rate / 20)))   # paced: ~20 sends per second per sender
    frames = {n: frames_of(devices[n]) for n in names}
    # one interleaved stream: format j mod F at position j, each format walking through its own file — equal counts of
    # every format in any stretch of any sender's stream, so the mix ULPF sees cannot drift with which connection it reads
    longest = max(len(f) for f in frames.values())
    mixed = [frames[names[j % len(names)]][(j // len(names)) % len(frames[names[j % len(names)]])] for j in range(longest * len(names))]
    S = []
    for k in range(a.senders):
        S.append({"k": k, "src": a.base + str(k + 1), "format": "+".join(names), "chunks": chunks_of(mixed, (k * 7919 * len(names)) % len(mixed), size, 32),
                  "sent": 0, "ports": [], "reconnects": 0, "error": None})

    def connect(s):
        for _ in range(400):
            try:
                c = socket.socket()
                c.bind((s["src"], 0))
                c.connect((host, int(port)))
                s["ports"].append(c.getsockname()[1])
                return c
            except OSError as e:
                s["error"] = str(e)
                time.sleep(0.05)
        raise SystemExit(f"sender {s['k']} could not connect: {s['error']}")

    for s in S:
        s["sock"] = connect(s)
    go = threading.Event()
    T = {}

    def run(s):
        go.wait()
        t0, end, c, j = T["t0"], T["t0"] + a.duration, s["sock"], 0
        while True:
            now = time.time()
            if now >= end:
                break
            if per_rate:
                due = t0 + s["sent"] / per_rate
                if due > now:
                    time.sleep(min(due - now, end - now))
                    continue
            blob, n = s["chunks"][j % len(s["chunks"])]
            try:
                c.sendall(blob)
            except OSError as e:
                s["reconnects"] += 1; s["error"] = str(e)
                c.close(); c = connect(s)   # the chunk counts as not sent: it is sent again
                continue
            s["sent"] += n
            j += 1
        s["t_last"] = time.time()
        c.close()

    th = [threading.Thread(target=run, args=(s,), daemon=True) for s in S]
    [t.start() for t in th]
    T["t0"] = time.time()
    go.set()

    def status(done=False):
        tmp = a.status + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"t0": T["t0"], "at": time.time(), "sent": sum(s["sent"] for s in S), "done": done}, f)
        os.replace(tmp, a.status)

    while any(t.is_alive() for t in th):
        status()
        for t in th:
            t.join(timeout=1.0 / len(th))
    status(done=True)
    ru = __import__("resource").getrusage(__import__("resource").RUSAGE_SELF)
    json.dump({"t0": T["t0"], "t1": max(s["t_last"] for s in S), "sent": sum(s["sent"] for s in S), "rate": a.rate, "chunk_frames": size, "cpu_s": ru.ru_utime + ru.ru_stime,
               "senders": [{k: s[k] for k in ("k", "src", "format", "sent", "ports", "reconnects", "error", "t_last")} for s in S]}, open(a.out, "w"))


if __name__ == "__main__":
    main()
