#!/usr/bin/env python3
"""Step 5's traffic: peer B sends three lines and goes silent; peer A streams the whole mixed capture as
RFC 6587 octet-counted frames at a steady rate. Writes progress.json as it goes (for the UI)."""
import json
import socket
import sys
import time

port, capture, progress, rate = int(sys.argv[1]), sys.argv[2], sys.argv[3], float(sys.argv[4])
lines = open(capture, "rb").read().rstrip(b"\n").split(b"\n")


def frame(l: bytes) -> bytes:
    return str(len(l)).encode() + b" " + l


def write(sent_a, sent_b, done):
    json.dump({"sent_a": sent_a, "sent_b": sent_b, "total": len(lines) + 3, "done": done, "at": time.time()}, open(progress + ".tmp", "w"))
    import os
    os.replace(progress + ".tmp", progress)


b = socket.create_connection(("127.0.0.1", port))
for l in lines[:3]:
    b.sendall(frame(l))
    time.sleep(0.05)
write(0, 3, False)
# B stays connected but silent from here on: the runtime declares it silent after --silence-after
a = socket.create_connection(("127.0.0.1", port))
sent = 0
for l in lines:
    a.sendall(frame(l))
    sent += 1
    if sent % 5 == 0:
        write(sent, 3, False)
    time.sleep(1.0 / rate)
write(sent, 3, True)
time.sleep(0.5)
a.close()
b.close()
