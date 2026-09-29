#!/usr/bin/env python3
"""Raw capture of what the FortiGate sends over syslog/TCP — byte for byte, before any ULPF component sees it. Standard
library. Used to record genuine device output per syslog format (default, csv, cef, json) for the pack analysis in
docs/real-device-fortigate.md.

    python3 capture.py --listen 172.20.20.1:6516 --out default.raw --seconds 60
"""
import argparse
import socket
import threading
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="172.20.20.1:6516"); ap.add_argument("--out", required=True); ap.add_argument("--seconds", type=float, default=60)
    a = ap.parse_args()
    host, port = a.listen.rsplit(":", 1)
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind((host, int(port))); srv.listen(8); srv.settimeout(0.5)
    out, lock, end, n = open(a.out, "wb"), threading.Lock(), time.time() + a.seconds, [0]

    def serve(c, peer):
        c.settimeout(0.5)
        while time.time() < end:
            try:
                b = c.recv(65536)
            except socket.timeout:
                continue
            if not b:
                break
            with lock:
                out.write(b); out.flush(); n[0] += len(b)
        c.close()
    peers = []
    while time.time() < end:
        try:
            c, peer = srv.accept()
        except socket.timeout:
            continue
        peers.append(peer)
        threading.Thread(target=serve, args=(c, peer), daemon=True).start()
    time.sleep(1)
    print(f"captured {n[0]} bytes from {peers} into {a.out}")


if __name__ == "__main__":
    main()
