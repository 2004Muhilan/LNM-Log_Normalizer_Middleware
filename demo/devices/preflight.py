#!/usr/bin/env python3
"""Pre-flight for the real-device demo (start-demo.sh devices runs it first; a person can too). Standard library.
Runs in the ULPF distro (Ubuntu), BEFORE ULPF listens on :6515.

    python3 demo/devices/preflight.py [--leave-connected]

1. the Containerlab distro is kept up WITHOUT a window: a hidden Windows-side `wsl.exe -d Containerlab` session holding
   `ulpf-clab-keepalive` (started once; the distro otherwise stops when its last window closes, and the FortiGate with it)
2. the FortiGate's licence reads Valid (else STOP: one evaluation per account); every lab container is running (a stopped
   one is started — `docker start` only, never containerlab deploy); the traffic loop runs (restarted if not)
3. both devices really reach ULPF's syslog ingress: a throwaway listener on 0.0.0.0:6515 (the port ULPF will use), each
   device connected, bytes from 172.20.20.2 and 172.20.20.11 awaited. The FortiGate is RECONNECTED automatically when it
   does not send (re-committing its syslog setting restarts FortiOS's backed-off reliable-syslog connection)
4. both disconnected again (unless --leave-connected): the demo's first step connects them on stage
Exit 0 only when all of it holds; the report says what was fixed on the way.
"""
import argparse
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = str(ROOT / "demo" / "devices" / "lab.sh")
FGT, IDS = "172.20.20.2", "172.20.20.11"
REPORT = []


def say(ok, what, detail=""):
    REPORT.append((ok, what, detail))
    print(f"  {'ok  ' if ok is True else 'FIX ' if ok == 'fixed' else 'FAIL'}  {what}" + (f"  — {detail}" if detail else ""), flush=True)


def lab(*args, timeout=180):
    r = subprocess.run(["wsl.exe", "-d", "Containerlab", "--", "bash", LAB, *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).replace("\r", "")


def clab_sh(cmd, timeout=120):
    r = subprocess.run(["wsl.exe", "-d", "Containerlab", "--", "bash", "-c", cmd], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).replace("\r", "")


def status():
    rc, out = lab("status", timeout=90)
    return {k.strip(): v.strip() for k, v in (l.split("=", 1) for l in out.splitlines() if "=" in l)}


def keepalive():
    rc, out = clab_sh("pgrep -f [u]lpf-clab-keepalive > /dev/null && echo running || echo none")
    if "running" in out:
        return say(True, "Containerlab distro kept up without a window", "keep-alive session already running")
    # a hidden Windows process, detached from this shell: it outlives every terminal window
    # Start-Process joins -ArgumentList with spaces: the bash -c script must travel as ONE quoted argument
    subprocess.run(["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-Command",
                    "Start-Process -WindowStyle Hidden -FilePath wsl.exe -ArgumentList '-d','Containerlab','--','bash','-c','\"exec -a ulpf-clab-keepalive sleep infinity\"'"],
                   capture_output=True, text=True, timeout=60)
    for _ in range(20):
        rc, out = clab_sh("pgrep -f [u]lpf-clab-keepalive > /dev/null && echo running || echo none")
        if "running" in out:
            return say("fixed", "Containerlab distro kept up without a window", "hidden keep-alive session started (wsl.exe -d Containerlab, ulpf-clab-keepalive)")
        time.sleep(1)
    say(False, "Containerlab distro kept up without a window", "the keep-alive session did not start")


class Probe:
    """A throwaway syslog/TCP listener on ULPF's own port: which peers connect and send bytes."""

    def __init__(self, addr=("0.0.0.0", 6515)):
        self.seen, self.lock = {}, threading.Lock()
        self.s = socket.socket(); self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(addr); self.s.listen(16); self.s.settimeout(0.5)
        self.stop = False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stop:
            try:
                c, (host, _) = self.s.accept()
            except OSError:
                continue
            threading.Thread(target=self.read, args=(c, host), daemon=True).start()

    def read(self, c, host):
        c.settimeout(1)
        while not self.stop:
            try:
                b = c.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not b:
                break
            with self.lock:
                self.seen[host] = self.seen.get(host, 0) + len(b)
        c.close()

    def bytes_from(self, host):
        with self.lock:
            return self.seen.get(host, 0)

    def close(self):
        self.stop = True
        self.s.close()


def await_bytes(p, host, seconds, nudge=None):
    end = time.time() + seconds
    n0 = p.bytes_from(host)
    while time.time() < end:
        if p.bytes_from(host) > n0:
            return True
        if nudge and time.time() > end - seconds / 2:
            nudge(); nudge = None
        time.sleep(1)
    return False


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--leave-connected", action="store_true")
    a = ap.parse_args()
    print("device pre-flight (real-device demo):", flush=True)
    keepalive()
    st = status()
    if not st:
        say(False, "the lab answers", "demo/devices/lab.sh status returned nothing — is the Containerlab distro installed?"); return 1
    lic = st.get("fgt_License_Status")
    say(lic == "Valid", "FortiGate licence", f"{lic} · serial {st.get('fgt_Serial-Number')} · {st.get('fgt_Version', '').replace('_', ' ')}")
    if lic != "Valid":
        print("STOP: the licence is not Valid — do not redeploy anything; see docs/real-device-fortigate.md"); return 2
    for c in ("clab-fortigate-fgt", "fgt-client", "fgt-server", "fgt-ids", "fgt-ids-syslog"):
        if st.get(f"container_{c}") == "running" or c == "fgt-ids-syslog":   # the forwarder is connected below
            if c != "fgt-ids-syslog":
                say(True, f"container {c} running")
            continue
        if c == "clab-fortigate-fgt":
            say(False, "container clab-fortigate-fgt running", "start it: wsl -d Containerlab -- bash demo/devices/fortigate/start.sh (docker start only)"); return 1
        clab_sh(f"docker start {c}")
        say("fixed", f"container {c} running", "was stopped: started (docker start)")
    if st.get("traffic_loop") != "running":
        clab_sh(f"docker cp {ROOT}/demo/devices/fortigate/traffic.sh fgt-client:/traffic.sh; docker exec -d fgt-client sh /traffic.sh")
        say("fixed", "traffic loop in fgt-client", "was not running: started")
    else:
        say(True, "traffic loop in fgt-client")
    try:
        p = Probe()
    except OSError as ex:
        say(False, "ULPF's syslog port 6515 is free for the check", f"{ex} — stop the demo first (bash demo/start-demo.sh stop)"); return 1
    try:
        lab("fgt-connect", "default")   # the demo starts from the device's default format
        ok = await_bytes(p, FGT, 40)
        if not ok:
            lab("fgt-connect", "default")   # the automatic reconnect: a re-commit restarts FortiOS's backed-off reliable-syslog connection
            ok = await_bytes(p, FGT, 40)
            say("fixed" if ok else False, "FortiGate reaches ULPF's syslog ingress (TCP 6515)", "it did not send at first: syslog re-committed automatically" if ok else "no bytes after two attempts")
        else:
            say(True, "FortiGate reaches ULPF's syslog ingress (TCP 6515)", f"{p.bytes_from(FGT)} bytes from {FGT}")
        lab("ids-connect")
        ok = await_bytes(p, IDS, 60, nudge=lambda: lab("attack"))
        say(ok, "Suricata reaches ULPF's syslog ingress (TCP 6515)", f"{p.bytes_from(IDS)} bytes from {IDS} (through its rsyslog forwarder)" if ok else "no alert forwarded within 60 s (attack traffic sent to provoke one)")
    finally:
        if not a.leave_connected:
            lab("fgt-disconnect"); lab("ids-disconnect")
            print("  both devices disconnected again: the demo's first step connects them on stage", flush=True)
        p.close()
    failed = [r for r in REPORT if r[0] is False]
    print(f"DEVICE PRE-FLIGHT: {'PASS' if not failed else str(len(failed)) + ' FAIL'}" + (f" ({sum(1 for r in REPORT if r[0] == 'fixed')} fixed on the way)" if any(r[0] == 'fixed' for r in REPORT) else ""))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
