"""The real devices, seen and driven from the System page (the final demo, 2026-09-30): the licensed FortiGate VM and the
Suricata sensor in the Containerlab distro. Every action is demo/devices/lab.sh run in that distro — the same commands a
person would type, logged with their output. Standard library.

The presenter never needs a terminal: connect / disconnect each device's syslog (its ingress connector into ULPF), switch
the FortiGate's log format live, make admin logins (real system events), send attack traffic through the FortiGate
(which Suricata sees on the same wire). Reliability (`ensure`): the licence must read Valid; a device that should be
connected but is not sending is reconnected — for the FortiGate by re-committing its syslog setting, which is what
restarts FortiOS's backed-off reliable-syslog connection.
"""
from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = str(ROOT / "demo" / "devices" / "lab.sh")
FGT, IDS = "172.20.20.2", "172.20.20.11"


class Devices:
    FGT, IDS = FGT, IDS
    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.lock = threading.Lock()
        self.status: dict = {}
        self.checked_at = 0.0
        self.busy: str | None = None        # the action in progress, shown on the page
        self.history: list[dict] = []       # every action: what, when, its output, how long
        self.format = "default"

    def run(self, *args, timeout=180) -> tuple[int, str]:
        r = subprocess.run(["wsl.exe", "-d", "Containerlab", "--", "bash", LAB, *args], capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr).replace("\r", "").strip()
        return r.returncode, out

    def refresh(self) -> dict:
        try:
            rc, out = self.run("status", timeout=60)
        except (OSError, subprocess.TimeoutExpired) as ex:
            rc, out = 1, f"{type(ex).__name__}: {ex}"
        st = {"reachable": rc == 0 and "fgt_License_Status" in out, "raw_error": None if rc == 0 else out[-300:]}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                st[k.strip()] = v.strip()
        st["licence_valid"] = st.get("fgt_License_Status") == "Valid"
        st["fgt_syslog_on"] = st.get("syslog_status") == "enable"
        st["ids_forwarder_on"] = st.get("container_fgt-ids-syslog") == "running"
        if st.get("syslog_format"):
            self.format = st["syslog_format"]
        with self.lock:
            self.status, self.checked_at = st, time.time()
        return st

    def act(self, what: str, *args) -> dict:
        """One device-side action, serialized (one at a time), recorded."""
        with self.lock:
            if self.busy:
                raise RuntimeError(f"another device action is running: {self.busy}")
            self.busy = what + (" " + " ".join(args) if args else "")
        t0 = time.time()
        try:
            rc, out = self.run(what, *args)
        finally:
            with self.lock:
                self.busy = None
        rec = {"at": time.strftime("%H:%M:%S"), "action": what, "args": list(args), "rc": rc, "output": out[-600:], "seconds": round(time.time() - t0, 1)}
        with self.lock:
            self.history.append(rec)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"{rec['at']} {what} {' '.join(args)} rc={rc} {rec['seconds']}s\n{out}\n")
        if what == "fgt-format" and args:
            self.format = args[0]
        threading.Thread(target=self.refresh, daemon=True).start()
        if rc != 0:
            raise RuntimeError(f"{what} failed: {out[-300:]}")
        return rec

    def ensure_connected(self, host: str, connected, wait_s: float = 45) -> dict:
        """Connect a device and make sure it is SENDING (seen by the System page), reconnecting once if it is not: for the
        FortiGate, re-committing the syslog setting restarts its backed-off reliable-syslog connection."""
        steps = []
        act = ("fgt-connect", self.format) if host == FGT else ("ids-connect",)
        for attempt in (1, 2):
            steps.append(self.act(*act))
            end = time.time() + wait_s
            while time.time() < end:
                if connected(host):
                    return {"connected": True, "attempts": attempt, "steps": steps}
                time.sleep(2)
        return {"connected": False, "attempts": 2, "steps": steps}

    def view(self) -> dict:
        with self.lock:
            return {"status": dict(self.status), "checked_s_ago": round(time.time() - self.checked_at) if self.checked_at else None,
                    "busy": self.busy, "history": self.history[-8:], "actions": len(self.history), "format": self.format}
