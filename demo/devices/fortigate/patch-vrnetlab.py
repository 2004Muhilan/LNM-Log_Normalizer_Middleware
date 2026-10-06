#!/usr/bin/env python3
"""Two surgical, idempotent edits to vrnetlab.py inside the FortiGate container (no `containerlab deploy`, which would
make a new firewall with a new serial number):

  1. the VM UUID is pinned to the one the evaluation licence was activated with (vrnetlab otherwise draws a random UUID
     on every container start; the UUID environment variable, if ever set, still wins);
  2. the VM gets ONE data NIC, port2, for the traffic container: vrnetlab waits for container interface eth1 (made by
     link.sh) — at most 120 s, so a plain `docker start` without the link still boots, without port2.

    python3 patch-vrnetlab.py IN OUT      (start.sh copies vrnetlab.py out of the container, patches, copies it back)
    python3 patch-vrnetlab.py launch.py OUT   (a file named launch*: the launcher's prompt fix below)
"""
import os
import sys

# the UUID of the boot in which the licence was activated: FGT_UUID (start.sh reads it from ~/.fgt-uuid, SETUP.md step 21),
# else this lab's own (its licence was activated with it)
UUID = os.environ.get("FGT_UUID", "").strip() or "e9fbd16d-8991-4beb-8ec9-66767115dd38"
EDITS = [
    ('self._uuid = os.getenv("UUID") or str(uuid.uuid4())',
     f'self._uuid = os.getenv("UUID") or "{UUID}"  # ULPF: pinned, the licence\'s UUID'),
    ('self.num_provisioned_nics = int(os.environ.get("CLAB_INTFS", 0))',
     'self.num_provisioned_nics = max(int(os.environ.get("CLAB_INTFS", 0)), 1)  # ULPF: port2 for the traffic container'),
    ('''                self.logger.debug("interfaces provisioned, continuing...")
                break
            time.sleep(5)''',
     '''                self.logger.debug("interfaces provisioned, continuing...")
                break
            _ulpf_waited = getattr(self, "_ulpf_waited", 0)  # ULPF: never wait forever for eth1
            if _ulpf_waited >= 120:
                self.logger.warning("ULPF: no eth1 after 120 s - booting without port2 (run link.sh, then restart)")
                self.num_provisioned_nics = 0
                break
            self._ulpf_waited = _ulpf_waited + 5
            time.sleep(5)'''),
]


# launch.py (the FortiGate's vrnetlab launcher). Its bootstrap waits for "login:" or the DEFAULT prompt
# "FortiGate-VM64-KVM #"; once it has set the hostname (fgt) the prompt is "fgt #", which it never recognises: it types
# the username into an open console session, waits for a "Password:" that never comes, and after ~68 min its read times
# out, the launcher crashes and takes the VM down with it (seen 2026-09-29 13:47 UTC). Recognise the configured prompt too.
# The login pattern is anchored at the end of what the console has shown: a stale "fgt login:" earlier in the buffer must
# not win over a live "fgt #" prompt (the patterns are tried in order; seen on the first attempt at this fix).
_LAUNCH_NEW = ('(ridx, match, res) = self.tn.expect([b"login: *$", ("(?:FortiGate-VM64-KVM|" + re.escape(self.hostname) + ") #").encode()], 1)'
               '  # ULPF: the configured prompt too; login only when it is the last thing shown')
LAUNCH_EDITS = [
    ('(ridx, match, res) = self.tn.expect([b"login:", b"FortiGate-VM64-KVM #"], 1)', _LAUNCH_NEW),                     # vrnetlab as shipped
    ('(ridx, match, res) = self.tn.expect([b"login:", ("(?:FortiGate-VM64-KVM|" + re.escape(self.hostname) + ") #").encode()], 1)  # ULPF: the configured prompt too',
     _LAUNCH_NEW),                                                                                                        # this lab's first attempt
]


# ...and the scripted console login itself hangs: it waits for "Password" after it has already read "Pas" of it (a prompt
# split across two reads), forever, until the read times out ~68 min later and the launcher crashes with the VM. The login
# only exists to set the hostname, which this VM keeps in its own configuration. So a login prompt means the VM is up:
# nothing is typed on the serial console (the lab automates over SSH with a key).
_LOGIN_OLD = '''                self.wait_write(self.username, wait=None)
                self.wait_write("", wait=self.username)
                self.wait_write(self.password, wait="Password")
                self.wait_write(self.password, wait=None)
'''
_LOGIN_NEW = '''                # ULPF: no scripted console login (it hangs on a split "Password" prompt and crashes the launcher, and the VM
                # with it, ~68 min later); this VM keeps its own configuration, so a login prompt means it is up
                self.running = True
                self.tn.close()
                self.logger.info(f"Startup complete in {datetime.datetime.now() - self.start_time} (ULPF: console login skipped)")
                return
'''


def main():
    src = open(sys.argv[1]).read()
    out = src
    if os.path.basename(sys.argv[1]).startswith("launch"):   # alternatives: whichever version of the line is there
        if _LAUNCH_NEW not in out:
            olds = [old for old, _ in LAUNCH_EDITS if out.count(old) == 1]
            if not olds:
                sys.exit("patch-vrnetlab: launch.py: the bootstrap expect line is not the one this patch knows")
            out = out.replace(olds[0], _LAUNCH_NEW)
        if _LOGIN_NEW not in out:
            if out.count(_LOGIN_OLD) != 1:
                sys.exit("patch-vrnetlab: launch.py: the console login block is not the one this patch knows")
            out = out.replace(_LOGIN_OLD, _LOGIN_NEW)
    else:
        for old, new in EDITS:
            if new in out:
                continue   # already applied
            if out.count(old) != 1:
                sys.exit(f"patch-vrnetlab: expected exactly one match for: {old[:70]!r}")
            out = out.replace(old, new)
    compile(out, "vrnetlab.py", "exec")
    open(sys.argv[2], "w").write(out)
    print("patched" if out != src else "already patched")


if __name__ == "__main__":
    main()
