"""Parser Transparency Log, the learning plane's side (2026-09-27): signing a pack LOGS it — every pack the plane emits
(onboarded, auto-healed, vendor-onboarded, hand-written) is in the log before anything can load it — and a pack signed
without logging is refused by the runtime."""
import json
import shutil
import subprocess
from pathlib import Path

from ulpf_learn.signing import sign_pack

ROOT = Path(__file__).resolve().parents[2]
RT = ROOT / "runtime" / "bin" / "ulpf-runtime"
TLOG = ROOT / "runtime" / "bin" / "ulpf-tlog"


def test_signing_logs_the_pack_and_an_unlogged_pack_is_refused(tmp_path):
    d = tmp_path / "pack"
    shutil.copytree(ROOT / "contracts" / "golden" / "squid-native", d, ignore=shutil.ignore_patterns("pack.json.tlog-proof", "pack.json.sig"))
    doc = json.loads((d / "pack.json").read_text(encoding="utf-8"))
    doc["pack_version"] = "9.9"   # fixed bytes: logged once, however often the suite runs
    (d / "pack.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    sign_pack(d, log=False)
    assert not (d / "pack.json.tlog-proof").exists()
    r = subprocess.run([str(RT), "verify-pack", "--pack", str(d)], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode != 0 and "not in the parser transparency log" in (r.stdout + r.stderr)
    sign_pack(d, produced_by="auto-healed")
    assert (d / "pack.json.tlog-proof").read_text().startswith("c2sp.org/tlog-proof@v1\n")
    r = subprocess.run([str(RT), "verify-pack", "--pack", str(d)], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    v = subprocess.run([str(TLOG), "verify", "--pack", str(d)], capture_output=True, text=True, cwd=ROOT)
    assert v.returncode == 0 and "9.9" in v.stdout and "auto-healed" in v.stdout
