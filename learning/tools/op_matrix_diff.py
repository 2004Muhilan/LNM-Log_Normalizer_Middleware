"""Compact executor diff for the op-coverage matrix: for every vector input where the reference
executor and the Go engine disagree, print only the differing parts. Run: cd learning && python tools/op_matrix_diff.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "learning"))
sys.path.insert(0, str(ROOT / "learning" / "tests"))
import op_matrix  # noqa: E402
from ulpf_learn import dslexec  # noqa: E402

RUNTIME = ROOT / "runtime" / "bin" / "ulpf-runtime"


def strip(m):
    m = json.loads(json.dumps(m))
    if m.get("failure"):
        m["failure"].pop("reason", None)
    return m


def main():
    tmp = Path(tempfile.mkdtemp())
    env = dict(os.environ, ULPF_ROOT=str(ROOT))
    n_diff = 0
    for v in op_matrix.V:
        sp = tmp / f"{v['name']}.json"
        sp.write_bytes(json.dumps(v["spec"]).encode())
        inp = tmp / f"{v['name']}.log"
        inp.write_bytes(b"\n".join(v["inputs"]) + b"\n")
        prog = dslexec.compile_spec(sp.read_bytes())
        go = subprocess.run([str(RUNTIME), "parse", "--spec", str(sp), "--input", str(inp)], capture_output=True, text=True, env=env)
        if go.returncode != 0:
            print(f"## {v['name']}: ENGINE ERROR {go.stderr[:300]}")
            n_diff += 1
            continue
        gms = [json.loads(l) for l in go.stdout.splitlines() if l.strip()]
        for raw, gm in zip(v["inputs"], gms):
            pm = prog.parse(raw)
            a, b = strip(pm), strip(gm)
            if a == b:
                continue
            n_diff += 1
            print(f"## {v['name']}  input={raw!r}")
            if a["status"] != b["status"]:
                print(f"   status py={a['status']} go={b['status']}  py_fail={pm.get('failure')}  go_fail={gm.get('failure')}")
            if a.get("failure") != b.get("failure"):
                print(f"   failure py={pm.get('failure')} go={gm.get('failure')}")
            if a.get("buffers") != b.get("buffers"):
                print(f"   buffers py={a.get('buffers')} go={b.get('buffers')}")
            ps, gs = a.get("spans", []), b.get("spans", [])
            for i in range(max(len(ps), len(gs))):
                x = ps[i] if i < len(ps) else None
                y = gs[i] if i < len(gs) else None
                if x != y:
                    print(f"   span[{i}] py={json.dumps(x, sort_keys=True)}\n           go={json.dumps(y, sort_keys=True)}")
    print(f"\n{n_diff} differing inputs")


if __name__ == "__main__":
    main()
