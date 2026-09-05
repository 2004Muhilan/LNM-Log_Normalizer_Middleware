"""P3->P4 boundary probe: for every slot of the golden Squid session, survivors ∩ each library class under
the bare intersection rule (PURE) and the proposal-anchored rule (ANCH). The numbers in docs/p3-report.md §6
come from this. Run: cd learning && python tools/probe_ambiguity_rules.py"""
import fnmatch, json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ulpf_learn.session import Session
from ulpf_learn.enumerate_ import enumerate_candidates, load_table
from ulpf_learn.library import Library

root = Path(__file__).resolve().parents[2]
tmp = Path(tempfile.mkdtemp())
s = Session(tmp / "s")
s.onboard(root / "contracts/golden/squid-native/samples/access.log", "squid-proxy-01", "op-014")
lib = Library()
table = load_table(4002)
types = {l["path"]: l.get("type") for l in table["leaf_paths"]}
print("current certificates:", {cid: c["status"] for cid, c in s.state["certificates"].items()})
print("current unevidenced:", [u["field"] for u in s.state["unevidenced"]])
print()
for slot, part in s.plan.parts():
    en = enumerate_candidates(4002, part.cls, slot.samples)
    surv = en.survivors
    print(f"--- {part.field} class={part.cls} samples={slot.samples[:2]} proposal={part.candidates} survivors={len(surv)}")
    for name, cls in lib.classes.items():
        pats = cls["candidates"]
        inter = [a for a in surv if any(fnmatch.fnmatchcase(a, p) for p in pats)]
        if len(inter) >= 2:
            print(f"    PURE  {name:24s} |∩|={len(inter):3d} {inter if len(inter) <= 8 else inter[:8] + ['...']}")
    # anchored rule: classes containing the rank-1 proposal; pair_of holds the leaf fixed
    for x in part.candidates[:1]:
        for name, cls in lib.classes.items():
            pats = cls["candidates"]
            if not any(fnmatch.fnmatchcase(x, p) for p in pats):
                continue
            if "pair_of" in cls:
                pre = next(p for p in cls["pair_of"] if x.startswith(p + "."))
                leaf = x[len(pre) + 1:]
                rivals = [a for a in surv if a in {f"{p}.{leaf}" for p in cls["pair_of"]}]
            else:
                rivals = [a for a in surv if a in cls["candidates"]]
            print(f"    ANCH  {name:24s} |rivals|={len(rivals)} {rivals}")
print()
print("timestamp_t leaves in 4002:", [p for p, t in types.items() if t == "timestamp_t"])
print("float survivors pos_1:", enumerate_candidates(4002, "float", ["1157689312.049"]).survivors)
print("integer epoch seconds survivors (timestamp_t?):", [a for a in enumerate_candidates(4002, "integer", ["1157689312"]).survivors if types[a] == "timestamp_t"])
print("integer epoch millis survivors (timestamp_t?):", [a for a in enumerate_candidates(4002, "integer", ["1157689312049"]).survivors if types[a] == "timestamp_t"])
