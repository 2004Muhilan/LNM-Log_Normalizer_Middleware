import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import re2
from ulpf_learn import dslexec
spec = json.loads((Path(__file__).resolve().parents[2] / "drafts/sufficiency/asa-302013.json").read_text())
step = spec["root"][0]
rx = re2.compile(("^(?:" + step["pattern"] + ")").encode())
print("groupindex:", dict(rx.groupindex), "captures:", list(step["captures"]))
for i, st in enumerate(spec["root"]):
    if st.get("op") == "regex":
        rx = re2.compile(("^(?:" + st["pattern"] + ")").encode())
        print(i, set(rx.groupindex) == set(st["captures"]), set(rx.groupindex) ^ set(st["captures"]))
