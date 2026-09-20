#!/usr/bin/env python3
"""The operator's answers for the live sequence, applied through the SAME CLI as everywhere else
(`ulpf_learn respond --discriminator operator_assertion`). Demo glue, not pipeline: it only decides WHEN to call it.

    assertions.py SESSION_DIR LIVE_DIR [--interactive] "field=attribute|why" ...

Scripted: the listed answers (the truth about flowgen — the operator's own notes on their sensor) are queued one by
one, exactly as the UI queues a dropdown choice, and applied. Interactive: nothing is queued; the operator chooses in
the System page (demo/ui/live.html). When they press "promote", whatever they did not answer themselves is filled from the notes — an
unanswered column would keep the model's label, and two columns carrying the same label make a pack the contract refuses.
Ends when no mandatory attribute is blocked and every expected answer was applied.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    args = sys.argv[1:]
    interactive = "--interactive" in args
    args = [a for a in args if a != "--interactive"]
    session, live, notes = Path(args[0]), Path(args[1]), []
    for a in args[2:]:
        f, rest = a.split("=", 1)
        attr, why = rest.split("|", 1)
        notes.append({"field": f, "attribute": attr, "note": why})
    queue = live / "assertions.jsonl"
    queue.write_text("")
    pause = float(os.environ.get("ULPF_LIVE_ASSERT_PAUSE", "1"))

    def publish(done=False):
        s = json.loads((session / "session.json").read_text())
        open_certs = [{"id": cid, "field": c["field"]["path"], "class": c["evidence"]["discriminator"].get("ambiguity_class"), "status": c["status"],
                       "candidates": [r["attribute"] for r in c["ranked_candidates"]]} for cid, c in s["certificates"].items() if c["status"] != "resolved"]
        fields = [{"field": p["field"], "cls": p["cls"], "samples": sl["samples"][:3], "mapped": [m["attribute"] for m in p["mappings"]],
                   "provenance": [m["provenance"].get("category") for m in p["mappings"]]} for sl in s["plan"]["slots"] for p in sl["parts"]]
        tmp = live / "pending.json.tmp"
        tmp.write_text(json.dumps({"session": str(session.relative_to(live)), "interactive": interactive, "done": done, "blockers": s["verdict"]["blockers"], "open_certificates": open_certs,
                                   "fields": fields, "mandatory": ["time", "src_endpoint.ip", "dst_endpoint.ip", "action_id"], "notes": notes if interactive else []}))
        os.replace(tmp, live / "pending.json")
        return s

    publish()
    if interactive:
        print(">>> waiting for the operator: choose on the System page (live.html), then press promote", flush=True)
    applied, asserted, to_queue, promote_seen, next_at = 0, set(), list(notes) if not interactive else [], False, time.time() + pause
    deadline = time.time() + 900
    while time.time() < deadline:
        if to_queue and time.time() >= next_at:
            with open(queue, "a") as f:
                f.write(json.dumps({**to_queue.pop(0), "by": "notes"}) + "\n")
            next_at = time.time() + pause
        lines = [l for l in queue.read_text().splitlines() if l.strip()]
        while applied < len(lines):
            d = json.loads(lines[applied]); applied += 1
            if d.get("promote"):
                promote_seen = True
                to_queue = [n for n in notes if n["field"] not in asserted]
                continue
            f, attr = d["field"], d["attribute"]
            note = d.get("note") or "chosen by the operator on the review screen"
            print(f"operator op-014 ASSERTS  {f}  ->  {attr}    ({note})", flush=True)
            r = subprocess.run([sys.executable, "-m", "ulpf_learn", "respond", "--session", str(session), "--discriminator", "operator_assertion", "--field", f, "--attribute", attr,
                                "--input", f"operator op-014 asserts {f} is {attr}: {note}"], cwd=ROOT / "learning", capture_output=True, text=True)
            if r.returncode != 0:
                print((r.stdout + r.stderr)[-600:]); return 1
            asserted.add(f)
            publish()
        s = publish()
        if not s["verdict"]["blockers"] and not to_queue and applied == len(lines) and (promote_seen or not interactive):
            publish(done=True)
            return 0
        time.sleep(0.2)
    print("timed out waiting for the operator's answers"); return 1


if __name__ == "__main__":
    sys.exit(main())
