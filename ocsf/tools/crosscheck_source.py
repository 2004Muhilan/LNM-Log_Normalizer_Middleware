#!/usr/bin/env python3
"""Independent completeness check: recompile each pinned class from the OCSF schema SOURCE tree
(tag 1.3.0) and compare its top-level attribute set with the server export used by build_pinned.py.

The two derivations share no code with each other or with OCSF's own compiler, so agreement is
evidence that the pinned tables are the complete class attribute sets as OCSF defines them.
Resolution rules implemented from the source layout:
  - `extends` chain (class -> ... -> base_event), attributes merged child-over-parent
  - `$include` entries inside `attributes` (includes/*.json and profiles/*.json), merged recursively
  - class-level `profiles` list: each profile's attributes merged (extension profiles resolved under extensions/)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / "ocsf" / "cache"
SRC = CACHE / "ocsf-schema-1.3.0"
PINNED = ROOT / "ocsf" / "pinned"


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def index_events():
    by_name = {}
    for p in (SRC / "events").rglob("*.json"):
        d = load(p)
        if "name" in d:
            by_name[d["name"]] = d
    return by_name


def profile_file(ref: str) -> Path | None:
    # "profiles/host.json" or bare "host" or "linux/linux_users" (extension)
    cands = []
    if ref.endswith(".json"):
        cands.append(SRC / ref)
    else:
        cands.append(SRC / "profiles" / f"{ref}.json")
        if "/" in ref:
            ext, name = ref.split("/", 1)
            cands.append(SRC / "extensions" / ext / "profiles" / f"{name}.json")
    for c in cands:
        if c.exists():
            return c
    return None


def merge_attrs(dst: dict, src: dict, notes: list, origin: str):
    for k, v in src.items():
        if k == "$include":
            for inc in (v if isinstance(v, list) else [v]):
                f = profile_file(inc) if "profiles/" in inc or not inc.startswith("includes/") else SRC / inc
                if f is None or not f.exists():
                    notes.append(f"unresolved $include {inc} from {origin}")
                    continue
                merge_attrs(dst, load(f).get("attributes", {}), notes, str(f.relative_to(SRC)))
            continue
        dst[k] = v


def compile_class(name: str, events: dict, notes: list) -> tuple[dict, list]:
    d = events[name]
    attrs: dict = {}
    profiles: list = []
    if d.get("extends"):
        parent_attrs, parent_profiles = compile_class(d["extends"], events, notes)
        attrs.update(parent_attrs)
        profiles.extend(parent_profiles)
    merge_attrs(attrs, d.get("attributes", {}), notes, f"events:{name}")
    for pr in d.get("profiles", []) or []:
        if pr not in profiles:
            profiles.append(pr)
        f = profile_file(pr)
        if f is None:
            notes.append(f"profile {pr} declared by {name} not found in source tree")
            continue
        merge_attrs(attrs, load(f).get("attributes", {}), notes, f"profile:{pr}")
    return attrs, profiles


def apply_datetime_profile(attrs: dict, profiles: list, dictionary: dict, notes: list) -> dict:
    """The `datetime` profile is synthesized by the OCSF compiler rather than listed: for every
    attribute whose dictionary type is timestamp_t it adds a `<name>_dt` companion of type datetime_t.
    Verified against profiles/datetime.json, whose attributes carry the `_dt` naming rule."""
    if "datetime" not in profiles:
        return attrs
    prof = load(SRC / "profiles" / "datetime.json")
    declared = set(prof.get("attributes", {}))
    out = dict(attrs)
    for name in list(attrs):
        if dictionary.get(name, {}).get("type") == "timestamp_t":
            out[f"{name}_dt"] = {"synthesized_by": "datetime profile"}
    notes.append(f"datetime profile applied: declared={sorted(declared)} synthesized={sorted(k for k in out if k not in attrs)}")
    return out


def main() -> int:
    events = index_events()
    dictionary = load(SRC / "dictionary.json")["attributes"]
    index = load(PINNED / "index.json")
    ok = True
    for entry in index["classes"]:
        cname = entry["name"]
        table = load(ROOT / entry["file"])
        pinned_set = {a["name"] for a in table["attributes"]}
        notes: list = []
        src_attrs, profiles = compile_class(cname, events, notes)
        src_attrs = apply_datetime_profile(src_attrs, profiles, dictionary, notes)
        src_set = set(src_attrs)
        only_export = sorted(pinned_set - src_set)
        only_source = sorted(src_set - pinned_set)
        status = "AGREE" if not only_export and not only_source else "DIFF"
        ok = ok and status == "AGREE"
        print(f"{cname:20s} export={len(pinned_set):3d} source={len(src_set):3d} {status}")
        if only_export:
            print(f"   in export only : {only_export}")
        if only_source:
            print(f"   in source only : {only_source}")
        for n in notes:
            print(f"   note: {n}")
    print("RESULT:", "all pinned tables agree with the independent source compile" if ok else "DISAGREEMENT — investigate before freezing")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
