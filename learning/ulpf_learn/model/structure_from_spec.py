"""A Structure from an executed parser spec — the adapter that lets csv/kv/regex sources (the P1
sufficiency drafts) reach the provider before P6 induces those shapes. The spec is executed by the
reference executor on the sample lines; every semantic cell becomes a slot with the vendor's field name,
the cell's class, and its observed values. The provider sees exactly what induction would give it plus
the names the format itself carries."""
from __future__ import annotations

from collections import OrderedDict

from .. import dslexec
from ..induce import SlotObservation, Structure, classify, join_class


def structure_from_spec(spec_bytes: bytes, lines: list[bytes], max_samples: int = 8) -> tuple[Structure, list[bytes]]:
    prog = dslexec.compile_spec(spec_bytes)
    values: "OrderedDict[str, list[str]]" = OrderedDict()
    classes: dict[str, str] = {}
    kept: list[bytes] = []
    for line in lines:
        m = prog.parse(line)
        if m["status"] != "ok":
            continue
        kept.append(line)
        for sp in m["spans"]:
            if sp["kind"] != "semantic" or sp.get("declared_null"):
                continue
            path = sp["path"]
            values.setdefault(path, []).append(sp["value"])
            # the OBSERVED class, as induction would compute it — not the cell's declared class. The
            # declared class is the parser's widest acceptable shape (ASA hosts are `text` because names
            # can appear); the enumerator must judge what the samples actually are (IPs here), or the
            # correct label is refuted as type-incompatible (P4 spike, 9B on asa-302013).
            c = classify(sp["value"])
            classes[path] = join_class(classes[path], c) if path in classes else c
    if not kept:
        raise ValueError("no sample line parses under the spec")
    slots = []
    for i, (path, vals) in enumerate(values.items()):
        distinct = sorted(set(vals))
        slots.append(SlotObservation(i, classes[path], len(distinct), distinct[:max_samples],
                                     distinct[0] if len(distinct) == 1 and len(vals) > 1 else None, any("/" in v for v in vals), name=path))
    return Structure(len(slots), slots, len(kept)), kept
