"""Prompt assembly — from the induced structure and the onboarding samples only. Nothing else reaches
the model: no live traffic, no other source's data, no library knowledge (the library judges the
model's output; it does not steer it). The templates are hashed into the proposal's provenance."""
from __future__ import annotations

import hashlib

from ..induce import Structure

SYSTEM_CLASS = """You classify log formats into OCSF 1.3 event classes. You are shown sample lines from one log source and a description of its fields. Answer with JSON only, following the schema you are given exactly. Choose the single event class that best describes what each line records."""

SYSTEM_LABEL = """You label the fields of a log format with OCSF 1.3 attribute paths for the event class {class_name} ({class_uid}).

You are shown sample lines and, for each field slot, its position, the structural class of its values (integer, float, ipv4, url, word, text, ...), the number of distinct values seen, sample values, and — when the format carries one — the vendor's field name.

Rules:
- Answer with JSON only, following the schema exactly; the "label" for a slot is one attribute path of this event class, or "unmapped" when the field is vendor-specific and has no OCSF attribute, or "compound" when the token is several values joined by a separator such as "/" and must be split before labelling.
- Label from what the values and names show. Do not invent fields that are not present.
- If a slot could legitimately be two or three different attributes (for example which of two addresses is the source), put your best choice in "label" and the others in "alternatives", ranked. Do not pad alternatives when you are not in doubt.
- One value, one attribute: pick the most specific path that fits the value's type."""

SYSTEM_SLOT = """You label one field of a log format with an OCSF 1.3 attribute path for the event class {class_name} ({class_uid}). The allowed labels are exactly the attributes whose type accepts this field's values, plus "unmapped" for a vendor-specific field with no OCSF attribute. Answer with JSON only, following the schema exactly. If two or three of the allowed labels are plausible, put your best choice in "label" and the others in "alternatives"."""

EXAMPLE = """Example (a different, made-up source, event class authentication):
lines:
  2024-01-05T10:00:01Z sshd 10.0.0.5 alice accepted publickey
  2024-01-05T10:00:07Z sshd 10.0.0.9 bob failed password
slots:
  slot 1: class=word distinct=2 samples: 2024-01-05T10:00:01Z, 2024-01-05T10:00:07Z
  slot 2: class=word distinct=1 samples: sshd
  slot 3: class=ipv4 distinct=2 samples: 10.0.0.5, 10.0.0.9
  slot 4: class=word distinct=2 samples: alice, bob
  slot 5: class=word distinct=2 samples: accepted, failed
  slot 6: class=word distinct=2 samples: publickey, password
answer:
{"slots":[{"slot":1,"label":"time"},{"slot":2,"label":"unmapped"},{"slot":3,"label":"src_endpoint.ip"},{"slot":4,"label":"user.name"},{"slot":5,"label":"status"},{"slot":6,"label":"auth_protocol"}]}"""


def describe_structure(structure: Structure, lines: list[bytes], max_lines: int | None = None) -> str:
    # wide structures (PAN-OS 53 cells, FortiGate 72 keys with ~600-byte lines) get fewer lines and
    # samples so the prompt stays well inside a 16k context; the slot table carries the information
    wide = structure.arity > 24
    if max_lines is None:
        max_lines = 3 if wide else 6
    n_samples = 3 if wide else 6
    shown = [l.decode("utf-8", "replace") for l in lines[:max_lines]]
    parts = ["lines:"] + [f"  {l}" for l in shown] + ["slots:"]
    for s in structure.slots:
        name = f" name={s.name}" if s.name else ""
        const = " (constant)" if s.constant is not None else ""
        parts.append(f"  slot {s.index + 1}:{name} class={s.token_class} distinct={s.distinct}{const} samples: {', '.join(v[:60] for v in s.samples[:n_samples])}")
    return "\n".join(parts)


def user_class(structure: Structure, lines: list[bytes]) -> str:
    return describe_structure(structure, lines) + "\n\nWhich OCSF event class do these lines record?"


def user_label(structure: Structure, lines: list[bytes], feedback: str = "") -> str:
    body = EXAMPLE + "\n\nNow this source:\n" + describe_structure(structure, lines) + f"\n\nLabel all {structure.arity} slots."
    if feedback:
        body += "\n\nYour previous answer was rejected by the validator:\n" + feedback + "\nAnswer again for all slots, correcting these."
    return body


def user_slot(structure: Structure, lines: list[bytes], index: int) -> str:
    s = structure.slots[index]
    name = f" (vendor name: {s.name})" if s.name else ""
    return describe_structure(structure, lines) + f"\n\nLabel slot {index + 1}{name}: class={s.token_class}, samples: {', '.join(s.samples[:6])}."


def template_hash() -> str:
    return "sha256:" + hashlib.sha256((SYSTEM_CLASS + SYSTEM_LABEL + SYSTEM_SLOT + EXAMPLE).encode()).hexdigest()
