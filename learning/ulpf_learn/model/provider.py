"""ModelProvider — the model behind the P3 `Provider` seam, with the builder/verifier loop.

propose(structure):
  1. event class: one grammar-constrained answer over the pinned classes;
  2. labels, in one of two modes:
       whole    — one answer labelling every slot with an attribute of the class (grammar: the class's
                  attributes + unmapped + compound); the validator then checks each rank-1 label for
                  type compatibility against the enumerator's survivors; refuted slots are fed back and
                  the model answers again, up to `max_iterations`; slots still refuted are abandoned to
                  review (no proposal for that slot);
       per-slot — one answer per slot with the grammar restricted to that slot's survivors (+ unmapped);
                  type compatibility holds by construction, so the loop has nothing to refute.
  3. a Proposal exactly like the fixture's — ranked candidates per slot, proposed_by "model",
     model_hash = the verified digest of the weights — plus a provenance record (model, weights digest,
     llama.cpp build, decoding configuration, grammar and prompt-template hashes, backend, iterations,
     timings) that the session stores.

No output crosses into a Proposal without validating against the emission schema (invariant 1 for the
part that is by check) and being judged by the enumerator. The model never sees a live log."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema

from ..enumerate_ import enumerate_candidates
from ..induce import Structure
from ..provider import Proposal, Provider, SlotProposal
from . import emission, prompt
from .client import DECODING, LlamaClient

ROOT = Path(__file__).resolve().parents[3]
UID_BY_NAME = {v: k for k, v in emission.PINNED_CLASSES.items()}


@dataclass
class Trace:
    """Everything the spike measures, per proposal."""
    model_id: str
    mode: str
    iterations: int = 0
    calls: int = 0
    prompt_tokens: int = 0
    predicted_tokens: int = 0
    wall_ms: float = 0.0
    refuted_by_iteration: list[list[int]] = field(default_factory=list)   # slot indices refuted per iteration
    abandoned: list[int] = field(default_factory=list)
    schema_invalid: int = 0
    think_leak: int = 0
    raw_outputs: list[str] = field(default_factory=list)
    class_answer: str = ""


class ModelProvider(Provider):
    name = "model"

    def __init__(self, client: LlamaClient, model_id: str, model_hash: str, mode: str = "whole",
                 max_iterations: int = 3, backend: str = "unknown", event_class_uid: int | None = None):
        if mode not in ("whole", "per-slot"):
            raise ValueError(mode)
        self.client, self.model_id, self.model_hash, self.mode = client, model_id, model_hash, mode
        self.max_iterations, self.backend, self.forced_class = max_iterations, backend, event_class_uid
        self.lines: list[bytes] = []
        self.last_trace: Trace | None = None
        self.props = {}
        try:
            self.props = client.props()
        except Exception:  # noqa: BLE001 - provenance is best effort; the digest is not
            pass

    # the session passes the samples so the prompt can show lines, not only slot summaries
    def set_samples(self, lines: list[bytes]) -> None:
        self.lines = list(lines)

    def provenance(self) -> dict:
        t = self.last_trace
        return {
            "provider": "model", "model_id": self.model_id, "model_hash": self.model_hash,
            "llama_cpp": {"build_info": self.props.get("build_info"), "model_path": self.props.get("model_path"), "n_ctx": self.props.get("n_ctx")},
            "decoding": dict(DECODING),
            "backend": self.backend, "mode": self.mode, "max_iterations": self.max_iterations,
            "prompt_template_hash": prompt.template_hash(),
            "grammar_hashes": getattr(self, "_grammar_hashes", {}),
            "trace": {k: v for k, v in (t.__dict__.items() if t else []) if k != "raw_outputs"},
        }

    # ------------------------------------------------------------------ steps
    def _ask(self, system: str, user: str, schema: dict, tr: Trace, max_tokens: int) -> dict | None:
        c = self.client.chat(system, user, schema, max_tokens=max_tokens)
        tr.calls += 1
        tr.prompt_tokens += c.prompt_tokens
        tr.predicted_tokens += c.predicted_tokens
        tr.wall_ms += c.wall_ms
        tr.raw_outputs.append(c.text)
        if "<think>" in c.text or "<|think|>" in c.text:
            tr.think_leak += 1
        try:
            doc = json.loads(c.text)
            jsonschema.validate(doc, schema)
            return doc
        except (json.JSONDecodeError, jsonschema.ValidationError):
            tr.schema_invalid += 1
            return None

    def _choose_class(self, structure: Structure, tr: Trace) -> int:
        if self.forced_class:
            tr.class_answer = f"forced:{self.forced_class}"
            return self.forced_class
        schema = emission.class_schema()
        self._grammar_hashes = {"class": emission.schema_hash(schema)}
        doc = self._ask(prompt.SYSTEM_CLASS, prompt.user_class(structure, self.lines), schema, tr, 64)
        name = doc["event_class"] if doc else "network_activity"
        tr.class_answer = name
        return UID_BY_NAME[name]

    def propose(self, structure: Structure) -> Proposal:
        tr = Trace(self.model_id, self.mode)
        t0 = time.perf_counter()
        uid = self._choose_class(structure, tr)
        cname = emission.PINNED_CLASSES[uid]
        surv = {s.index: enumerate_candidates(uid, s.token_class, s.samples).survivors for s in structure.slots}
        labels: dict[int, list[str]] = {}
        flags: dict[int, str] = {}
        if self.mode == "whole":
            schema = emission.proposal_schema(uid, structure.arity)
            self._grammar_hashes["labels"] = emission.schema_hash(schema)
            system = prompt.SYSTEM_LABEL.format(class_name=cname, class_uid=uid)
            feedback, pending = "", set(range(structure.arity))
            for it in range(self.max_iterations):
                tr.iterations = it + 1
                # budget: models pretty-print and add alternatives (the 9B needed ~1.1k tokens for 10 slots);
                # a truncated answer is a wasted iteration (one seen in the desktop spike), never a wrong label
                doc = self._ask(system, prompt.user_label(structure, self.lines, feedback), schema, tr, 256 + 120 * structure.arity)
                if doc is None:
                    feedback = "The answer was not valid JSON for the schema."
                    tr.refuted_by_iteration.append(sorted(pending))
                    continue
                refuted = []
                notes = []
                for row in doc["slots"]:
                    i = row["slot"] - 1
                    if i not in pending:
                        continue
                    lab = row["label"]
                    if lab in (emission.UNMAPPED, emission.COMPOUND):
                        flags[i] = lab
                        labels[i] = []
                        pending.discard(i)
                        continue
                    ranked = [lab] + [a for a in row.get("alternatives", []) if a != lab]
                    if lab in surv[i]:
                        labels[i] = ranked
                        pending.discard(i)
                    else:
                        refuted.append(i)
                        hint = ", ".join(surv[i][:12]) or "(none: no attribute of this class accepts this value)"
                        notes.append(f"  slot {i + 1}: {lab} does not accept a {structure.slots[i].token_class} value; type-compatible attributes include {hint}")
                tr.refuted_by_iteration.append(refuted)
                if not refuted:
                    break
                feedback = "\n".join(notes)
            tr.abandoned = sorted(pending)
        else:
            self._grammar_hashes["slots"] = {}
            system = prompt.SYSTEM_SLOT.format(class_name=cname, class_uid=uid)
            for s in structure.slots:
                schema = emission.slot_schema(surv[s.index])
                self._grammar_hashes["slots"][str(s.index + 1)] = emission.schema_hash(schema)
                doc = self._ask(system, prompt.user_slot(structure, self.lines, s.index), schema, tr, 96)
                tr.iterations = 1
                if doc is None:
                    tr.abandoned.append(s.index)
                    continue
                if doc["label"] == emission.UNMAPPED:
                    flags[s.index], labels[s.index] = emission.UNMAPPED, []
                else:
                    labels[s.index] = [doc["label"]] + [a for a in doc.get("alternatives", []) if a != doc["label"]]
        slots = []
        for s in structure.slots:
            cands = labels.get(s.index, [])
            flag = flags.get(s.index)
            slots.append(SlotProposal(s.index, cands, "" if not flag else flag,
                                      (s.name or f"slot_{s.index + 1}") if flag == emission.UNMAPPED else None,
                                      "/" if flag == emission.COMPOUND and s.has_slash else None))
        tr.wall_ms = (time.perf_counter() - t0) * 1000
        self.last_trace = tr
        return Proposal(uid, cname, slots, "model", self.model_hash, {"provenance": self.provenance()})


def verified_model_hash(model_id: str, manifest: Path | None = None, cache: Path | None = None) -> str:
    """The digest the pack records — computed from the file, compared to the manifest, never copied
    from it. Refuses on mismatch."""
    import sys
    sys.path.insert(0, str(ROOT / "learning" / "tools"))
    import models as m  # noqa: E402
    man = m.load(manifest or ROOT / "models" / "manifest.json")
    e = m.entry(man, model_id)
    return "sha256:" + m.verify((cache or ROOT / "models" / "cache") / e["file"], e)
