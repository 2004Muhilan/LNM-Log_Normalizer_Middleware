"""Discriminator library: load, class lookup (direct, subset match), deterministic ranking."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LIBRARY = ROOT / "library" / "discriminators-v1.yaml"


@dataclass
class Choice:
    discriminator_id: str
    cost_tier: str
    rank: int
    resolves: list[str]


class Library:
    def __init__(self, path: Path = LIBRARY):
        self.doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        self.version = self.doc["library_version"]
        self.tiers = {t["id"]: t["order"] for t in self.doc["cost_tiers"]}
        self.discriminators = self.doc["discriminators"]
        self.classes = self.doc["ambiguity_classes"]

    def match_class(self, ranked: list[str]) -> str | None:
        """Direct lookup: the first class whose candidate patterns cover every ranked attribute."""
        for name, cls in self.classes.items():
            pats = cls["candidates"]
            if len(ranked) >= 2 and all(any(fnmatch.fnmatchcase(a, p) for p in pats) for a in ranked):
                return name
        return None

    def rank(self, class_name: str, resolves_by_discriminator: dict[str, list[str]]) -> list[Choice]:
        """cost tier ascending, then fields resolved descending, then id — deterministic."""
        ids = self.classes[class_name]["discriminators"]
        rows = []
        for d in ids:
            spec = self.discriminators[d]
            resolves = resolves_by_discriminator.get(d, [])
            rows.append((self.tiers[spec["cost_tier"]], -len(resolves), d, spec["cost_tier"], resolves))
        rows.sort()
        return [Choice(d, tier, i + 1, res) for i, (_, _, d, tier, res) in enumerate(rows)]

    def request_text(self, discriminator_id: str, **kw) -> str:
        t = self.discriminators[discriminator_id]["request_template"].strip()
        try:
            return t.format(**kw)
        except KeyError:
            return t
