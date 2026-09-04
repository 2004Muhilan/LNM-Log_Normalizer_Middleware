"""ULPF contract validation (learning-plane side).

Validates the four frozen contracts — parser spec, span map, ambiguity certificate, parser pack —
against their JSON Schemas and the semantic invariants the schemas cannot express (span tiling,
RE2 compilability, candidate-set subset rules, pack hash composition, subset-guard table hashes).
"""
from .validate import KINDS, validate_document, validate_file, ValidationError

__all__ = ["KINDS", "validate_document", "validate_file", "ValidationError"]
