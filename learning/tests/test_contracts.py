"""Contract conformance: every golden vector behaves as its index entry expects, in Python."""
import json
from pathlib import Path

import pytest

from ulpf_contracts import validate_file, validate_document

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "contracts" / "golden"
INDEX = json.loads((GOLDEN / "index.json").read_text())


@pytest.mark.parametrize("vector", INDEX["vectors"], ids=[v["path"] for v in INDEX["vectors"]])
def test_golden_vector(vector):
    errs = validate_file(vector["kind"], GOLDEN / vector["path"])
    if vector["expect"] == "valid":
        assert errs == [], errs
    else:
        assert errs, "expected the vector to be rejected"
        matches = vector["reason_match"]
        matches = [matches] if isinstance(matches, str) else matches
        assert any(m in e for m in matches for e in errs), errs


def test_version_bump_is_refused_for_every_kind():
    for kind in ("parser-spec", "span-map", "ambiguity-certificate", "parser-pack"):
        errs = validate_document(kind, {"schema_version": "2.0.0"})
        assert errs and "unsupported schema_version" in errs[0]


def test_numeric_confidence_is_rejected_anywhere_in_a_certificate():
    cert = json.loads((GOLDEN / "squid-native/certificate-snapshots/cert_squid_pos3_ambiguous.json").read_text())
    cert["ranked_candidates"][0]["confidence"] = 0.83
    errs = validate_document("ambiguity-certificate", cert)
    assert errs
