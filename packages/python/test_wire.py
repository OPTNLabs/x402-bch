import json
from pathlib import Path

from x402_bch import request_hash, validate_requirements


def test_wire_core():
    fixture = json.loads((Path(__file__).parents[2] / "spec/conformance/v1/payment-requirements.json").read_text())
    for case in fixture["cases"]:
        validate_requirements(case["requirements"])
    assert len(request_hash({"url": "https://example.test/resource"})) == 64
