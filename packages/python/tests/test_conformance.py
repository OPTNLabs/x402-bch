import json
from pathlib import Path
import re


def test_payment_requirements_fixture():
    fixture = json.loads(
        (Path(__file__).parents[1] / "spec/conformance/v1/payment-requirements.json").read_text()
    )
    assert fixture["version"] == 1
    assert fixture["cases"]
    for case in fixture["cases"]:
        requirements = case["requirements"]
        assert requirements["x402Version"] == 2
        assert requirements["scheme"] == "exact"
        assert re.fullmatch(r"\d+", requirements["amount"])
        request_hash = requirements.get("extra", {}).get("requestHash")
        if request_hash is not None:
            assert re.fullmatch(r"[0-9a-f]{64}", request_hash)
