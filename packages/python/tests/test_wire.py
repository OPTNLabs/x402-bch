import json
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from x402_bch.core import request_hash, validate_payment_payload, validate_requirements


def test_wire_core():
    fixture = json.loads((Path(__file__).parents[3] / "spec/conformance/v1/payment-requirements.json").read_text())
    for case in fixture["cases"]:
        validate_requirements(case["requirements"])
    assert request_hash('{"url":"https://example.test/resource"}') == "1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675"
    requirements = fixture["cases"][0]["requirements"]
    payload = {"x402Version": 2, "scheme": "exact", "network": requirements["network"],
               "payload": {"transaction": "AQID"}, "accepted": requirements}
    validate_payment_payload(payload, requirements)
    payload["payload"]["transaction"] = "bad"
    try:
        validate_payment_payload(payload, requirements)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid transaction accepted")
