import json
from pathlib import Path

from x402_bch.covenant import profile_hashes_match, validate_covenant_transition


FIXTURE = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/covenant-profiles.json").read_text())


def test_registered_covenant_profile_fixture():
    assert profile_hashes_match(FIXTURE["profile"])
    for case in FIXTURE["cases"]:
        result = validate_covenant_transition(FIXTURE["profile"], case)
        if case["expected"] == "accept":
            assert result == {"accepted": True}, case["id"]
        else:
            assert result == {"accepted": False, "errorCode": case["errorCode"]}, case["id"]
