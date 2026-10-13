"""Registered covenant-profile identity and successor validation."""

import hashlib
import json
from typing import Any


def validate_covenant_transition(profile: dict[str, Any], transition: dict[str, Any]) -> dict[str, Any]:
    if not profile_hashes_match(profile):
        return {"accepted": False, "errorCode": "profile-identity-mismatch"}
    policy = profile["successorPolicy"]
    if (
        transition["source"]["lockingBytecode"] != policy["lockingBytecode"]
        or transition["successor"]["lockingBytecode"] != policy["lockingBytecode"]
    ):
        return {"accepted": False, "errorCode": "locking-bytecode-mismatch"}
    if transition["successorOutputIndex"] != policy["outputIndex"]:
        return {"accepted": False, "errorCode": "successor-output-index-mismatch"}
    if (
        transition["requestHash"] != transition["source"]["requestHash"]
        or transition["requestHash"] != transition["successor"]["requestHash"]
    ):
        return {"accepted": False, "errorCode": "request-hash-mismatch"}
    if policy["stateTransition"] == "epoch-plus-one" and int(transition["successor"]["epoch"]) != int(transition["source"]["epoch"]) + 1:
        return {"accepted": False, "errorCode": "state-transition-invalid"}
    fee = int(transition["fee"])
    if fee > int(policy["maxFee"]):
        return {"accepted": False, "errorCode": "fee-exceeds-limit"}
    if policy["value"] == "preserve-minus-fee" and int(transition["source"]["value"]) - int(transition["successor"]["value"]) != fee:
        return {"accepted": False, "errorCode": "state-transition-invalid"}
    if policy["token"] == "preserve" and transition["source"]["token"] != transition["successor"]["token"]:
        return {"accepted": False, "errorCode": "token-state-mismatch"}
    return {"accepted": True}


def profile_hashes_match(profile: dict[str, Any]) -> bool:
    descriptor = {
        "id": profile["id"],
        "family": profile["family"],
        "profileVersion": profile["profileVersion"],
        "network": profile["network"],
        "constructorParameters": profile["constructorParameters"],
        "successorPolicy": profile["successorPolicy"],
    }
    return (
        _sha256(_canonical_json(descriptor).encode()) == profile["descriptorHash"]
        and _sha256(bytes.fromhex(profile["successorPolicy"]["lockingBytecode"])) == profile["lockingBytecodeHash"]
        and _sha256(_canonical_json(profile["successorPolicy"]).encode()) == profile["successorPolicyHash"]
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
