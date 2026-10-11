"""Lossless x402-BCH wire-level primitives."""

import hashlib
import re
import base64
from typing import Any


def validate_requirements(requirements: dict[str, Any]) -> None:
    if requirements.get("x402Version") not in (None, 2) or requirements.get("scheme") != "exact":
        raise ValueError("unsupported x402 requirements")
    if requirements.get("network") not in ("bch:bitcoincash", "bch:bchtest"):
        raise ValueError("unsupported BCH network")
    if not requirements.get("asset") or not requirements.get("payTo"):
        raise ValueError("asset and payTo are required")
    if not re.fullmatch(r"[0-9]+", requirements.get("amount", "")):
        raise ValueError("amount must be an unsigned decimal string")
    extra = requirements.get("extra", {})
    if extra.get("paymentFlow") != "upfront":
        raise ValueError("BCH exact requires upfront payment")
    if extra.get("requestHash") is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", extra["requestHash"]):
        raise ValueError("requestHash must be 32-byte hexadecimal")


def validate_payment_payload(payload: dict[str, Any], expected: dict[str, Any]) -> None:
    """Validate the wallet-agnostic x402 BCH payment envelope and its binding."""
    validate_requirements(expected)
    if payload.get("x402Version") != 2:
        raise ValueError("payment payload does not bind to requirements")
    accepted = payload.get("accepted", {})
    for field in ("scheme", "network", "asset", "amount", "payTo"):
        if accepted.get(field) != expected.get(field):
            raise ValueError("accepted requirements mismatch")
    transaction = payload.get("payload", {}).get("transaction", "")
    try:
        if not base64.b64decode(transaction, validate=True):
            raise ValueError("empty transaction")
    except (ValueError, TypeError) as error:
        raise ValueError("transaction must be non-empty base64") from error


def request_hash(canonical_request: str) -> str:
    if not canonical_request:
        raise ValueError("canonical request must not be empty")
    return hashlib.sha256(canonical_request.encode()).hexdigest()
