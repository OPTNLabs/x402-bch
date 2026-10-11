"""Lossless x402-BCH wire-level primitives."""

import hashlib
import json
import re
from typing import Any


def validate_requirements(requirements: dict[str, Any]) -> None:
    if requirements.get("x402Version") != 2 or requirements.get("scheme") != "exact":
        raise ValueError("unsupported x402 requirements")
    if not re.fullmatch(r"[0-9]+", requirements.get("amount", "")):
        raise ValueError("amount must be an unsigned decimal string")
    extra = requirements.get("extra", {})
    if extra.get("paymentFlow") != "upfront":
        raise ValueError("BCH exact requires upfront payment")
    if extra.get("requestHash") is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", extra["requestHash"]):
        raise ValueError("requestHash must be 32-byte hexadecimal")


def request_hash(resource: Any) -> str:
    encoded = json.dumps(resource, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode()).hexdigest()
