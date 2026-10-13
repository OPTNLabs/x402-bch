"""x402 wire-level requirements and payment-payload helpers."""

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


def build_native_requirements(
    network: str, pay_to: str, amount: str, request_hash: str | None = None
) -> dict[str, Any]:
    """Build the server-side x402 exact offer for native BCH."""
    _validate_server_inputs(network, pay_to, amount)
    extra: dict[str, Any] = {
        "assetTransferMethod": "native",
        "paymentFlow": "upfront",
    }
    if request_hash is not None:
        _validate_request_hash(request_hash)
        extra["requestHash"] = request_hash
    return {
        "x402Version": 2,
        "scheme": "exact",
        "network": network,
        "amount": amount,
        "asset": "BCH",
        "payTo": pay_to,
        "maxTimeoutSeconds": 300,
        "extra": extra,
    }


def build_cash_token_requirements(
    network: str,
    pay_to: str,
    category: str,
    amount: str,
    value: str | None = None,
    request_hash: str | None = None,
    nft: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a server-side fungible or NFT CashToken offer."""
    _validate_server_inputs(network, pay_to, amount)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", category):
        raise ValueError("CashToken category must be 32-byte hexadecimal")
    value = "1000" if value is None else value
    if not re.fullmatch(r"(0|[1-9][0-9]*)", value):
        raise ValueError("CashToken value must be canonical satoshis")
    token: dict[str, Any] = {"category": category, "amount": amount}
    if nft is not None:
        if nft.get("capability") not in ("none", "mutable", "minting"):
            raise ValueError("CashToken NFT capability is invalid")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", nft.get("commitment", "")):
            raise ValueError("CashToken commitment must be hexadecimal")
        if len(nft["commitment"]) > 80:
            raise ValueError("CashToken commitment is too large")
        token["nft"] = dict(nft)
    extra: dict[str, Any] = {
        "assetTransferMethod": "cashtoken",
        "paymentFlow": "upfront",
        "value": value,
        "token": token,
    }
    if request_hash is not None:
        _validate_request_hash(request_hash)
        extra["requestHash"] = request_hash
    return {
        "x402Version": 2,
        "scheme": "exact",
        "network": network,
        "amount": amount,
        "asset": category,
        "payTo": pay_to,
        "maxTimeoutSeconds": 300,
        "extra": extra,
    }


def _validate_server_inputs(network: str, pay_to: str, amount: str) -> None:
    if network not in ("bch:bitcoincash", "bch:bchtest"):
        raise ValueError("unsupported BCH network")
    if not pay_to:
        raise ValueError("payTo is required")
    if not re.fullmatch(r"(0|[1-9][0-9]*)", amount):
        raise ValueError("amount must be a canonical decimal string")


def _validate_request_hash(request_hash: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", request_hash):
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
    if accepted.get("extra", {}) != expected.get("extra", {}):
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
