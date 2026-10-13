"""Framework-neutral x402 HTTP 402 and retry header boundary."""

from __future__ import annotations

import base64

BCH_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
BCH_PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
BCH_PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"


def encode_bch_http_header(json_value: str) -> str:
    if not json_value:
        raise ValueError("HTTP x402 header JSON must not be empty")
    return base64.b64encode(json_value.encode()).decode()


def decode_bch_http_header(header: str) -> str:
    try:
        decoded = base64.b64decode(header, validate=True).decode()
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("HTTP x402 header is not valid non-empty base64") from error
    if not decoded:
        raise ValueError("HTTP x402 header JSON must not be empty")
    return decoded


def create_bch_payment_required_response(requirements_json: str) -> dict[str, object]:
    return {"status": 402, "headers": {BCH_PAYMENT_REQUIRED_HEADER: encode_bch_http_header(requirements_json)}, "body": "Payment required"}


def create_bch_payment_signature_header(payload_json: str) -> dict[str, str]:
    return {BCH_PAYMENT_SIGNATURE_HEADER: encode_bch_http_header(payload_json)}


def create_bch_payment_response(result_json: str) -> dict[str, str]:
    return {BCH_PAYMENT_RESPONSE_HEADER: encode_bch_http_header(result_json)}
