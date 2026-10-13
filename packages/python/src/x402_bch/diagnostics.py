"""Stable, log-safe diagnostics for protocol and provider boundaries."""

from __future__ import annotations

from typing import Any

DIAGNOSTIC_REDACTED = "[redacted]"
_SENSITIVE = {"mnemonic", "privatekey", "seed", "secret", "authorization", "transaction", "rawtransaction", "signedtransaction"}


def create_bch_diagnostic(stage: str, code: str, message: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in (context or {}).items():
        safe[key] = DIAGNOSTIC_REDACTED if key.lower() in _SENSITIVE else value if value is None or isinstance(value, (str, int, float, bool)) else str(value)
    return {"stage": stage, "code": code, "message": message, "context": safe}
