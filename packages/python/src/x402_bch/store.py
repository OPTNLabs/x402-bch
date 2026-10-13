"""Wallet, provider, client, and facilitator boundaries for x402-BCH.

The interfaces in this module deliberately do not own keys, UTXO selection, or
network transport. A wallet returns one complete signed BCH transaction and a
provider supplies authoritative source outputs and transaction state.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from functools import lru_cache
from pathlib import Path
from importlib.resources import files
import json
from dataclasses import dataclass
from threading import Lock
from typing import Any, Protocol

from .address import decode_cash_address, encode_cash_address
from .core import (
    accepts_bch_settlement,
    parse_transaction,
    provider_transaction_matches,
    serialize_transaction,
    signing_hash,
    transaction_id,
    validate_payment_payload,
    validate_requirements,
    verify_cash_token_payment,
    verify_native_payment,
)
from .core import Transaction, TransactionInput, TransactionOutput
from .core import CashToken

class BchSettlementStore(Protocol):
    def claim(self, txid: str, binding: str) -> str: ...

    def mark_accepted(self, txid: str) -> None: ...

    def release(self, txid: str) -> None: ...


class InMemoryBchSettlementStore:
    """Single-process replay store; production deployments should share it."""

    def __init__(self) -> None:
        self._records: dict[str, tuple[str, bool]] = {}
        self._lock = Lock()

    def claim(self, txid: str, binding: str) -> str:
        with self._lock:
            record = self._records.get(txid)
            if record is None:
                self._records[txid] = (binding, False)
                return "acquired"
            return "same" if record[0] == binding else "conflict"

    def mark_accepted(self, txid: str) -> None:
        with self._lock:
            record = self._records.get(txid)
            if record is not None:
                self._records[txid] = (record[0], True)

    def release(self, txid: str) -> None:
        with self._lock:
            record = self._records.get(txid)
            if record is not None and not record[1]:
                del self._records[txid]
