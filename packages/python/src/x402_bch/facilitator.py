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
    get_request_hash_commitment,
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
from .provider import BchProvider
from .store import BchSettlementStore, InMemoryBchSettlementStore
from .core import Transaction, TransactionInput, TransactionOutput
from .core import CashToken

class ExactBchFacilitator:
    """Verify and settle unchanged wallet-signed BCH transactions."""

    def __init__(
        self,
        provider: BchProvider,
        strategy: str = "confirmations",
        confirmations: int = 1,
        settlement_store: BchSettlementStore | None = None,
    ) -> None:
        self.provider = provider
        self.strategy = strategy
        self.confirmations = confirmations
        self.store = settlement_store or InMemoryBchSettlementStore()

    def verify(self, payload: dict[str, Any], requirements: dict[str, Any]) -> dict[str, Any]:
        try:
            verified = self._verify_payment(payload, requirements, require_unspent=True)
            return {"isValid": True, "payer": verified["payer"], "transaction": verified["txid"]}
        except Exception as error:  # noqa: BLE001 - x402 returns normalized failure data
            return {"isValid": False, "payer": "", "invalidReason": f"invalid_exact_bch_payment:{error}"}

    def settle(self, payload: dict[str, Any], requirements: dict[str, Any]) -> dict[str, Any]:
        try:
            validate_payment_payload(payload, requirements)
            encoded = payload["payload"]["transaction"]
            raw = base64.b64decode(encoded, validate=True)
            txid = transaction_id(encoded)
        except Exception as error:  # noqa: BLE001
            return {"success": False, "errorReason": f"invalid_exact_bch_payment:{error}", "transaction": ""}

        observed = self.provider.get_transaction(txid)
        if observed is not None and provider_transaction_matches(txid, observed):
            try:
                observed_payload = {**payload, "payload": {"transaction": base64.b64encode(observed).decode("ascii")}}
                verified = self._verify_payment(observed_payload, requirements, require_unspent=False)
                if self._accepted(txid):
                    self.store.mark_accepted(txid)
                    return {"success": True, "transaction": txid, "payer": verified["payer"]}
            except Exception:
                pass

        binding = json.dumps(
            {"accepted": requirements, "resource": payload.get("resource")},
            sort_keys=True,
            separators=(",", ":"),
        )
        claim = self.store.claim(txid, binding)
        if claim == "conflict":
            return {"success": False, "errorReason": "transaction_already_claimed_for_another_request", "transaction": txid}
        if claim == "same":
            if not self._accepted(txid):
                return {"success": False, "errorReason": "settlement_pending", "transaction": txid}
            verified = self._verify_payment(payload, requirements, require_unspent=False)
            self.store.mark_accepted(txid)
            return {"success": True, "transaction": txid, "payer": verified["payer"]}

        try:
            verified = self._verify_payment(payload, requirements, require_unspent=True)
            broadcast_txid = self.provider.broadcast(raw)
            if broadcast_txid.lower() != txid.lower():
                raise ValueError("broadcast returned mismatched transaction ID")
        except Exception as error:  # noqa: BLE001
            status = self.provider.get_transaction_status(txid)
            if status.get("kind") == "notFound":
                self.store.release(txid)
                return {"success": False, "errorReason": f"broadcast_failed:{error}", "transaction": txid}
            return {"success": False, "errorReason": "settlement_pending", "transaction": txid}

        if not self._accepted(txid):
            return {"success": False, "errorReason": "settlement_pending", "transaction": txid}
        self.store.mark_accepted(txid)
        return {"success": True, "transaction": txid, "payer": verified["payer"]}

    def _verify_payment(self, payload: dict[str, Any], requirements: dict[str, Any], require_unspent: bool) -> dict[str, str]:
        validate_payment_payload(payload, requirements)
        transaction = parse_transaction(payload["payload"]["transaction"])
        merchant = decode_cash_address(requirements["payTo"], requirements["network"])
        expected_request_hash = requirements.get("extra", {}).get("requestHash")
        if expected_request_hash is not None and get_request_hash_commitment(transaction) != str(expected_request_hash).lower():
            raise ValueError("payment transaction does not commit to the requested resource hash")
        sources: list[dict[str, Any]] = []
        for input_value in transaction.inputs:
            source = self.provider.get_source_output(input_value.txid, input_value.vout)
            if require_unspent and self.provider.get_outpoint_status(input_value.txid, input_value.vout) != "unspent":
                raise ValueError("source output is not unspent")
            sources.append(source)
        extra = requirements.get("extra", {})
        if extra.get("assetTransferMethod") == "cashtoken":
            sources = [
                {**source, "token": source.get("token") or CashToken(requirements["asset"].lower(), 0, None)}
                for source in sources
            ]
            token = extra.get("token", {})
            nft = token.get("nft")
            merchant_nft = (nft["capability"], bytes.fromhex(nft["commitment"])) if nft else None
            result = verify_cash_token_payment(
                transaction, sources, extra.get("value", "1000"), merchant["scriptPubKey"].hex(),
                requirements["asset"], requirements["amount"], merchant_nft,
            )
        else:
            result = verify_native_payment(
                transaction, sources, requirements["amount"], merchant["scriptPubKey"].hex(),
            )
        return {"txid": result["txid"], "payer": ""}

    def _accepted(self, txid: str) -> bool:
        status = self.provider.get_transaction_status(txid)
        kind = status.get("kind")
        if self.strategy == "mempool":
            return kind in ("mempool", "confirmed")
        if self.strategy == "noDoubleSpendProof":
            return kind == "confirmed" or (
                kind == "mempool" and not self.provider.has_double_spend_proof(txid)
            )
        if self.strategy != "confirmations" or kind != "confirmed":
            return False
        height = status.get("height")
        tip = self.provider.get_tip_height()
        confirmations = max(1, self.confirmations)
        return isinstance(height, int) and tip >= height and tip - height + 1 >= confirmations
