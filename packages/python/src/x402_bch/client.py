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
from .wallet import BchSigner, BchTransactionRequest, BchUtxo, BchWallet
from .builders import build_and_sign_cash_token_payment, build_and_sign_native_payment
from .core import Transaction, TransactionInput, TransactionOutput
from .core import CashToken

def to_transaction_request(requirements: dict[str, Any]) -> BchTransactionRequest:
    """Translate x402 requirements into a wallet-owned transaction request."""

    validate_requirements(requirements)
    extra = requirements.get("extra", {})
    is_token = extra.get("assetTransferMethod") == "cashtoken"
    token = extra.get("token") if is_token else None
    return BchTransactionRequest(
        network="mainnet" if requirements["network"] == "bch:bitcoincash" else "chipnet",
        pay_to=requirements["payTo"],
        value=extra.get("value", requirements["amount"]) if is_token else requirements["amount"],
        asset=requirements["asset"],
        token_amount=requirements["amount"] if is_token else None,
        token_nft=token.get("nft") if isinstance(token, dict) else None,
        request_hash=extra.get("requestHash"),
    )


class ExactBchClient:
    """Create x402 payment payloads from a wallet-signed BCH transaction."""

    def __init__(self, wallet: BchWallet, provider: BchProvider) -> None:
        self.wallet = wallet
        self.provider = provider

    def create_payment_payload(self, requirements: dict[str, Any]) -> dict[str, Any]:
        request = to_transaction_request(requirements)
        raw = self.wallet.create_payment(request)
        if not isinstance(raw, bytes) or not raw:
            raise ValueError("wallet must return non-empty raw BCH transaction bytes")
        encoded = base64.b64encode(raw).decode("ascii")
        transaction = parse_transaction(encoded)
        merchant = decode_cash_address(requirements["payTo"], requirements["network"])
        sources = [
            self.provider.get_source_output(input_value.txid, input_value.vout)
            for input_value in transaction.inputs
        ]
        extra = requirements.get("extra", {})
        request_hash = extra.get("requestHash")
        if request_hash is not None:
            if get_request_hash_commitment(transaction) != str(request_hash).lower():
                raise ValueError("payment transaction does not commit to the requested resource hash")
        if extra.get("assetTransferMethod") == "cashtoken":
            token = extra.get("token", {})
            nft = token.get("nft") if isinstance(token, dict) else None
            merchant_nft = (nft["capability"], bytes.fromhex(nft["commitment"])) if nft else None
            sources = [
                {**source, "token": source.get("token") or CashToken(requirements["asset"].lower(), 0, None)}
                for source in sources
            ]
            verify_cash_token_payment(
                transaction,
                sources,
                str(extra.get("value", "1000")),
                merchant["scriptPubKey"].hex(),
                requirements["asset"],
                requirements["amount"],
                merchant_nft,
            )
        else:
            verify_native_payment(
                transaction, sources, requirements["amount"], merchant["scriptPubKey"].hex()
            )
        return {
            "x402Version": 2,
            "scheme": requirements["scheme"],
            "network": requirements["network"],
            "payload": {"transaction": encoded},
            "accepted": requirements,
        }


class ExactBchSignerClient:
    """Signer-backed exact client with provider-owned UTXO discovery.

    This is the low-level counterpart to :class:`ExactBchClient`: callers who
    do not delegate construction to an external wallet can still use the same
    request validation and payload boundary.
    """

    def __init__(self, signer: BchSigner, provider: BchProvider, fee_rate: int = 1, dust_threshold: int = 546) -> None:
        self.signer = signer
        self.provider = provider
        self.fee_rate = fee_rate
        self.dust_threshold = dust_threshold

    def create_payment_payload(self, requirements: dict[str, Any]) -> dict[str, Any]:
        validate_requirements(requirements)
        merchant = decode_cash_address(requirements["payTo"], requirements["network"])
        address = self.signer.address(requirements["network"])
        utxos = [
            item for item in self.provider.list_utxos(address)
            if item.script_pub_key.lower() == merchant_payer_script(self.signer, requirements["network"]).hex()
        ]
        extra = requirements.get("extra", {})
        is_token = extra.get("assetTransferMethod") == "cashtoken"
        category = requirements["asset"]
        if is_token:
            utxos = [item for item in utxos if item.token is None or item.token.category.lower() == category.lower()]
        else:
            utxos = [item for item in utxos if item.token is None]
        utxos.sort(key=lambda item: int(item.value), reverse=True)
        if not utxos:
            raise ValueError("no compatible BCH UTXOs available")
        selected: list[BchUtxo] = []
        value = 0
        token_amount = 0
        target_value = int(extra.get("value", requirements["amount"])) if is_token else int(requirements["amount"])
        target_tokens = int(requirements["amount"]) if is_token else 0
        for item in utxos:
            selected.append(item)
            value += int(item.value)
            token_amount += item.token.amount if item.token is not None else 0
            if value >= target_value and token_amount >= target_tokens:
                break
        if value < target_value or token_amount < target_tokens:
            raise ValueError("insufficient BCH/CashToken UTXOs for payment and fee")
        network = "mainnet" if requirements["network"] == "bch:bitcoincash" else "chipnet"
        request_hash = extra.get("requestHash")
        if is_token:
            nft = extra.get("token", {}).get("nft") if isinstance(extra.get("token"), dict) else None
            merchant_nft = (nft["capability"], bytes.fromhex(nft["commitment"])) if nft else None
            raw = build_and_sign_cash_token_payment(
                selected, merchant["scriptPubKey"], target_value, category, target_tokens,
                self.signer, merchant_nft, self.fee_rate, max(1000, self.dust_threshold), network, request_hash,
            )
        else:
            raw = build_and_sign_native_payment(
                selected, merchant["scriptPubKey"], target_value, self.signer,
                self.fee_rate, self.dust_threshold, network, request_hash,
            )

        class FixedWallet:
            def create_payment(self, _request: BchTransactionRequest) -> bytes:
                return raw

        return ExactBchClient(FixedWallet(), self.provider).create_payment_payload(requirements)


def merchant_payer_script(signer: BchSigner, network: str) -> bytes:
    decoded = decode_cash_address(signer.address(network), network)
    script = decoded.get("scriptPubKey")
    if not isinstance(script, bytes):
        raise ValueError("signer address did not decode to a script")
    return script
