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
from .wallet import BchSigner, BchUtxo
from .core import Transaction, TransactionInput, TransactionOutput
from .core import request_hash_script
from .core import CashToken
from .crypto import _SECP256K1_G, _SECP256K1_N, _secp_point_mul

def build_and_sign_native_payment(
    selected: list[BchUtxo],
    merchant_script_pubkey: bytes,
    merchant_value: int,
    signer: BchSigner,
    fee_rate: int = 1,
    dust_threshold: int = 546,
    network: str = "mainnet",
    request_hash: str | None = None,
) -> bytes:
    """Build and sign a deterministic native-BCH P2PKH payment.

    UTXO selection and the private key remain caller-owned. The builder only
    constructs the explicit input/output state, signs BCH ForkID digests, and
    validates the resulting transaction before returning raw bytes.
    """
    if not selected or len(selected) > 100:
        raise ValueError("invalid BCH input count")
    if merchant_value < dust_threshold:
        raise ValueError("merchant output is dust")
    input_value = sum(int(utxo.value) for utxo in selected)
    if input_value < merchant_value:
        raise ValueError("selected BCH UTXOs do not cover payment")
    cashaddr_network = "bch:bitcoincash" if network in ("mainnet", "bch:bitcoincash") else "bch:bchtest"
    payer = decode_cash_address(signer.address(network), cashaddr_network)  # type: ignore[arg-type]
    change_script = payer["scriptPubKey"]
    if not isinstance(change_script, bytes):
        raise ValueError("signer address did not decode to a script")
    change = input_value - merchant_value
    source_outputs = [
        {"value": utxo.value, "scriptPubKey": utxo.script_pub_key}
        for utxo in selected
    ]

    def push(value: bytes) -> bytes:
        if len(value) > 75:
            raise ValueError("signature or public key push is too large")
        return bytes([len(value)]) + value

    for _ in range(32):
        include_change = change >= dust_threshold
        outputs = [TransactionOutput(merchant_value, merchant_script_pubkey)]
        if include_change:
            outputs.append(TransactionOutput(change, change_script))
        if request_hash is not None:
            outputs.append(TransactionOutput(0, request_hash_script(request_hash)))
        transaction = Transaction(
            version=2,
            inputs=tuple(
                TransactionInput(utxo.txid, utxo.vout, b"", 0xFFFFFFFF)
                for utxo in selected
            ),
            outputs=tuple(outputs),
            locktime=0,
        )
        public_key = signer.public_key()
        inputs = list(transaction.inputs)
        for index, (input_item, utxo) in enumerate(zip(inputs, selected)):
            digest = signing_hash(
                Transaction(transaction.version, tuple(inputs), transaction.outputs, 0),
                index,
                utxo.value,
                utxo.script_pub_key,
            )
            signature = signer.sign_digest(digest)
            inputs[index] = TransactionInput(
                input_item.txid,
                input_item.vout,
                push(signature + b"\x41") + push(public_key),
                input_item.sequence,
            )
        transaction = Transaction(transaction.version, tuple(inputs), transaction.outputs, 0)
        raw = serialize_transaction(transaction)
        required_fee = len(raw) * fee_rate
        available = input_value - merchant_value
        if not include_change:
            if available < required_fee:
                raise ValueError("selected BCH UTXOs do not cover fee")
            verify_native_payment(transaction, source_outputs, str(merchant_value), merchant_script_pubkey.hex(), fee_rate, dust_threshold)
            return raw
        desired_change = available - required_fee
        if desired_change < dust_threshold:
            change = 0
            continue
        if change > desired_change:
            change = desired_change
            continue
        verify_native_payment(transaction, source_outputs, str(merchant_value), merchant_script_pubkey.hex(), fee_rate, dust_threshold)
        return raw
    raise ValueError("BCH fee/change calculation did not converge")

def build_and_sign_cash_token_payment(
    selected: list[BchUtxo],
    merchant_script_pubkey: bytes,
    merchant_value: int,
    category: str,
    token_amount: int,
    signer: BchSigner,
    merchant_nft: tuple[str, bytes] | None = None,
    fee_rate: int = 1,
    dust_threshold: int = 1000,
    network: str = "mainnet",
    request_hash: str | None = None,
) -> bytes:
    """Build a fungible/NFT CashToken payment with explicit token state."""
    if not isinstance(category, str) or len(category) != 64:
        raise ValueError("CashToken category must be 32-byte hexadecimal")
    if token_amount < 0 or not selected:
        raise ValueError("invalid CashToken payment")
    source_tokens: list[CashToken] = []
    for utxo in selected:
        token = utxo.token
        if token is not None and (not isinstance(token, CashToken) or token.category.lower() != category.lower()):
            raise ValueError("selected UTXOs do not contain the requested CashToken")
        source_tokens.append(token if isinstance(token, CashToken) else CashToken(category.lower(), 0, None))
    source_amount = sum(token.amount for token in source_tokens)
    if source_amount < token_amount:
        raise ValueError("selected CashToken UTXOs do not cover payment")
    source_nfts = [token.nft for token in source_tokens if token.nft is not None]
    if sorted(source_nfts, key=repr) != sorted(([merchant_nft] if merchant_nft else []), key=repr):
        raise ValueError("selected NFT state does not match merchant output")
    input_value = sum(int(utxo.value) for utxo in selected)
    if input_value < merchant_value:
        raise ValueError("selected BCH UTXOs do not cover payment")
    chain = "bch:bitcoincash" if network in ("mainnet", "bch:bitcoincash") else "bch:bchtest"
    change_address = decode_cash_address(signer.address(network), chain)  # type: ignore[arg-type]
    change_script = change_address["scriptPubKey"]
    if not isinstance(change_script, bytes):
        raise ValueError("signer address did not decode to a script")
    change_value = input_value - merchant_value
    token_change = source_amount - token_amount
    sources = [{"value": u.value, "scriptPubKey": u.script_pub_key, "token": t} for u, t in zip(selected, source_tokens)]

    def push(value: bytes) -> bytes:
        if len(value) > 75: raise ValueError("push value is too large")
        return bytes([len(value)]) + value

    for _ in range(32):
        if change_value < dust_threshold and token_change > 0:
            raise ValueError("CashToken change requires a dust-valued BCH output")
        outputs = [TransactionOutput(merchant_value, merchant_script_pubkey, CashToken(category.lower(), token_amount, merchant_nft))]
        if token_change > 0:
            outputs.append(TransactionOutput(change_value, change_script, CashToken(category.lower(), token_change, None)))
        if request_hash is not None:
            outputs.append(TransactionOutput(0, request_hash_script(request_hash)))
        transaction = Transaction(2, tuple(TransactionInput(u.txid, u.vout, b"", 0xFFFFFFFF) for u in selected), tuple(outputs), 0)
        public_key = signer.public_key()
        inputs = list(transaction.inputs)
        for index, (input_item, utxo) in enumerate(zip(inputs, selected)):
            digest = signing_hash(transaction, index, utxo.value, utxo.script_pub_key)
            inputs[index] = TransactionInput(input_item.txid, input_item.vout, push(signer.sign_digest(digest) + b"\x41") + push(public_key), input_item.sequence)
        transaction = Transaction(2, tuple(inputs), transaction.outputs, 0)
        raw = serialize_transaction(transaction)
        required_fee = len(raw) * fee_rate
        available = input_value - merchant_value
        if available < required_fee: raise ValueError("selected BCH UTXOs do not cover fee")
        desired = available - required_fee
        if token_change == 0 and desired < 546: desired = 0
        if token_change > 0 and desired < dust_threshold: raise ValueError("selected BCH UTXOs do not cover token change dust")
        if change_value > desired:
            change_value = desired
            continue
        verify_cash_token_payment(transaction, sources, str(merchant_value), merchant_script_pubkey.hex(), category, str(token_amount), merchant_nft, fee_rate, dust_threshold)
        return raw
    raise ValueError("BCH fee/change calculation did not converge")
