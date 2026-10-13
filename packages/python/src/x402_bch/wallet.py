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
from .crypto import _SECP256K1_G, _SECP256K1_N, _secp_point_mul

@dataclass(frozen=True)
class BchTransactionRequest:
    network: str
    pay_to: str
    value: str
    asset: str
    token_amount: str | None = None
    token_nft: dict[str, str] | None = None
    request_hash: str | None = None


class BchWallet(Protocol):
    """Application-owned wallet boundary; private keys never cross it."""

    def create_payment(self, request: BchTransactionRequest) -> bytes:
        """Select UTXOs, calculate change/fees, sign, and return raw bytes."""


class BchSigner(Protocol):
    """Low-level signer boundary for caller-owned UTXO transaction builders."""

    def public_key(self) -> bytes: ...

    def sign_digest(self, digest: bytes) -> bytes: ...

    def address(self, network: str) -> str: ...


class Secp256k1BchSigner:
    """Mnemonic-backed BCH signer retaining key material only in this object."""

    def __init__(self, mnemonic: str, network: str = "bch:bchtest", passphrase: str = "", change: int = 0, index: int = 0, account: int = 0):
        self._network = network
        self._private_key = _derive_bip44_private_key(mnemonic, network, change, index, account, passphrase)

    def public_key(self) -> bytes:
        point = _secp_point_mul(int.from_bytes(self._private_key, "big"), _SECP256K1_G)
        if point is None: raise ValueError("invalid derived key")
        return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")

    def address(self, network: str | None = None) -> str:
        target = network or self._network
        target = {"mainnet": "bch:bitcoincash", "chipnet": "bch:bchtest"}.get(target, target)
        decoded = derive_bch_wallet_address_from_private(self._private_key, target)
        return str(decoded)

    def sign_digest(self, digest: bytes) -> bytes:
        if len(digest) != 32: raise ValueError("BCH signing digest must be 32 bytes")
        # RFC6979 HMAC-SHA256 deterministic nonce generation.
        x = self._private_key; z = int.from_bytes(digest, "big")
        v, k = b"\x01" * 32, b"\x00" * 32
        k = hmac.new(k, v + b"\x00" + x + digest, hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()
        k = hmac.new(k, v + b"\x01" + x + digest, hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()
        while True:
            v = hmac.new(k, v, hashlib.sha256).digest(); nonce = int.from_bytes(v, "big")
            if 1 <= nonce < _SECP256K1_N:
                point = _secp_point_mul(nonce, _SECP256K1_G); r = point[0] % _SECP256K1_N
                if r:
                    s = (pow(nonce, -1, _SECP256K1_N) * (z + r * int.from_bytes(x, "big"))) % _SECP256K1_N
                    if s > _SECP256K1_N // 2: s = _SECP256K1_N - s
                    return _encode_der_signature(r, s)
            k = hmac.new(k, v + b"\x00", hashlib.sha256).digest(); v = hmac.new(k, v, hashlib.sha256).digest()


def _encode_der_signature(r: int, s: int) -> bytes:
    def integer(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80: raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def _derive_bip44_private_key(mnemonic: str, network: str, change: int, index: int, account: int, passphrase: str) -> bytes:
    _validate_bip39_mnemonic(mnemonic)
    coin = 145 if network in ("bch:bitcoincash", "mainnet") else 1
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048, 64)
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest(); key, chain = digest[:32], digest[32:]
    for child_index in (0x8000002C, coin | 0x80000000, account | 0x80000000, change, index):
        point = _secp_point_mul(int.from_bytes(key, "big"), _SECP256K1_G); public = bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")
        data = (b"\0" + key if child_index >= 0x80000000 else public) + child_index.to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest(); key = ((int.from_bytes(digest[:32], "big") + int.from_bytes(key, "big")) % _SECP256K1_N).to_bytes(32, "big"); chain = digest[32:]
    return key


@lru_cache(maxsize=1)
def _bip39_words() -> tuple[str, ...]:
    packaged = files("x402_bch.data").joinpath("bip39-english.txt")
    if packaged.is_file():
        return tuple(packaged.read_text(encoding="utf-8").splitlines())
    path = Path(__file__).parents[2] / "spec/conformance/v1/bip39-english.txt"
    return tuple(path.read_text(encoding="utf-8").splitlines())


def _validate_bip39_mnemonic(mnemonic: str) -> None:
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24) or any(word not in _bip39_words() for word in words):
        raise ValueError("invalid BIP39 English mnemonic")
    bits = "".join(f"{_bip39_words().index(word):011b}" for word in words)
    entropy_bits = len(words) * 11 * 32 // 33
    entropy = int(bits[:entropy_bits], 2).to_bytes(entropy_bits // 8, "big")
    checksum = bits[entropy_bits:]
    expected = f"{hashlib.sha256(entropy).digest()[0]:08b}"[: len(checksum)]
    if checksum != expected:
        raise ValueError("invalid BIP39 mnemonic checksum")


def derive_bch_wallet_address_from_private(private_key: bytes, network: str) -> str:
    point = _secp_point_mul(int.from_bytes(private_key, "big"), _SECP256K1_G)
    public = bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")
    script = b"\x76\xa9\x14" + hashlib.new("ripemd160", hashlib.sha256(public).digest()).digest() + b"\x88\xac"
    return encode_cash_address(script, network)  # type: ignore[arg-type]


def derive_bch_wallet_address(
    mnemonic: str,
    network: str,
    change: int,
    index: int,
    account_index: int = 0,
    passphrase: str = "",
    coin_type: int | None = None,
) -> dict[str, object]:
    """Derive one BIP44 BCH address without retaining private key material."""
    if change not in (0, 1) or min(index, account_index) < 0:
        raise ValueError("invalid BIP44 derivation index")
    if network not in ("bch:bitcoincash", "bch:bchtest"):
        raise ValueError("unsupported BCH network")
    coin = coin_type if coin_type is not None else (145 if network == "bch:bitcoincash" else 1)
    if not 0 <= coin < 0x80000000 or account_index >= 0x80000000 or index >= 0xFFFFFFFF:
        raise ValueError("BIP44 derivation index is outside u32")
    _validate_bip39_mnemonic(mnemonic)
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048, 64)
    key, chain = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32], hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[32:]

    def child(parent: bytes, chain_code: bytes, child_index: int) -> tuple[bytes, bytes]:
        hardened = child_index >= 0x80000000
        point = _secp_point_mul(int.from_bytes(parent, "big"), _SECP256K1_G)
        if point is None: raise ValueError("invalid BIP32 parent key")
        x, y = point
        public = bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
        data = (b"\0" + parent if hardened else public) + child_index.to_bytes(4, "big")
        digest = hmac.new(chain_code, data, hashlib.sha512).digest()
        scalar = (int.from_bytes(digest[:32], "big") + int.from_bytes(parent, "big")) % _SECP256K1_N
        if scalar == 0: raise ValueError("invalid BIP32 child key")
        return scalar.to_bytes(32, "big"), digest[32:]

    for child_index in (0x8000002C, coin | 0x80000000, account_index | 0x80000000, change, index):
        key, chain = child(key, chain, child_index)
    point = _secp_point_mul(int.from_bytes(key, "big"), _SECP256K1_G)
    if point is None: raise ValueError("invalid derived key")
    x, y = point
    public_key = bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
    # encode_cash_address accepts the canonical P2PKH locking script.
    script = b"\x76\xa9\x14" + hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).digest() + b"\x88\xac"
    return {
        "address": encode_cash_address(script, network),
        "path": f"m/44'/{coin}'/{account_index}'/{change}/{index}",
        "change": change,
        "index": index,
        "publicKey": public_key.hex(),
    }


def discover_bch_hd_wallet_addresses(
    mnemonic: str,
    network: str,
    provider: BchProvider,
    gap_limit: int = 20,
    max_addresses: int = 1000,
    passphrase: str = "",
    account_index: int = 0,
) -> list[dict[str, object]]:
    """Discover used addresses on receive/change branches using provider UTXOs."""
    if gap_limit < 1 or max_addresses < gap_limit:
        raise ValueError("invalid HD discovery limits")
    discovered: list[dict[str, object]] = []
    coin_type = 145 if network == "bch:bitcoincash" else 1
    for change in (0, 1):
        unused = 0
        for index in range(max_addresses):
            if unused >= gap_limit: break
            wallet = derive_bch_wallet_address(mnemonic, network, change, index, account_index, passphrase, coin_type)
            utxos = provider.list_utxos(str(wallet["address"]))
            discovered.append({**wallet, "utxos": utxos})
            unused = unused + 1 if not utxos else 0
    return discovered


@dataclass(frozen=True)
class BchUtxo:
    txid: str
    vout: int
    value: str
    script_pub_key: str
    token: Any | None = None
    height: int | None = None
