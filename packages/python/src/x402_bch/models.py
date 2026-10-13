"""Shared BCH value models."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TransactionInput:
    txid: str
    vout: int
    script_sig: bytes
    sequence: int


@dataclass(frozen=True)
class TransactionOutput:
    value: int
    script_pubkey: bytes
    token: "CashToken | None" = None


@dataclass(frozen=True)
class CashToken:
    category: str
    amount: int
    nft: tuple[str, bytes] | None = None


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[TransactionInput, ...]
    outputs: tuple[TransactionOutput, ...]
    locktime: int
