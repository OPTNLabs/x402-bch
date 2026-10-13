"""Deterministic in-memory UTXO provider for SDK integration tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .address import decode_cash_address
from .wallet import BchUtxo


@dataclass(frozen=True)
class MocknetTransaction:
    txid: str
    raw_transaction: bytes
    inputs: tuple[tuple[str, int], ...]
    outputs: tuple[dict[str, Any], ...]


class MocknetProvider:
    def __init__(self, network: str, initial_utxos: list[BchUtxo], tip_height: int = 0) -> None:
        if network not in ("bch:bitcoincash", "bch:bchtest"):
            raise ValueError("unsupported BCH network")
        self.network = network
        self.tip_height = tip_height
        self._unspent = {self._key(item.txid, item.vout): item for item in initial_utxos}
        self._outputs = {self._key(item.txid, item.vout): self._source(item) for item in initial_utxos}
        self._registered: dict[bytes, MocknetTransaction] = {}
        self._transactions: dict[str, bytes] = {}
        self._statuses: dict[str, dict[str, Any]] = {}

    def register_transaction(self, transaction: MocknetTransaction) -> None:
        if len(transaction.txid) != 64:
            raise ValueError("mocknet txid must be 32-byte hexadecimal")
        bytes.fromhex(transaction.txid)
        self._registered[transaction.raw_transaction] = transaction

    def list_utxos(self, address: str) -> list[BchUtxo]:
        script = decode_cash_address(address, self.network)["scriptPubKey"]
        return [item for item in self._unspent.values() if item.script_pub_key.lower() == script.hex()]

    def get_source_output(self, txid: str, vout: int) -> dict[str, Any]:
        try:
            return dict(self._outputs[self._key(txid, vout)])
        except KeyError as error:
            raise LookupError("mocknet source output was not found") from error

    def get_outpoint_status(self, txid: str, vout: int) -> str:
        key = self._key(txid, vout)
        if key in self._unspent:
            return "unspent"
        return "spent" if key in self._outputs else "unknown"

    def broadcast(self, raw_transaction: bytes) -> str:
        try:
            transaction = self._registered[raw_transaction]
        except KeyError as error:
            raise ValueError("mocknet transaction is not registered") from error
        if transaction.txid in self._statuses and self._statuses[transaction.txid]["kind"] != "conflicted":
            return transaction.txid
        for txid, vout in transaction.inputs:
            if self._key(txid, vout) not in self._unspent:
                raise ValueError("mocknet input is already spent")
        for txid, vout in transaction.inputs:
            del self._unspent[self._key(txid, vout)]
        for vout, output in enumerate(transaction.outputs):
            key = self._key(transaction.txid, vout)
            self._outputs[key] = dict(output)
            self._unspent[key] = BchUtxo(transaction.txid, vout, str(output["value"]), str(output["scriptPubKey"]), output.get("token"))
        self._transactions[transaction.txid] = raw_transaction
        self._statuses[transaction.txid] = {"kind": "mempool"}
        return transaction.txid

    def get_transaction(self, txid: str) -> bytes | None:
        return self._transactions.get(txid)

    def get_transaction_status(self, txid: str) -> dict[str, Any]:
        return dict(self._statuses.get(txid, {"kind": "notFound"}))

    def get_tip_height(self) -> int:
        return self.tip_height

    def has_double_spend_proof(self, _txid: str) -> bool:
        return False

    def confirm(self, txid: str, height: int | None = None) -> None:
        if txid not in self._transactions:
            raise LookupError("mocknet transaction is not known")
        confirmed_height = height if height is not None else self.tip_height
        self._statuses[txid] = {"kind": "confirmed", "height": confirmed_height}

    @staticmethod
    def _key(txid: str, vout: int) -> str:
        return f"{txid.lower()}:{vout}"

    @staticmethod
    def _source(utxo: BchUtxo) -> dict[str, Any]:
        return {"value": utxo.value, "scriptPubKey": utxo.script_pub_key, **({"token": utxo.token} if utxo.token is not None else {})}
