"""Wallet, provider, client, and facilitator boundaries for x402-BCH.

The interfaces in this module deliberately do not own keys, UTXO selection, or
network transport. A wallet returns one complete signed BCH transaction and a
provider supplies authoritative source outputs and transaction state.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import ssl
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
from .wallet import BchUtxo

class BchProvider(Protocol):
    """Authoritative BCH chain boundary used by clients and facilitators."""

    network: str
    def list_utxos(self, address: str) -> list[BchUtxo]: ...
    def get_source_output(self, txid: str, vout: int) -> dict[str, Any]: ...
    def get_outpoint_status(self, txid: str, vout: int) -> str: ...
    def broadcast(self, raw_transaction: bytes) -> str: ...
    def get_transaction(self, txid: str) -> bytes | None: ...
    def get_transaction_status(self, txid: str) -> dict[str, Any]: ...
    def get_tip_height(self) -> int: ...
    def has_double_spend_proof(self, txid: str) -> bool: ...
from .core import Transaction, TransactionInput, TransactionOutput
from .core import CashToken
from .crypto import _SECP256K1_G, _SECP256K1_N, _secp_point_mul

class FulcrumTransport(Protocol):
    def request(self, method: str, params: list[Any]) -> Any: ...


class SocketFulcrumTransport:
    """Concrete one-request-per-connection Electrum Cash JSON-RPC transport."""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 10.0,
        tls: bool = False,
        server_hostname: str | None = None,
    ) -> None:
        if not host or not (1 <= port <= 65535):
            raise ValueError("Fulcrum host and port are required")
        if timeout <= 0:
            raise ValueError("Fulcrum timeout must be positive")
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tls = tls
        self.server_hostname = server_hostname or host

    def request(self, method: str, params: list[Any]) -> Any:
        request = {"id": 1, "method": method, "params": params}
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as connection:
            connection.settimeout(self.timeout)
            if self.tls:
                context = ssl.create_default_context()
                with context.wrap_socket(connection, server_hostname=self.server_hostname) as secure:
                    secure.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
                    line = _read_json_line(secure)
            else:
                connection.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
                line = _read_json_line(connection)
        response = json.loads(line)
        if not isinstance(response, dict):
            raise ValueError("Fulcrum response is not an object")
        if response.get("error") is not None:
            error = response["error"]
            if isinstance(error, dict):
                raise RuntimeError(f"Fulcrum RPC error ({error.get('code', -1)}): {error.get('message', 'unknown error')}")
            raise RuntimeError("Fulcrum RPC error")
        return response.get("result")


def _read_json_line(connection: socket.socket) -> str:
    buffer = bytearray()
    while len(buffer) <= 4 * 1024 * 1024:
        chunk = connection.recv(4096)
        if not chunk:
            break
        buffer.extend(chunk)
        if b"\n" in chunk:
            return bytes(buffer).split(b"\n", 1)[0].decode()
    raise ValueError("Fulcrum response is missing a newline-delimited JSON message")


class FailoverFulcrumTransport:
    """Sequentially retries injected Electrum Cash transports."""

    def __init__(self, transports: list[FulcrumTransport]) -> None:
        if not transports:
            raise ValueError("at least one Fulcrum transport is required")
        self.transports = transports

    def request(self, method: str, params: list[Any]) -> Any:
        errors: list[str] = []
        for transport in self.transports:
            try:
                return transport.request(method, params)
            except Exception as error:  # noqa: BLE001
                errors.append(str(error))
        raise RuntimeError(f"all Fulcrum transports failed: {'; '.join(errors)}")


class FulcrumProvider:
    """Transport-backed Electrum Cash provider for the SDK role surface.

    The transport owns TCP/TLS/WebSocket concerns. This adapter only maps
    Fulcrum JSON-RPC results into the chain-authoritative provider contract.
    """

    def __init__(self, network: str, transport: FulcrumTransport) -> None:
        if network not in ("bch:bitcoincash", "bch:bchtest"):
            raise ValueError("unsupported BCH network")
        self.network = network
        self.transport = transport

    def _script_hash(self, address: str) -> str:
        decoded = decode_cash_address(address, self.network)  # type: ignore[arg-type]
        script = decoded["scriptPubKey"]
        if not isinstance(script, bytes):
            raise ValueError("decoded CashAddr did not contain script bytes")
        return hashlib.sha256(script).digest()[::-1].hex()

    def list_utxos(self, address: str) -> list[BchUtxo]:
        result = self.transport.request(
            "blockchain.scripthash.listunspent", [self._script_hash(address), "include_tokens"]
        )
        if not isinstance(result, list):
            raise ValueError("Fulcrum listunspent response is not an array")
        script = decode_cash_address(address, self.network)["scriptPubKey"]
        if not isinstance(script, bytes):
            raise ValueError("decoded CashAddr did not contain script bytes")
        return [
            BchUtxo(
                txid=str(item.get("tx_hash", item.get("txid", ""))),
                vout=int(item.get("tx_pos", item.get("vout", -1))),
                value=str(item.get("value", "")),
                script_pub_key=script.hex(),
                token=_fulcrum_token(item),
                height=int(item["height"]) if int(item.get("height", 0)) > 0 else None,
            )
            for item in result
            if isinstance(item, dict)
        ]

    def get_source_output(self, txid: str, vout: int) -> dict[str, Any]:
        result = self.transport.request("blockchain.transaction.get", [txid, True])
        if not isinstance(result, dict) or not isinstance(result.get("vout"), list):
            raise ValueError("Fulcrum transaction response has no vout array")
        for item in result["vout"]:
            if not isinstance(item, dict) or int(item.get("n", -1)) != vout:
                continue
            script = item.get("scriptPubKey", {})
            if not isinstance(script, dict) or not isinstance(script.get("hex"), str):
                raise ValueError("source output has no script hex")
            return {"value": item.get("value"), "scriptPubKey": script["hex"]}
        raise LookupError("source output was not found")

    def get_outpoint_status(self, txid: str, vout: int) -> str:
        # Electrum Cash cannot determine an outpoint's spend state from the
        # transaction alone. A provider implementation must index the source
        # script hash (or expose a richer outpoint API); fail closed here.
        del txid, vout
        return "unknown"

    def broadcast(self, raw_transaction: bytes) -> str:
        result = self.transport.request(
            "blockchain.transaction.broadcast", [raw_transaction.hex()]
        )
        if not isinstance(result, str) or len(result) != 64:
            raise ValueError("Fulcrum broadcast did not return a transaction ID")
        return result.lower()

    def get_transaction(self, txid: str) -> bytes | None:
        try:
            result = self.transport.request("blockchain.transaction.get", [txid])
        except Exception as error:  # noqa: BLE001
            if "not found" in str(error).lower() or "no transaction" in str(error).lower():
                return None
            raise
        if not isinstance(result, str):
            raise ValueError("Fulcrum transaction response is not raw hexadecimal data")
        return bytes.fromhex(result)

    def get_transaction_status(self, txid: str) -> dict[str, Any]:
        try:
            height = int(self.transport.request("blockchain.transaction.get_height", [txid]))
        except Exception as error:  # noqa: BLE001
            if "not found" in str(error).lower() or "no transaction" in str(error).lower():
                return {"kind": "notFound"}
            raise
        if height > 0:
            return {"kind": "confirmed", "height": height}
        if height in (0, -1):
            return {"kind": "mempool"}
        return {"kind": "notFound"}

    def get_tip_height(self) -> int:
        result = self.transport.request("blockchain.headers.subscribe", [])
        if not isinstance(result, dict) or not isinstance(result.get("height"), int):
            raise ValueError("invalid Fulcrum chain tip")
        return result["height"]

    def has_double_spend_proof(self, txid: str) -> bool:
        result = self.transport.request("blockchain.transaction.dsproof.get", [txid])
        return result not in (None, "")


def _fulcrum_token(item: dict[str, Any]) -> CashToken | None:
    token = item.get("token_data", item.get("tokenData"))
    if not isinstance(token, dict) or not isinstance(token.get("category"), str):
        return None
    nft_value = token.get("nft")
    nft = None
    if isinstance(nft_value, dict):
        capability = nft_value.get("capability")
        commitment = nft_value.get("commitment", "")
        if isinstance(capability, str) and isinstance(commitment, str):
            nft = (capability, bytes.fromhex(commitment))
    return CashToken(token["category"].lower(), int(token.get("amount", 0)), nft)
