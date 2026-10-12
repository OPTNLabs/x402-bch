"""BCH CashAddr and standard locking-script primitives."""

from __future__ import annotations

from typing import Literal

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_PREFIX = {"bch:bitcoincash": "bitcoincash", "bch:bchtest": "bchtest"}
_HASH_LENGTHS = (20, 24, 28, 32, 40, 48, 56, 64)


def _polymod(values: list[int]) -> int:
    generator = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2Eabe2A8, 0x1E4F43E470)
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for index, item in enumerate(generator):
            if (top >> index) & 1:
                checksum ^= item
    return checksum


def _prefix_expand(prefix: str) -> list[int]:
    return [ord(value) & 0x1F for value in prefix] + [0]


def _convert_bits(values: list[int], from_bits: int, to_bits: int, pad: bool) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    maximum = (1 << to_bits) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            raise ValueError("CashAddr data contains an invalid value")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & maximum)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & maximum)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & maximum):
        raise ValueError("CashAddr has non-zero padding")
    return result


def _script_for_hash(kind: str, payload: bytes) -> bytes:
    if kind == "p2pkh" and len(payload) == 20:
        return b"\x76\xa9\x14" + payload + b"\x88\xac"
    if kind == "p2sh" and len(payload) in (20, 32):
        return (b"\xa9\x14" if len(payload) == 20 else b"\xaa\x20") + payload + b"\x87"
    raise ValueError("unsupported CashAddr payload")


def decode_cash_address(address: str, network: Literal["bch:bitcoincash", "bch:bchtest"]) -> dict[str, object]:
    """Decode a network-bound CashAddr into standard locking bytecode."""
    if address != address.lower() or ":" not in address:
        raise ValueError("CashAddr must be lowercase and include a prefix")
    prefix, encoded = address.split(":", 1)
    if prefix != _PREFIX[network]:
        raise ValueError("CashAddr network mismatch")
    if not encoded or any(value not in _CHARSET for value in encoded):
        raise ValueError("invalid CashAddr characters")
    values = [_CHARSET.index(value) for value in encoded]
    if _polymod(_prefix_expand(prefix) + values) != 1:
        raise ValueError("invalid CashAddr checksum")
    payload = _convert_bits(values[:-8], 5, 8, False)
    if not payload:
        raise ValueError("CashAddr payload is empty")
    version = payload[0]
    token_support = bool(version & 0x10)
    base_version = version & 0x0F
    kind_code = base_version >> 3
    size_code = base_version & 0x07
    if kind_code not in (0, 1) or size_code >= len(_HASH_LENGTHS):
        raise ValueError("unsupported CashAddr type")
    hash_payload = bytes(payload[1:])
    if len(hash_payload) != _HASH_LENGTHS[size_code]:
        raise ValueError("CashAddr payload length does not match version")
    kind = "p2pkh" if kind_code == 0 else "p2sh"
    return {"scriptPubKey": _script_for_hash(kind, hash_payload), "tokenSupport": token_support}


def encode_cash_address(
    script_pubkey: bytes,
    network: Literal["bch:bitcoincash", "bch:bchtest"],
    token_support: bool = False,
) -> str:
    """Encode a standard P2PKH, P2SH20, or P2SH32 script as CashAddr."""
    if len(script_pubkey) == 25 and script_pubkey[:3] == b"\x76\xa9\x14" and script_pubkey[-2:] == b"\x88\xac":
        kind_code, payload = 0, script_pubkey[3:-2]
    elif len(script_pubkey) == 23 and script_pubkey[:2] == b"\xa9\x14" and script_pubkey[-1:] == b"\x87":
        kind_code, payload = 1 << 3, script_pubkey[2:-1]
    elif len(script_pubkey) == 35 and script_pubkey[:2] == b"\xaa\x20" and script_pubkey[-1:] == b"\x87":
        kind_code, payload = (1 << 3) | 3, script_pubkey[2:-1]
    else:
        raise ValueError("unsupported locking script for CashAddr")
    version = kind_code | (0x10 if token_support else 0)
    prefix = _PREFIX[network]
    data = _convert_bits([version, *payload], 8, 5, True)
    checksum = _polymod(_prefix_expand(prefix) + data + [0] * 8) ^ 1
    data.extend((checksum >> (5 * (7 - index))) & 0x1F for index in range(8))
    return f"{prefix}:{''.join(_CHARSET[value] for value in data)}"
