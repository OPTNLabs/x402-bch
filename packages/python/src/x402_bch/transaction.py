"""BCH transaction models, codecs, commitments, and signing hashes."""

import base64
import hashlib
import re
import struct

from .models import CashToken, Transaction, TransactionInput, TransactionOutput
from .crypto import _double_sha256
def validate_transaction_envelope(transaction: str) -> None:
    """Check the portable BCH envelope boundary, without claiming VM validation."""
    try:
        raw = base64.b64decode(transaction, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("transaction envelope must be valid non-empty base64") from error
    if len(raw) < 10:
        raise ValueError("transaction envelope is incomplete")
    version = int.from_bytes(raw[:4], "little")
    if version not in (1, 2):
        raise ValueError("unsupported transaction version")
    if raw[4] == 0:
        raise ValueError("transaction must contain an input")


def transaction_id(transaction: str) -> str:
    """Return the conventional little-endian-display BCH txid."""
    try:
        raw = base64.b64decode(transaction, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("transaction must be non-empty base64") from error
    if not raw:
        raise ValueError("transaction must be non-empty base64")
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def request_hash_script(request_hash_value: str) -> bytes:
    """Build the canonical zero-value OP_RETURN request commitment script."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", request_hash_value):
        raise ValueError("request hash must be 32-byte hexadecimal")
    return b"\x6a\x20" + bytes.fromhex(request_hash_value)


def _read_compact_size(raw: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(raw):
        raise ValueError("transaction ended while reading compact size")
    prefix = raw[offset]
    offset += 1
    if prefix < 253:
        return prefix, offset
    width = {253: 2, 254: 4, 255: 8}[prefix]
    if offset + width > len(raw):
        raise ValueError("transaction ended while reading compact size")
    value = int.from_bytes(raw[offset : offset + width], "little")
    if value < (253 if width == 2 else 65536 if width == 4 else 4294967296):
        raise ValueError("non-canonical compact size")
    return value, offset + width


def _write_compact_size(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("compact size is outside u64")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def _read_bytes(raw: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    if length < 0 or offset + length > len(raw):
        raise ValueError(f"transaction ended while reading {label}")
    return raw[offset : offset + length], offset + length


def _read_token_prefix(field: bytes) -> tuple[CashToken | None, bytes]:
    if not field or field[0] != 0xEF:
        return None, field
    if len(field) < 34:
        raise ValueError("CashToken prefix is too short")
    category = field[1:33][::-1].hex()
    bitfield = field[33]
    structure = bitfield & 0xF0
    capability = bitfield & 0x0F
    if structure & 0x80:
        raise ValueError("CashToken prefix has a reserved bit")
    if capability > 2:
        raise ValueError("CashToken NFT capability is invalid")
    has_nft = bool(structure & 0x20)
    has_commitment = bool(structure & 0x40)
    has_amount = bool(structure & 0x10)
    if has_commitment and not has_nft:
        raise ValueError("CashToken commitment requires an NFT")
    if capability and not has_nft:
        raise ValueError("CashToken capability requires an NFT")
    offset = 34
    commitment = b""
    if has_nft and has_commitment:
        length, offset = _read_compact_size(field, offset)
        if length == 0 or length > 40:
            raise ValueError("CashToken NFT commitment length is invalid")
        commitment, offset = _read_bytes(field, offset, length, "CashToken commitment")
    amount = 0
    if has_amount:
        amount, offset = _read_compact_size(field, offset)
        if amount == 0 or amount > 0x7FFFFFFFFFFFFFFF:
            raise ValueError("CashToken amount is outside the supported range")
    if not has_nft and not has_amount:
        raise ValueError("CashToken prefix does not encode a token")
    nft = None if not has_nft else (("none", "mutable", "minting")[capability], commitment)
    return CashToken(category, amount, nft), field[offset:]


def _encode_token_prefix(token: CashToken | None) -> bytes:
    if token is None or (token.nft is None and token.amount == 0):
        return b""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", token.category):
        raise ValueError("CashToken category must be 32-byte hexadecimal")
    if token.amount < 0 or token.amount > 0x7FFFFFFFFFFFFFFF:
        raise ValueError("CashToken amount is outside the supported range")
    prefix = bytearray(b"\xEF")
    prefix.extend(bytes.fromhex(token.category)[::-1])
    bitfield = 0
    if token.nft is not None:
        capability, commitment = token.nft
        if capability not in ("none", "mutable", "minting"):
            raise ValueError("CashToken NFT capability is invalid")
        bitfield |= ("none", "mutable", "minting").index(capability) | 0x20
        if len(commitment) > 40:
            raise ValueError("CashToken NFT commitment is too large")
        if commitment:
            bitfield |= 0x40
    else:
        commitment = b""
    if token.amount > 0:
        bitfield |= 0x10
    prefix.append(bitfield)
    if commitment:
        prefix.extend(_write_compact_size(len(commitment)))
        prefix.extend(commitment)
    if token.amount > 0:
        prefix.extend(_write_compact_size(token.amount))
    return bytes(prefix)


def parse_transaction(transaction: str) -> Transaction:
    """Parse a strict base64-encoded BCH transaction without executing scripts."""
    try:
        raw = base64.b64decode(transaction, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("transaction must be non-empty base64") from error
    if not raw:
        raise ValueError("transaction must be non-empty base64")
    offset = 0
    version_bytes, offset = _read_bytes(raw, offset, 4, "version")
    version = int.from_bytes(version_bytes, "little", signed=True)
    if version not in (1, 2):
        raise ValueError("unsupported transaction version")
    input_count, offset = _read_compact_size(raw, offset)
    if input_count == 0 or input_count > 100:
        raise ValueError("invalid transaction input count")
    inputs: list[TransactionInput] = []
    for _ in range(input_count):
        outpoint, offset = _read_bytes(raw, offset, 32, "outpoint hash")
        vout_bytes, offset = _read_bytes(raw, offset, 4, "outpoint index")
        script_length, offset = _read_compact_size(raw, offset)
        script_sig, offset = _read_bytes(raw, offset, script_length, "unlocking script")
        sequence_bytes, offset = _read_bytes(raw, offset, 4, "sequence")
        inputs.append(
            TransactionInput(
                txid=outpoint[::-1].hex(),
                vout=int.from_bytes(vout_bytes, "little"),
                script_sig=script_sig,
                sequence=int.from_bytes(sequence_bytes, "little"),
            )
        )
    output_count, offset = _read_compact_size(raw, offset)
    if output_count == 0 or output_count > 16:
        raise ValueError("invalid transaction output count")
    outputs: list[TransactionOutput] = []
    for _ in range(output_count):
        value_bytes, offset = _read_bytes(raw, offset, 8, "output value")
        script_length, offset = _read_compact_size(raw, offset)
        locking_field, offset = _read_bytes(raw, offset, script_length, "locking script")
        token, script_pubkey = _read_token_prefix(locking_field)
        outputs.append(TransactionOutput(int.from_bytes(value_bytes, "little"), script_pubkey, token))
    locktime_bytes, offset = _read_bytes(raw, offset, 4, "locktime")
    if offset != len(raw):
        raise ValueError("trailing transaction bytes")
    return Transaction(version, tuple(inputs), tuple(outputs), int.from_bytes(locktime_bytes, "little"))


def serialize_transaction(transaction: Transaction) -> bytes:
    """Serialize the portable transaction model using canonical BCH encoding."""
    if not transaction.inputs or len(transaction.inputs) > 100:
        raise ValueError("invalid transaction input count")
    if not transaction.outputs or len(transaction.outputs) > 16:
        raise ValueError("invalid transaction output count")
    result = bytearray(struct.pack("<i", transaction.version))
    result.extend(_write_compact_size(len(transaction.inputs)))
    for item in transaction.inputs:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", item.txid):
            raise ValueError("input txid must be 32-byte hexadecimal")
        if item.vout < 0 or item.vout > 0xFFFFFFFF or item.sequence < 0 or item.sequence > 0xFFFFFFFF:
            raise ValueError("input index or sequence is outside u32")
        result.extend(bytes.fromhex(item.txid)[::-1])
        result.extend(struct.pack("<I", item.vout))
        result.extend(_write_compact_size(len(item.script_sig)))
        result.extend(item.script_sig)
        result.extend(struct.pack("<I", item.sequence))
    result.extend(_write_compact_size(len(transaction.outputs)))
    for item in transaction.outputs:
        if item.value < 0 or item.value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("output value is outside u64")
        result.extend(struct.pack("<Q", item.value))
        locking_field = _encode_token_prefix(item.token) + item.script_pubkey
        result.extend(_write_compact_size(len(locking_field)))
        result.extend(locking_field)
    if transaction.locktime < 0 or transaction.locktime > 0xFFFFFFFF:
        raise ValueError("locktime is outside u32")
    result.extend(struct.pack("<I", transaction.locktime))
    return bytes(result)


def get_request_hash_commitment(transaction: Transaction) -> str | None:
    """Return the canonical zero-value OP_RETURN request commitment, if present."""
    for output in transaction.outputs:
        script = output.script_pubkey
        if output.value == 0 and len(script) == 34 and script[:2] == b"\x6a\x20":
            return script[2:].hex()
    return None


def assert_request_hash_commitment(transaction: Transaction, request_hash_value: str) -> None:
    """Require a transaction to commit to the requested 32-byte resource hash."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", request_hash_value):
        raise ValueError("request hash must be 32-byte hexadecimal")
    if get_request_hash_commitment(transaction) != request_hash_value.lower():
        raise ValueError("payment transaction does not commit to the requested resource hash")


def signing_hash(
    transaction: Transaction,
    input_index: int,
    source_value: str,
    source_script_pubkey: str,
) -> bytes:
    """Return the BCH ForkID digest for one P2PKH input."""
    if input_index < 0 or input_index >= len(transaction.inputs):
        raise ValueError("invalid input index")
    value = _canonical_uint(source_value, "source value")
    source_script = bytes.fromhex(source_script_pubkey)
    current = transaction.inputs[input_index]
    prevouts = b"".join(
        bytes.fromhex(item.txid)[::-1] + struct.pack("<I", item.vout)
        for item in transaction.inputs
    )
    sequences = b"".join(struct.pack("<I", item.sequence) for item in transaction.inputs)
    outputs = b"".join(
        struct.pack("<Q", item.value)
        + _write_compact_size(len(_encode_token_prefix(item.token) + item.script_pubkey))
        + _encode_token_prefix(item.token)
        + item.script_pubkey
        for item in transaction.outputs
    )
    preimage = (
        struct.pack("<i", transaction.version)
        + _double_sha256(prevouts)
        + _double_sha256(sequences)
        + bytes.fromhex(current.txid)[::-1]
        + struct.pack("<I", current.vout)
        + _write_compact_size(len(source_script))
        + source_script
        + struct.pack("<Q", value)
        + struct.pack("<I", current.sequence)
        + _double_sha256(outputs)
        + struct.pack("<I", transaction.locktime)
        + struct.pack("<I", 0x41)
    )
    return _double_sha256(preimage)


def _canonical_uint(value: str, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise ValueError(f"{label} must be canonical unsigned units")
    parsed = int(value)
    if parsed > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{label} exceeds u64")
    return parsed
