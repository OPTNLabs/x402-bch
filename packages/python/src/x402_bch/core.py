"""Lossless x402-BCH wire-level primitives."""

import hashlib
import re
import base64
import struct
from dataclasses import dataclass
from typing import Any


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


def validate_requirements(requirements: dict[str, Any]) -> None:
    if requirements.get("x402Version") not in (None, 2) or requirements.get("scheme") != "exact":
        raise ValueError("unsupported x402 requirements")
    if requirements.get("network") not in ("bch:bitcoincash", "bch:bchtest"):
        raise ValueError("unsupported BCH network")
    if not requirements.get("asset") or not requirements.get("payTo"):
        raise ValueError("asset and payTo are required")
    if not re.fullmatch(r"[0-9]+", requirements.get("amount", "")):
        raise ValueError("amount must be an unsigned decimal string")
    extra = requirements.get("extra", {})
    if extra.get("paymentFlow") != "upfront":
        raise ValueError("BCH exact requires upfront payment")
    if extra.get("requestHash") is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", extra["requestHash"]):
        raise ValueError("requestHash must be 32-byte hexadecimal")


def validate_payment_payload(payload: dict[str, Any], expected: dict[str, Any]) -> None:
    """Validate the wallet-agnostic x402 BCH payment envelope and its binding."""
    validate_requirements(expected)
    if payload.get("x402Version") != 2:
        raise ValueError("payment payload does not bind to requirements")
    accepted = payload.get("accepted", {})
    for field in ("scheme", "network", "asset", "amount", "payTo"):
        if accepted.get(field) != expected.get(field):
            raise ValueError("accepted requirements mismatch")
    if accepted.get("extra", {}) != expected.get("extra", {}):
        raise ValueError("accepted requirements mismatch")
    transaction = payload.get("payload", {}).get("transaction", "")
    try:
        if not base64.b64decode(transaction, validate=True):
            raise ValueError("empty transaction")
    except (ValueError, TypeError) as error:
        raise ValueError("transaction must be non-empty base64") from error


def request_hash(canonical_request: str) -> str:
    if not canonical_request:
        raise ValueError("canonical request must not be empty")
    return hashlib.sha256(canonical_request.encode()).hexdigest()


def accepts_bch_settlement(
    strategy: str,
    status: str,
    confirmations: int = 0,
    height: int | None = None,
    tip_height: int | None = None,
    double_spend_proof: bool = False,
) -> bool:
    """Apply the pure BCH settlement policy to provider-observed facts."""
    if strategy == "mempool":
        return status in ("mempool", "confirmed")
    if strategy == "noDoubleSpendProof":
        return status == "confirmed" or (status == "mempool" and not double_spend_proof)
    if strategy != "confirmations" or confirmations < 1 or status != "confirmed":
        return False
    if height is None or tip_height is None or tip_height < height:
        return False
    return tip_height - height + 1 >= confirmations


def resolve_bch_settlement_outcome(
    candidate_valid: bool,
    provider_observation: str,
    strategy: str,
    status: str,
    confirmations: int = 0,
    height: int | None = None,
    tip_height: int | None = None,
    double_spend_proof: bool = False,
) -> str:
    """Normalize provider and policy facts into a retry-safe outcome."""
    if (
        not candidate_valid
        or provider_observation == "mismatch"
        or provider_observation not in ("missing", "match")
        or status == "conflicted"
    ):
        return "rejected"
    if provider_observation == "missing":
        return "pending"
    return (
        "accepted"
        if accepts_bch_settlement(
            strategy, status, confirmations, height, tip_height, double_spend_proof
        )
        else "pending"
    )


def evaluate_bch_vm(unlocking_script: bytes, locking_script: bytes) -> dict[str, bool | str | None]:
    """Evaluate the bounded BCH VM profile used by cross-language fixtures."""
    stack: list[bytes] = []
    error = _execute_bch_script(unlocking_script, stack)
    if error is None:
        error = _execute_bch_script(locking_script, stack)
    if error is None and len(stack) != 1:
        error = "CLEANSTACK"
    if error is None and not _vm_truthy(stack[0]):
        error = "FALSE"
    return {"accepted": error is None, "errorCode": error}


def resolve_bch_settlement_integration(
    candidate_txid: str,
    candidate_valid: bool,
    binding_matches: bool,
    existing_claim: str,
    provider_observation: str,
    strategy: str,
    status: str,
    confirmations: int = 0,
    height: int | None = None,
    tip_height: int | None = None,
    broadcast_attempt: str = "none",
) -> dict[str, str]:
    """Model deterministic facilitator retry orchestration without side effects."""
    transaction_id = candidate_txid if candidate_valid else ""
    if not candidate_valid or not binding_matches or provider_observation == "mismatch":
        return {"state": "rejected", "transactionId": transaction_id, "nextAction": "reject"}
    if existing_claim == "different":
        return {"state": "rejected", "transactionId": transaction_id, "nextAction": "conflict"}
    state = resolve_bch_settlement_outcome(
        True, provider_observation, strategy, status, confirmations, height, tip_height, False
    )
    if state != "pending":
        return {
            "state": state,
            "transactionId": transaction_id,
            "nextAction": "skip" if state == "accepted" else "reject",
        }
    if provider_observation == "missing" and existing_claim == "none" and broadcast_attempt == "none":
        return {"state": state, "transactionId": transaction_id, "nextAction": "broadcast"}
    if provider_observation == "missing" and broadcast_attempt == "lost":
        return {"state": state, "transactionId": transaction_id, "nextAction": "retry"}
    return {"state": state, "transactionId": transaction_id, "nextAction": "retain"}


def resolve_bch_settlement_from_provider(
    candidate_txid: str,
    candidate_valid: bool,
    binding_matches: bool,
    existing_claim: str,
    strategy: str,
    status: str,
    confirmations: int = 0,
    height: int | None = None,
    tip_height: int | None = None,
    broadcast_attempt: str = "none",
    raw_transaction: bytes | None = None,
) -> dict[str, str]:
    """Derive provider observation from raw bytes and resolve settlement."""
    return resolve_bch_settlement_integration(
        candidate_txid,
        candidate_valid,
        binding_matches,
        existing_claim,
        observe_bch_provider_transaction(candidate_txid, raw_transaction),
        strategy,
        status,
        confirmations,
        height,
        tip_height,
        broadcast_attempt,
    )


def provider_transaction_matches(candidate_txid: str, raw_transaction: bytes | None) -> bool:
    """Verify provider bytes recompute to the candidate transaction ID."""
    if raw_transaction is None or not re.fullmatch(r"[0-9a-fA-F]{64}", candidate_txid):
        return False
    encoded = base64.b64encode(raw_transaction).decode()
    try:
        parse_transaction(encoded)
        return transaction_id(encoded).lower() == candidate_txid.lower()
    except ValueError:
        return False


def observe_bch_provider_transaction(candidate_txid: str, raw_transaction: bytes | None) -> str:
    """Derive chain evidence from provider bytes before settlement decisions."""
    if raw_transaction is None:
        return "missing"
    return "match" if provider_transaction_matches(candidate_txid, raw_transaction) else "mismatch"


def get_bch_provider_source_output(
    source_txid: str, vout: int, raw_transaction: bytes | None
) -> dict[str, object]:
    """Project one source output only after provider txid reconciliation."""
    observation = observe_bch_provider_transaction(source_txid, raw_transaction)
    if observation in ("missing", "mismatch"):
        return {"observation": observation}
    try:
        encoded = base64.b64encode(raw_transaction or b"").decode()
        transaction = parse_transaction(encoded)
        if vout < 0 or vout >= len(transaction.outputs):
            return {"observation": "notFound"}
        output = transaction.outputs[vout]
    except (ValueError, IndexError):
        return {"observation": "notFound"}
    return {
        "observation": "match",
        "sourceOutput": {
            "value": str(output.value),
            "scriptPubKey": output.script_pubkey.hex(),
        },
    }


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


def _execute_bch_script(script: bytes, stack: list[bytes]) -> str | None:
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        if opcode == 0:
            stack.append(b"")
            continue
        if 1 <= opcode <= 75:
            value, offset, error = _read_bch_push(script, offset, opcode)
            if error is not None:
                return error
            stack.append(value)
            continue
        if opcode in (0x4C, 0x4D, 0x4E):
            width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[opcode]
            if offset + width > len(script):
                return "TRUNCATED_PUSH"
            length = int.from_bytes(script[offset : offset + width], "little")
            offset += width
            value, offset, error = _read_bch_push(script, offset, length)
            if error is not None:
                return error
            stack.append(value)
            continue
        if 0x51 <= opcode <= 0x60:
            stack.append(bytes([opcode - 0x50]))
            continue
        if opcode == 0x69:
            if not stack:
                return "INVALID_STACK_OPERATION"
            if not _vm_truthy(stack.pop()):
                return "VERIFY"
        elif opcode == 0x76:
            if not stack:
                return "INVALID_STACK_OPERATION"
            stack.append(stack[-1])
        elif opcode == 0x87:
            if len(stack) < 2:
                return "INVALID_STACK_OPERATION"
            right, left = stack.pop(), stack.pop()
            stack.append(b"\x01" if left == right else b"")
        elif opcode == 0x88:
            if len(stack) < 2:
                return "INVALID_STACK_OPERATION"
            right, left = stack.pop(), stack.pop()
            if left != right:
                return "EQUALVERIFY"
        elif opcode == 0xA9:
            if not stack:
                return "INVALID_STACK_OPERATION"
            stack.append(_hash160(stack.pop()))
        elif opcode == 0x6A:
            return "OP_RETURN"
        else:
            return "BAD_OPCODE"
    return None


def _read_bch_push(script: bytes, offset: int, length: int) -> tuple[bytes, int, str | None]:
    if length > 520:
        return b"", offset, "PUSH_SIZE"
    end = offset + length
    if end > len(script):
        return b"", offset, "TRUNCATED_PUSH"
    return script[offset:end], end, None


def _vm_truthy(value: bytes) -> bool:
    for index, item in enumerate(value):
        if item != 0:
            return not (index == len(value) - 1 and item == 0x80)
    return False


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


def verify_p2pkh_input(
    transaction: Transaction,
    input_index: int,
    source_value: str,
    source_script_pubkey: str,
) -> bytes:
    """Verify a BCH ForkID ECDSA P2PKH input and return its public-key hash."""
    source_script = bytes.fromhex(source_script_pubkey)
    if len(source_script) != 25 or source_script[:3] != b"\x76\xa9\x14" or source_script[-2:] != b"\x88\xac":
        raise ValueError("source output is not P2PKH")
    if input_index < 0 or input_index >= len(transaction.inputs):
        raise ValueError("invalid input index")
    script = transaction.inputs[input_index].script_sig
    if len(script) < 2:
        raise ValueError("invalid P2PKH scriptSig")
    signature_length = script[0]
    if signature_length < 2 or signature_length > 75 or 1 + signature_length >= len(script):
        raise ValueError("invalid P2PKH scriptSig")
    public_key_length_index = 1 + signature_length
    public_key_length = script[public_key_length_index]
    if public_key_length != 33 or public_key_length_index + 1 + public_key_length != len(script):
        raise ValueError("invalid P2PKH scriptSig")
    signature = script[1:public_key_length_index]
    public_key = script[public_key_length_index + 1 :]
    if signature[-1] != 0x41:
        raise ValueError("unsupported BCH sighash type")
    public_key_hash = _hash160(public_key)
    if public_key_hash != source_script[3:23]:
        raise ValueError("P2PKH public key does not match source output")
    r, s = _parse_der_signature(signature[:-1])
    if not _verify_secp256k1_ecdsa(signing_hash(transaction, input_index, source_value, source_script_pubkey), r, s, public_key):
        raise ValueError("invalid signature")
    return public_key_hash


def verify_p2sh_redeem_script(
    transaction: Transaction, input_index: int, source_script_pubkey: str
) -> None:
    """Check push-only unlocking and the committed P2SH20/P2SH32 redeem script.

    This validates the hash boundary only; it does not execute arbitrary BCH VM.
    """
    if input_index < 0 or input_index >= len(transaction.inputs):
        raise ValueError("invalid input index")
    source = bytes.fromhex(source_script_pubkey)
    is_p2sh20 = len(source) == 23 and source[:2] == b"\xa9\x14" and source[-1:] == b"\x87"
    is_p2sh32 = len(source) == 35 and source[:2] == b"\xaa\x20" and source[-1:] == b"\x87"
    if not is_p2sh20 and not is_p2sh32:
        raise ValueError("source output is not P2SH20 or P2SH32")
    pushes = _parse_push_only(transaction.inputs[input_index].script_sig)
    if not pushes:
        raise ValueError("P2SH unlocking script does not push a redeem script")
    redeem_script = pushes[-1]
    committed = _hash160(redeem_script) if is_p2sh20 else _double_sha256(redeem_script)
    if committed != source[2:-1]:
        raise ValueError("P2SH redeem script commitment mismatch")


def _parse_push_only(script: bytes) -> list[bytes]:
    pushes: list[bytes] = []
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        if opcode == 0:
            pushes.append(b"")
            continue
        if 1 <= opcode <= 75:
            length = opcode
        elif opcode == 0x4C:
            if offset >= len(script):
                raise ValueError("P2SH unlocking script has truncated PUSHDATA1")
            length = script[offset]
            offset += 1
        elif opcode == 0x4D:
            if offset + 2 > len(script):
                raise ValueError("P2SH unlocking script has truncated PUSHDATA2")
            length = int.from_bytes(script[offset : offset + 2], "little")
            offset += 2
        elif opcode == 0x4E:
            if offset + 4 > len(script):
                raise ValueError("P2SH unlocking script has truncated PUSHDATA4")
            length = int.from_bytes(script[offset : offset + 4], "little")
            offset += 4
        else:
            raise ValueError("P2SH unlocking script is not push-only")
        end = offset + length
        if end > len(script):
            raise ValueError("P2SH unlocking script push is truncated")
        pushes.append(script[offset:end])
        offset = end
    return pushes


def _double_sha256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def _parse_der_signature(encoded: bytes) -> tuple[int, int]:
    if len(encoded) < 8 or encoded[0] != 0x30 or encoded[1] + 2 != len(encoded):
        raise ValueError("malformed DER signature")
    offset = 2
    if encoded[offset] != 0x02:
        raise ValueError("malformed DER r")
    r_length = encoded[offset + 1]
    offset += 2
    if r_length == 0 or offset + r_length + 2 > len(encoded):
        raise ValueError("malformed DER r")
    r_bytes = encoded[offset : offset + r_length]
    offset += r_length
    if encoded[offset] != 0x02:
        raise ValueError("malformed DER s")
    s_length = encoded[offset + 1]
    offset += 2
    if s_length == 0 or offset + s_length != len(encoded):
        raise ValueError("malformed DER s")
    s_bytes = encoded[offset : offset + s_length]
    for item in (r_bytes, s_bytes):
        if item[0] & 0x80 or (len(item) > 1 and item[0] == 0 and item[1] < 0x80):
            raise ValueError("non-canonical DER integer")
    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


def _secp_point_add(left: tuple[int, int] | None, right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % _SECP256K1_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, _SECP256K1_P) % _SECP256K1_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _SECP256K1_P) % _SECP256K1_P
    x3 = (slope * slope - x1 - x2) % _SECP256K1_P
    return x3, (slope * (x1 - x3) - y1) % _SECP256K1_P


def _secp_point_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result = None
    base = point
    while scalar:
        if scalar & 1:
            result = _secp_point_add(result, base)
        base = _secp_point_add(base, base)
        scalar >>= 1
    return result


def _decode_compressed_public_key(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid compressed public key")
    x = int.from_bytes(encoded[1:], "big")
    if x >= _SECP256K1_P:
        raise ValueError("invalid compressed public key")
    y = pow((x * x * x + 7) % _SECP256K1_P, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if y * y % _SECP256K1_P != (x * x * x + 7) % _SECP256K1_P:
        raise ValueError("invalid compressed public key")
    if y & 1 != encoded[0] & 1:
        y = _SECP256K1_P - y
    return x, y


def _verify_secp256k1_ecdsa(digest: bytes, r: int, s: int, encoded_public_key: bytes) -> bool:
    if not 0 < r < _SECP256K1_N or not 0 < s < _SECP256K1_N:
        return False
    public_key = _decode_compressed_public_key(encoded_public_key)
    inverse = pow(s, -1, _SECP256K1_N)
    e = int.from_bytes(digest, "big")
    point = _secp_point_add(
        _secp_point_mul(e * inverse % _SECP256K1_N, _SECP256K1_G),
        _secp_point_mul(r * inverse % _SECP256K1_N, public_key),
    )
    return point is not None and point[0] % _SECP256K1_N == r


def _hash160(value: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(value).digest())


def _ripemd160(message: bytes) -> bytes:
    data = bytearray(message)
    bit_length = len(data) * 8
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data.extend(bit_length.to_bytes(8, "little"))
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    r_left = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    r_right = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    s_left = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    s_right = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    k_left = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k_right = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]
    def rol(value: int, shift: int) -> int:
        return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF
    def function(index: int, x: int, y: int, z: int) -> int:
        if index < 16: return x ^ y ^ z
        if index < 32: return (x & y) | (~x & z)
        if index < 48: return (x | ~y) ^ z
        if index < 64: return (x & z) | (y & ~z)
        return x ^ (y | ~z)
    for offset in range(0, len(data), 64):
        words = [int.from_bytes(data[offset + index * 4 : offset + index * 4 + 4], "little") for index in range(16)]
        left = h[:]
        right = h[:]
        for index in range(80):
            value = (rol((left[0] + function(index, left[1], left[2], left[3]) + words[r_left[index]] + k_left[index // 16]) & 0xFFFFFFFF, s_left[index]) + left[4]) & 0xFFFFFFFF
            left = [left[4], value, left[1], rol(left[2], 10), left[3]]
            value = (rol((right[0] + function(79 - index, right[1], right[2], right[3]) + words[r_right[index]] + k_right[index // 16]) & 0xFFFFFFFF, s_right[index]) + right[4]) & 0xFFFFFFFF
            right = [right[4], value, right[1], rol(right[2], 10), right[3]]
        h = [(h[1] + left[2] + right[3]) & 0xFFFFFFFF, (h[2] + left[3] + right[4]) & 0xFFFFFFFF, (h[3] + left[4] + right[0]) & 0xFFFFFFFF, (h[4] + left[0] + right[1]) & 0xFFFFFFFF, (h[0] + left[1] + right[2]) & 0xFFFFFFFF]
    return b"".join(value.to_bytes(4, "little") for value in h)


def verify_native_payment(
    transaction: Transaction,
    source_outputs: list[dict[str, Any]],
    merchant_value: str,
    merchant_script_pubkey: str,
    fee_rate: int = 1,
    dust_threshold: int = 546,
) -> dict[str, str]:
    """Check native BCH value/output policy; VM signatures remain an adapter boundary."""
    if len(source_outputs) != len(transaction.inputs):
        raise ValueError("source output count mismatch")
    if transaction.locktime != 0:
        raise ValueError("non-zero locktime is unsupported")
    merchant_amount = _canonical_uint(merchant_value, "merchant value")
    merchant_script = bytes.fromhex(merchant_script_pubkey)
    input_value = 0
    for source in source_outputs:
        input_value += _canonical_uint(str(source["value"]), "source value")
        if input_value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("input value exceeds u64")
    matches = [
        output
        for output in transaction.outputs
        if output.value == merchant_amount and output.script_pubkey == merchant_script
    ]
    if len(matches) != 1:
        raise ValueError("merchant output must match exactly once")
    output_value = 0
    for output in transaction.outputs:
        if output.script_pubkey[:1] != b"\x6a" and output.value < dust_threshold:
            raise ValueError("transaction output is dust")
        output_value += output.value
    if output_value > input_value:
        raise ValueError("transaction outputs exceed inputs")
    raw = serialize_transaction(transaction)
    fee = input_value - output_value
    if fee < len(raw) * fee_rate:
        raise ValueError("transaction fee is below the required BCH fee rate")
    if any(output.script_pubkey == merchant_script and output not in matches for output in transaction.outputs):
        raise ValueError("duplicate merchant output")
    return {"txid": hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex(), "fee": str(fee), "serializedSize": str(len(raw))}


def verify_cash_token_payment(
    transaction: Transaction,
    source_outputs: list[dict[str, Any]],
    merchant_value: str,
    merchant_script_pubkey: str,
    category: str,
    amount: str,
    merchant_nft: tuple[str, bytes] | None = None,
    fee_rate: int = 1,
    dust_threshold: int = 1000,
) -> dict[str, str]:
    """Check CashToken conservation and the exact token-bearing merchant output."""
    if len(source_outputs) != len(transaction.inputs):
        raise ValueError("source output count mismatch")
    if transaction.locktime != 0:
        raise ValueError("non-zero locktime is unsupported")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", category):
        raise ValueError("CashToken category must be 32-byte hexadecimal")
    expected_category = category.lower()
    expected_amount = _canonical_uint(amount, "CashToken amount")
    merchant_amount = _canonical_uint(merchant_value, "merchant value")
    merchant_script = bytes.fromhex(merchant_script_pubkey)
    input_value = sum(_canonical_uint(str(source["value"]), "source value") for source in source_outputs)
    source_tokens = [source.get("token") for source in source_outputs]
    if any(not isinstance(token, CashToken) for token in source_tokens):
        raise ValueError("CashToken source state is required")
    source_tokens = [token for token in source_tokens if isinstance(token, CashToken)]
    if any(token.category != expected_category for token in source_tokens):
        raise ValueError("CashToken source category mismatch")
    source_amount = sum(token.amount for token in source_tokens)
    source_nfts = sorted((token.nft for token in source_tokens if token.nft is not None), key=repr)
    output_tokens = [output.token for output in transaction.outputs if output.token is not None]
    if any(token.category != expected_category for token in output_tokens):
        raise ValueError("CashToken output category mismatch")
    if sum(token.amount for token in output_tokens) != source_amount:
        raise ValueError("CashToken state is not conserved")
    output_nfts = sorted((token.nft for token in output_tokens if token.nft is not None), key=repr)
    if output_nfts != source_nfts:
        raise ValueError("CashToken NFT state is not conserved")
    merchant_matches = [
        output
        for output in transaction.outputs
        if output.value == merchant_amount
        and output.script_pubkey == merchant_script
        and output.token is not None
        and output.token.category == expected_category
        and output.token.amount == expected_amount
        and output.token.nft == merchant_nft
    ]
    if len(merchant_matches) != 1:
        raise ValueError("merchant output must match exactly once")
    output_value = 0
    for output in transaction.outputs:
        if output.token is not None and output.value < dust_threshold:
            raise ValueError("CashToken output is dust")
        if output.token is None and output.script_pubkey[:1] != b"\x6a" and output.value < 546:
            raise ValueError("transaction output is dust")
        output_value += output.value
    if output_value > input_value:
        raise ValueError("transaction outputs exceed inputs")
    raw = serialize_transaction(transaction)
    fee = input_value - output_value
    if fee < len(raw) * fee_rate:
        raise ValueError("transaction fee is below the required BCH fee rate")
    return {"txid": hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex(), "fee": str(fee), "serializedSize": str(len(raw))}


def _canonical_uint(value: str, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise ValueError(f"{label} must be canonical unsigned units")
    parsed = int(value)
    if parsed > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{label} exceeds u64")
    return parsed
