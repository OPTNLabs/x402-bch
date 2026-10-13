"""BCH signature, P2SH, and payment policy verification."""

import hashlib
import re
from typing import Any
from .models import CashToken, Transaction
from .crypto import _double_sha256, _hash160, _parse_der_signature, _verify_secp256k1_ecdsa
from .transaction import _canonical_uint, serialize_transaction, signing_hash
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
