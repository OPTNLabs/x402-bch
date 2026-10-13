"""Deterministic BCH settlement policy and provider-fact projection."""

import base64
import re
from typing import Any
from .transaction import parse_transaction, transaction_id

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
