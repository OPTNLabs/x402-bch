"""Compatibility facade for the modular x402-BCH protocol implementation."""

from .models import CashToken, Transaction, TransactionInput, TransactionOutput
from .protocol import (
    build_cash_token_requirements,
    build_native_requirements,
    request_hash,
    validate_payment_payload,
    validate_requirements,
)
from .transaction import (
    assert_request_hash_commitment,
    get_request_hash_commitment,
    parse_transaction,
    request_hash_script,
    serialize_transaction,
    signing_hash,
    transaction_id,
    validate_transaction_envelope,
)
from .crypto import (
    _decode_compressed_public_key,
    _double_sha256,
    _hash160,
    _parse_der_signature,
    _secp_point_add,
    _secp_point_mul,
    _verify_secp256k1_ecdsa,
)
from .payment import (
    verify_cash_token_payment,
    verify_native_payment,
    verify_p2pkh_input,
    verify_p2sh_redeem_script,
)
from .settlement import (
    accepts_bch_settlement,
    get_bch_provider_source_output,
    observe_bch_provider_transaction,
    provider_transaction_matches,
    resolve_bch_settlement_from_provider,
    resolve_bch_settlement_integration,
    resolve_bch_settlement_outcome,
)
from .vm import evaluate_bch_vm

__all__ = [name for name in globals() if not name.startswith("_")]
