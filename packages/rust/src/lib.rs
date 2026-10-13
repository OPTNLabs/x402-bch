//! Bitcoin Cash network identity support for x402.
//!
//! BCH uses the `bch` namespace with the CashAddr network prefixes used by
//! BCH integrations: `bch:bitcoincash` for mainnet and `bch:bchtest` for
//! chipnet.
//!
//! This crate deliberately does not derive the network identity from a BCH
//! genesis hash or Bitcoin fork height. Those identifiers are useful for
//! chain-internal tooling, but they are not the network vocabulary used by BCH
//! WalletConnect integrations and would make x402 payments needlessly
//! incompatible with BCH applications.

pub mod address;
pub mod chain;
pub mod covenant;
pub mod diagnostics;
pub mod http;
pub mod mocknet;
pub mod provider;
pub mod script_vm;
pub mod settlement;
pub mod transaction;
pub mod v2_bch_exact;

#[cfg(test)]
mod regression;

pub use chain::{BCH_NAMESPACE, BchChainReference, BchChainReferenceFormatError};
pub use covenant::{
    CovenantErrorCode, CovenantNftState, CovenantProfile, CovenantState, CovenantTokenState,
    CovenantTransition, SuccessorPolicy, profile_hashes_match, validate_covenant_transition,
};
pub use mocknet::{MocknetProvider, MocknetTransaction};
#[cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
pub use provider::FulcrumWebSocketTransport;
pub use provider::{
    BchChainProvider, BchNodeRpc, BchOutpointStatus, BchProviderError, BchTransactionStatus,
    BchUtxo, FailoverFulcrumTransport, FulcrumProvider, FulcrumTransport,
};
#[cfg(not(target_arch = "wasm32"))]
pub use provider::{BchnHttpRpc, FulcrumTcpTransport};
#[cfg(target_arch = "wasm32")]
mod wasm;
pub use script_vm::{BchVmResult, evaluate_bch_vm};
pub use settlement::{BchSettlementClaim, BchSettlementStore, InMemoryBchSettlementStore};
pub use transaction::{
    BCH_SIGHASH_ALL_FORKID, BchNft, BchPaymentTarget, BchPolicy, BchToken, BchTokenCapability,
    BchTransaction, OutPoint, SourceOutput, TxId, assert_request_hash_commitment,
    get_request_hash_commitment, request_hash_script,
};
pub use v2_bch_exact::{
    BchExtra, BchProviderSourceOutputResult, ExactBchPayload, V2BchExact, V2BchExactClient,
    accepts_bch_settlement, get_bch_provider_source_output, observe_bch_provider_transaction,
    resolve_bch_settlement_from_provider, resolve_bch_settlement_integration,
    resolve_bch_settlement_outcome,
};
pub use v2_bch_exact::{request_hash, validate_payment_payload, validate_requirements};
#[cfg(target_arch = "wasm32")]
pub use wasm::{BchBrowserClient, BchBrowserWalletClient, JsFulcrumTransport};
