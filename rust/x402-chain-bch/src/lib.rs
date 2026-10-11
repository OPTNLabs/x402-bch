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
pub mod provider;
pub mod settlement;
pub mod transaction;
pub mod v2_bch_exact;

#[cfg(test)]
mod regression;

pub use chain::{BCH_NAMESPACE, BchChainReference, BchChainReferenceFormatError};
#[cfg(not(target_arch = "wasm32"))]
pub use provider::FulcrumTcpTransport;
#[cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
pub use provider::FulcrumWebSocketTransport;
pub use provider::{
    BchChainProvider, BchNodeRpc, BchOutpointStatus, BchProviderError, BchTransactionStatus,
    BchUtxo, FailoverFulcrumTransport, FulcrumProvider, FulcrumTransport,
};
#[cfg(target_arch = "wasm32")]
mod wasm;
pub use settlement::{BchSettlementClaim, BchSettlementStore, InMemoryBchSettlementStore};
pub use transaction::{
    BCH_SIGHASH_ALL_FORKID, BchNft, BchPaymentTarget, BchPolicy, BchToken, BchTokenCapability,
    BchTransaction, OutPoint, SourceOutput, TxId,
};
pub use v2_bch_exact::{BchExtra, ExactBchPayload, V2BchExact, V2BchExactClient};
#[cfg(target_arch = "wasm32")]
pub use wasm::{BchBrowserClient, BchBrowserWalletClient, JsFulcrumTransport};
