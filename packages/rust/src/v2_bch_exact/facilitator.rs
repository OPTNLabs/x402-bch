//! Facilitator-side BCH exact verification and settlement.

use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use x402_types::proto;
use x402_types::proto::v2;
use x402_types::scheme::{
    X402SchemeFacilitator, X402SchemeFacilitatorBuilder, X402SchemeFacilitatorError,
};

use crate::address::CashAddr;
use crate::provider::{
    BchChainProvider, BchOutpointStatus, BchProviderError, BchTransactionStatus,
};
use crate::settlement::{BchSettlementClaim, BchSettlementStore, InMemoryBchSettlementStore};
use crate::transaction::{
    BchNft, BchPolicy, BchTransaction, VerifiedPayment, assert_request_hash_commitment,
    is_p2pkh_script, parse_cash_token_nft, payment_target_with_nft, verify_payment,
};
use crate::v2_bch_exact::V2BchExact;
use crate::v2_bch_exact::types::{BchExtra, ExactScheme, SettleRequest, VerifyRequest};

fn requested_nft(
    extra: &BchExtra,
    asset: &str,
    amount: &str,
) -> Result<Option<BchNft>, crate::transaction::TransactionError> {
    let Some(token) = &extra.token else {
        return Ok(None);
    };
    if token.category != asset || token.amount != amount {
        return Err(crate::transaction::TransactionError::PolicyViolation(
            "CashToken request must match the x402 asset and amount".to_string(),
        ));
    }
    parse_cash_token_nft(
        token.nft.as_ref().map(|nft| nft.capability.as_str()),
        token.nft.as_ref().map(|nft| nft.commitment.as_str()),
    )
}

/// Settlement acceptance policy for unconfirmed BCH transactions.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "confirmations", rename_all = "camelCase")]
pub enum BchConfirmationStrategy {
    /// Accept a transaction once the provider reports it in the mempool.
    Mempool,
    /// Accept mempool transactions only while no BCH double-spend proof exists.
    NoDoubleSpendProof,
    /// Require the transaction to be mined with this many confirmations.
    Confirmations(u64),
}

impl Default for BchConfirmationStrategy {
    fn default() -> Self {
        Self::Confirmations(1)
    }
}

/// Apply the pure, provider-independent BCH settlement decision.
pub fn accepts_bch_settlement(
    strategy: BchConfirmationStrategy,
    status: &BchTransactionStatus,
    tip_height: Option<u64>,
    has_double_spend_proof: bool,
) -> bool {
    match strategy {
        BchConfirmationStrategy::Mempool => {
            matches!(
                status,
                BchTransactionStatus::Mempool | BchTransactionStatus::Confirmed { .. }
            )
        }
        BchConfirmationStrategy::NoDoubleSpendProof => {
            matches!(status, BchTransactionStatus::Confirmed { .. })
                || matches!(status, BchTransactionStatus::Mempool) && !has_double_spend_proof
        }
        BchConfirmationStrategy::Confirmations(required) => {
            let BchTransactionStatus::Confirmed { height } = status else {
                return false;
            };
            if required == 0 {
                return false;
            }
            let Some(tip_height) = tip_height else {
                return false;
            };
            tip_height
                .checked_sub(*height)
                .and_then(|depth| depth.checked_add(1))
                .is_some_and(|confirmations| confirmations >= required)
        }
    }
}

/// Normalize provider observation and settlement policy facts into a retry-safe outcome.
pub fn resolve_bch_settlement_outcome(
    candidate_valid: bool,
    provider_observation: &str,
    strategy: BchConfirmationStrategy,
    status: &BchTransactionStatus,
    tip_height: Option<u64>,
    has_double_spend_proof: bool,
) -> &'static str {
    if !candidate_valid
        || provider_observation == "mismatch"
        || provider_observation != "missing" && provider_observation != "match"
        || matches!(status, BchTransactionStatus::Conflicted)
    {
        return "rejected";
    }
    if provider_observation == "missing" {
        return "pending";
    }
    if accepts_bch_settlement(strategy, status, tip_height, has_double_spend_proof) {
        "accepted"
    } else {
        "pending"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchSettlementIntegrationResult {
    pub state: &'static str,
    pub transaction_id: String,
    pub next_action: &'static str,
}

/// Resolve deterministic facilitator orchestration without broadcasting or
/// persisting state. A retry always refers to the same candidate transaction.
pub fn resolve_bch_settlement_integration(
    candidate_txid: &str,
    candidate_valid: bool,
    binding_matches: bool,
    existing_claim: &str,
    provider_observation: &str,
    strategy: BchConfirmationStrategy,
    status: &BchTransactionStatus,
    tip_height: Option<u64>,
    has_double_spend_proof: bool,
    broadcast_attempt: &str,
) -> BchSettlementIntegrationResult {
    let transaction_id = if candidate_valid {
        candidate_txid.to_string()
    } else {
        String::new()
    };
    if !candidate_valid || !binding_matches || provider_observation == "mismatch" {
        return BchSettlementIntegrationResult {
            state: "rejected",
            transaction_id,
            next_action: "reject",
        };
    }
    if existing_claim == "different" {
        return BchSettlementIntegrationResult {
            state: "rejected",
            transaction_id,
            next_action: "conflict",
        };
    }
    let state = resolve_bch_settlement_outcome(
        true,
        provider_observation,
        strategy,
        status,
        tip_height,
        has_double_spend_proof,
    );
    if state != "pending" {
        return BchSettlementIntegrationResult {
            state,
            transaction_id,
            next_action: if state == "accepted" {
                "skip"
            } else {
                "reject"
            },
        };
    }
    if provider_observation == "missing" && existing_claim == "none" && broadcast_attempt == "none"
    {
        return BchSettlementIntegrationResult {
            state,
            transaction_id,
            next_action: "broadcast",
        };
    }
    if provider_observation == "missing" && broadcast_attempt == "lost" {
        return BchSettlementIntegrationResult {
            state,
            transaction_id,
            next_action: "retry",
        };
    }
    BchSettlementIntegrationResult {
        state,
        transaction_id,
        next_action: "retain",
    }
}

/// Derive chain evidence from provider-returned bytes before settlement
/// decisions. A missing observation is not a match and a malformed/mismatched
/// response is explicit mismatch evidence.
pub fn observe_bch_provider_transaction(
    candidate_txid: &str,
    raw_transaction: Option<&[u8]>,
) -> &'static str {
    let Some(raw_transaction) = raw_transaction else {
        return "missing";
    };
    let Ok(candidate_txid) = crate::transaction::TxId::from_hex(candidate_txid) else {
        return "mismatch";
    };
    if BchTransaction::assert_provider_transaction_id(&candidate_txid, raw_transaction).is_ok() {
        "match"
    } else {
        "mismatch"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchProviderSourceOutputResult {
    pub observation: &'static str,
    pub source_output: Option<crate::transaction::SourceOutput>,
}

/// Project one source output only after provider txid reconciliation.
pub fn get_bch_provider_source_output(
    source_txid: &str,
    vout: u32,
    raw_transaction: Option<&[u8]>,
) -> BchProviderSourceOutputResult {
    let observation = observe_bch_provider_transaction(source_txid, raw_transaction);
    if observation != "match" {
        return BchProviderSourceOutputResult {
            observation,
            source_output: None,
        };
    }
    let Some(raw_transaction) = raw_transaction else {
        unreachable!("matched provider observation requires raw transaction bytes");
    };
    let Ok(transaction) = BchTransaction::parse(raw_transaction) else {
        return BchProviderSourceOutputResult {
            observation: "notFound",
            source_output: None,
        };
    };
    let Some(output) = transaction.outputs.get(vout as usize) else {
        return BchProviderSourceOutputResult {
            observation: "notFound",
            source_output: None,
        };
    };
    BchProviderSourceOutputResult {
        observation: "match",
        source_output: Some(crate::transaction::SourceOutput {
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            token: output.token.clone(),
        }),
    }
}

/// Derive the provider observation, then apply the common settlement state
/// machine without broadcasting or persisting state.
pub fn resolve_bch_settlement_from_provider(
    candidate_txid: &str,
    candidate_valid: bool,
    binding_matches: bool,
    existing_claim: &str,
    strategy: BchConfirmationStrategy,
    status: &BchTransactionStatus,
    tip_height: Option<u64>,
    has_double_spend_proof: bool,
    broadcast_attempt: &str,
    raw_transaction: Option<&[u8]>,
) -> BchSettlementIntegrationResult {
    resolve_bch_settlement_integration(
        candidate_txid,
        candidate_valid,
        binding_matches,
        existing_claim,
        observe_bch_provider_transaction(candidate_txid, raw_transaction),
        strategy,
        status,
        tip_height,
        has_double_spend_proof,
        broadcast_attempt,
    )
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct BchFacilitatorConfig {
    pub settlement_strategy: BchConfirmationStrategy,
}

pub struct V2BchExactFacilitator<P> {
    provider: P,
    policy: BchPolicy,
    config: BchFacilitatorConfig,
    settlement_store: Arc<dyn BchSettlementStore>,
}

impl<P> V2BchExactFacilitator<P> {
    pub fn new(provider: P, policy: BchPolicy, config: BchFacilitatorConfig) -> Self {
        Self {
            provider,
            policy,
            config,
            settlement_store: Arc::new(InMemoryBchSettlementStore::default()),
        }
    }

    pub fn with_settlement_store<S>(
        provider: P,
        policy: BchPolicy,
        config: BchFacilitatorConfig,
        settlement_store: Arc<S>,
    ) -> Self
    where
        S: BchSettlementStore + 'static,
    {
        Self {
            provider,
            policy,
            config,
            settlement_store,
        }
    }
}

impl<P> X402SchemeFacilitatorBuilder<P> for V2BchExact
where
    P: BchChainProvider + 'static,
{
    fn build(
        &self,
        provider: P,
        config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        let config = config
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        Ok(Box::new(V2BchExactFacilitator::new(
            provider,
            BchPolicy::default(),
            config,
        )))
    }
}

#[async_trait::async_trait]
impl<P> X402SchemeFacilitator for V2BchExactFacilitator<P>
where
    P: BchChainProvider + Send + Sync,
{
    async fn verify(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, X402SchemeFacilitatorError> {
        let request = VerifyRequest::try_from(request)?;
        let verified = verify_transfer(&self.provider, &request, self.policy).await?;
        Ok(v2::VerifyResponse::valid(verified.payment.payer.to_string()).into())
    }

    async fn settle(
        &self,
        request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, X402SchemeFacilitatorError> {
        let request = SettleRequest::try_from(request)?;
        let raw_transaction = base64::engine::general_purpose::STANDARD
            .decode(&request.payment_payload.payload.transaction)
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
        let candidate_transaction = BchTransaction::parse(&raw_transaction)
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
        let expected_txid = candidate_transaction.txid();
        // A retry may arrive after local settlement state was lost. Prefer the
        // provider's canonical transaction when it has observed this txid;
        // confirmed inputs are expected to be spent and must not be rejected
        // merely because the facilitator restarted.
        if let Some(observed) = self
            .provider
            .transaction(&expected_txid)
            .await
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?
        {
            BchTransaction::assert_provider_transaction_id(&expected_txid, &observed)
                .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
            let observed_transaction = BchTransaction::parse(&observed)
                .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
            let verified = verify_transfer_with_transaction(
                &self.provider,
                &request,
                self.policy,
                observed_transaction,
                false,
            )
            .await?;
            let status = self
                .provider
                .transaction_status(&expected_txid)
                .await
                .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
            if self.settlement_accepted(&expected_txid, status).await? {
                return Ok(v2::SettleResponse::Success {
                    payer: verified.payment.payer.to_string(),
                    transaction: expected_txid.to_string(),
                    network: self.provider.chain_id().to_string(),
                }
                .into());
            }
        }
        let binding = settlement_binding(&request)
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?;
        match self
            .settlement_store
            .claim(&expected_txid.to_string(), &binding)
            .await
        {
            BchSettlementClaim::Conflict => {
                return Err(X402SchemeFacilitatorError::OnchainFailure(
                    "transaction already claimed for another request".to_string(),
                ));
            }
            BchSettlementClaim::Same => {
                let status = self
                    .provider
                    .transaction_status(&expected_txid)
                    .await
                    .map_err(|error| {
                        X402SchemeFacilitatorError::OnchainFailure(error.to_string())
                    })?;
                if !self.settlement_accepted(&expected_txid, status).await? {
                    return Ok(pending_response(&expected_txid, self.provider.chain_id()));
                }
                let verified =
                    verify_transfer_with_spent(&self.provider, &request, self.policy, false)
                        .await?;
                self.settlement_store
                    .mark_accepted(&expected_txid.to_string())
                    .await;
                return Ok(v2::SettleResponse::Success {
                    payer: verified.payment.payer.to_string(),
                    transaction: expected_txid.to_string(),
                    network: self.provider.chain_id().to_string(),
                }
                .into());
            }
            BchSettlementClaim::Acquired => {}
        }
        let verified = match verify_transfer(&self.provider, &request, self.policy).await {
            Ok(verified) => verified,
            Err(error) => {
                self.settlement_store
                    .release(&expected_txid.to_string())
                    .await;
                return Err(error.into());
            }
        };
        let raw_transaction = verified.transaction.serialize();
        let txid = match self.provider.broadcast(&raw_transaction).await {
            Ok(txid) => txid,
            Err(error) => match self.provider.transaction_status(&expected_txid).await {
                Ok(BchTransactionStatus::Mempool | BchTransactionStatus::Confirmed { .. }) => {
                    expected_txid
                }
                Ok(BchTransactionStatus::NotFound) => {
                    self.settlement_store
                        .release(&expected_txid.to_string())
                        .await;
                    return Err(X402SchemeFacilitatorError::OnchainFailure(
                        error.to_string(),
                    ));
                }
                Ok(BchTransactionStatus::Unknown | BchTransactionStatus::Conflicted) | Err(_) => {
                    return Err(X402SchemeFacilitatorError::OnchainFailure(format!(
                        "broadcast outcome unknown: {error}"
                    )));
                }
            },
        };
        if txid != expected_txid {
            self.settlement_store
                .release(&expected_txid.to_string())
                .await;
            return Err(X402SchemeFacilitatorError::OnchainFailure(
                "provider returned a transaction ID different from the signed transaction"
                    .to_string(),
            ));
        }

        let status = match self
            .provider
            .transaction_status(&txid)
            .await
            .map_err(|error| X402SchemeFacilitatorError::OnchainFailure(error.to_string()))?
        {
            // The node accepted the broadcast; Fulcrum indexes its mempool a moment later.
            BchTransactionStatus::NotFound => BchTransactionStatus::Mempool,
            status => status,
        };
        if self.settlement_accepted(&txid, status).await? {
            self.settlement_store.mark_accepted(&txid.to_string()).await;
            return Ok(v2::SettleResponse::Success {
                payer: verified.payment.payer.to_string(),
                transaction: txid.to_string(),
                network: self.provider.chain_id().to_string(),
            }
            .into());
        }
        Ok(pending_response(&txid, self.provider.chain_id()))
    }

    async fn supported(&self) -> Result<proto::SupportedResponse, X402SchemeFacilitatorError> {
        let chain_id = self.provider.chain_id();
        let mut signers = HashMap::new();
        signers.insert(chain_id.clone(), self.provider.signer_addresses());
        Ok(proto::SupportedResponse {
            kinds: vec![proto::SupportedPaymentKind {
                x402_version: v2::X402Version2.into(),
                scheme: ExactScheme.to_string(),
                network: chain_id.to_string(),
                extra: None,
            }],
            extensions: Vec::new(),
            signers,
        })
    }
}

fn settlement_binding(request: &SettleRequest) -> Result<String, serde_json::Error> {
    let value = serde_json::json!({
        "accepted": &request.payment_requirements,
        "resource": &request.payment_payload.resource,
    });
    Ok(canonical_json(&value))
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => serde_json::to_string(value).expect("string encodes"),
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("object key encodes"),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

impl<P> V2BchExactFacilitator<P>
where
    P: BchChainProvider + Send + Sync,
{
    async fn settlement_accepted(
        &self,
        txid: &crate::transaction::TxId,
        status: BchTransactionStatus,
    ) -> Result<bool, X402SchemeFacilitatorError> {
        match self.config.settlement_strategy {
            BchConfirmationStrategy::Mempool => Ok(accepts_bch_settlement(
                self.config.settlement_strategy,
                &status,
                None,
                false,
            )),
            BchConfirmationStrategy::NoDoubleSpendProof => match status {
                BchTransactionStatus::Confirmed { .. } => Ok(true),
                BchTransactionStatus::Mempool => {
                    let has_proof =
                        self.provider
                            .has_double_spend_proof(txid)
                            .await
                            .map_err(|error| {
                                X402SchemeFacilitatorError::OnchainFailure(error.to_string())
                            })?;
                    Ok(accepts_bch_settlement(
                        self.config.settlement_strategy,
                        &BchTransactionStatus::Mempool,
                        None,
                        has_proof,
                    ))
                }
                _ => Ok(false),
            },
            BchConfirmationStrategy::Confirmations(_) => {
                let tip = match status {
                    BchTransactionStatus::Confirmed { .. } => {
                        Some(self.provider.tip_height().await.map_err(|error| {
                            X402SchemeFacilitatorError::OnchainFailure(error.to_string())
                        })?)
                    }
                    _ => None,
                };
                Ok(accepts_bch_settlement(
                    self.config.settlement_strategy,
                    &status,
                    tip,
                    false,
                ))
            }
        }
    }
}

pub struct VerifiedBchPayment {
    pub transaction: BchTransaction,
    pub payment: VerifiedPayment,
}

pub async fn verify_transfer<P>(
    provider: &P,
    request: &VerifyRequest,
    policy: BchPolicy,
) -> Result<VerifiedBchPayment, proto::PaymentVerificationError>
where
    P: BchChainProvider + Send + Sync,
{
    verify_transfer_with_spent(provider, request, policy, true).await
}

async fn verify_transfer_with_spent<P>(
    provider: &P,
    request: &VerifyRequest,
    policy: BchPolicy,
    require_unspent: bool,
) -> Result<VerifiedBchPayment, proto::PaymentVerificationError>
where
    P: BchChainProvider + Send + Sync,
{
    let payload = &request.payment_payload;
    let requirements = &request.payment_requirements;
    if &payload.accepted != requirements {
        return Err(proto::PaymentVerificationError::AcceptedRequirementsMismatch);
    }
    if requirements.scheme.to_string() != "exact" {
        return Err(proto::PaymentVerificationError::UnsupportedScheme);
    }
    if requirements.network != provider.chain_id() {
        return Err(proto::PaymentVerificationError::UnsupportedChain);
    }
    if requirements.extra.payment_flow != "upfront"
        || !((requirements.asset == "BCH" && requirements.extra.asset_transfer_method == "native")
            || (requirements.asset != "BCH"
                && requirements.extra.asset_transfer_method == "cashtoken"))
    {
        return Err(proto::PaymentVerificationError::InvalidFormat(
            "BCH exact requires native or CashToken upfront payment flow".to_string(),
        ));
    }
    let network = crate::BchChainReference::try_from(requirements.network.clone())
        .map_err(|_| proto::PaymentVerificationError::UnsupportedChain)?;
    let pay_to = CashAddr::decode_script(&requirements.pay_to, network)
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    let merchant_script = pay_to.locking_script();
    let target = payment_target_with_nft(
        &requirements.asset,
        &requirements.amount,
        &requirements.extra.asset_transfer_method,
        requirements.extra.token_output_value.as_deref(),
        requested_nft(
            &requirements.extra,
            &requirements.asset,
            &requirements.amount,
        )
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?,
        &merchant_script,
        policy,
    )
    .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    if matches!(
        &target,
        crate::transaction::BchPaymentTarget::CashToken { .. }
    ) && !pay_to.token_support
    {
        return Err(proto::PaymentVerificationError::InvalidFormat(
            "CashToken payments require a token-support merchant CashAddr".to_string(),
        ));
    }
    let raw_transaction = base64::engine::general_purpose::STANDARD
        .decode(&payload.payload.transaction)
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    let transaction = BchTransaction::parse(&raw_transaction)
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    verify_transfer_with_transaction(provider, request, policy, transaction, require_unspent).await
}

async fn verify_transfer_with_transaction<P>(
    provider: &P,
    request: &VerifyRequest,
    policy: BchPolicy,
    transaction: BchTransaction,
    require_unspent: bool,
) -> Result<VerifiedBchPayment, proto::PaymentVerificationError>
where
    P: BchChainProvider + Send + Sync,
{
    let requirements = &request.payment_requirements;
    if &request.payment_payload.accepted != requirements {
        return Err(proto::PaymentVerificationError::AcceptedRequirementsMismatch);
    }
    if requirements.scheme.to_string() != "exact" {
        return Err(proto::PaymentVerificationError::UnsupportedScheme);
    }
    if requirements.network != provider.chain_id() {
        return Err(proto::PaymentVerificationError::UnsupportedChain);
    }
    if requirements.extra.payment_flow != "upfront"
        || !((requirements.asset == "BCH" && requirements.extra.asset_transfer_method == "native")
            || (requirements.asset != "BCH"
                && requirements.extra.asset_transfer_method == "cashtoken"))
    {
        return Err(proto::PaymentVerificationError::InvalidFormat(
            "BCH exact requires native or CashToken upfront payment flow".to_string(),
        ));
    }
    let network = crate::BchChainReference::try_from(requirements.network.clone())
        .map_err(|_| proto::PaymentVerificationError::UnsupportedChain)?;
    let pay_to = CashAddr::decode_script(&requirements.pay_to, network)
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    let merchant_script = pay_to.locking_script();
    let target = payment_target_with_nft(
        &requirements.asset,
        &requirements.amount,
        &requirements.extra.asset_transfer_method,
        requirements.extra.token_output_value.as_deref(),
        requested_nft(
            &requirements.extra,
            &requirements.asset,
            &requirements.amount,
        )
        .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?,
        &merchant_script,
        policy,
    )
    .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    if let Some(request_hash) = requirements.extra.request_hash.as_deref() {
        assert_request_hash_commitment(&transaction, request_hash)
            .map_err(|error| proto::PaymentVerificationError::InvalidFormat(error.to_string()))?;
    }
    let mut source_outputs = Vec::with_capacity(transaction.inputs.len());
    for input in &transaction.inputs {
        let source_output = provider
            .source_output(&input.outpoint)
            .await
            .map_err(provider_error)?;
        if require_unspent
            && provider
                .outpoint_status(&input.outpoint, &source_output)
                .await
                .map_err(provider_error)?
                != BchOutpointStatus::Unspent
        {
            return Err(proto::PaymentVerificationError::TransactionSimulation(
                "source output is not unspent".to_string(),
            ));
        }
        source_outputs.push(source_output);
    }
    let payment = verify_payment(
        &transaction,
        &source_outputs,
        network,
        &merchant_script,
        &target,
        policy,
    )
    .map_err(|error| proto::PaymentVerificationError::TransactionSimulation(error.to_string()))?;
    // A configured node runs the scripts of non-P2PKH inputs now; otherwise
    // the network runs them at broadcast. The Rust SDK does not yet embed a
    // BCH VM, so callers should require node-backed validation for contracts.
    if require_unspent
        && source_outputs
            .iter()
            .any(|source| !is_p2pkh_script(&source.script_pubkey))
        && let Some(Err(reason)) = provider.test_mempool_accept(&transaction.serialize()).await
    {
        return Err(proto::PaymentVerificationError::TransactionSimulation(
            format!("BCH node rejected the transaction: {reason}"),
        ));
    }
    Ok(VerifiedBchPayment {
        transaction,
        payment,
    })
}

fn pending_response(
    txid: &crate::transaction::TxId,
    network: impl ToString,
) -> proto::SettleResponse {
    // x402-types 2.0.2's typed error variant cannot carry `transaction`, so
    // construct the wire response explicitly to preserve x402 retry data.
    proto::SettleResponse(serde_json::json!({
        "success": false,
        "errorReason": "settlement_pending",
        "transaction": txid.to_string(),
        "network": network.to_string(),
    }))
}

fn provider_error(error: BchProviderError) -> proto::PaymentVerificationError {
    match error {
        BchProviderError::NotFound => proto::PaymentVerificationError::InsufficientFunds,
        other => proto::PaymentVerificationError::TransactionSimulation(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BchConfirmationStrategy, accepts_bch_settlement, canonical_json,
        get_bch_provider_source_output, observe_bch_provider_transaction,
        resolve_bch_settlement_from_provider, resolve_bch_settlement_integration,
        resolve_bch_settlement_outcome,
    };
    use crate::provider::BchTransactionStatus;
    use std::collections::HashMap;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementFixture {
        cases: Vec<SettlementCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementCase {
        id: String,
        strategy: String,
        status: String,
        confirmations: Option<u64>,
        height: Option<u64>,
        tip_height: Option<u64>,
        double_spend_proof: Option<bool>,
        expected_accepted: bool,
    }

    #[test]
    fn matches_the_shared_settlement_policy_fixture() {
        let fixture: SettlementFixture = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/settlement-policy.json"
        ))
        .expect("valid settlement policy fixture");
        assert_eq!(fixture.cases.len(), 13);
        for case in fixture.cases {
            let strategy = match case.strategy.as_str() {
                "mempool" => BchConfirmationStrategy::Mempool,
                "noDoubleSpendProof" => BchConfirmationStrategy::NoDoubleSpendProof,
                "confirmations" => BchConfirmationStrategy::Confirmations(
                    case.confirmations.expect("confirmation count"),
                ),
                other => panic!("{}: unknown strategy {other}", case.id),
            };
            let status = match case.status.as_str() {
                "notFound" => BchTransactionStatus::NotFound,
                "mempool" => BchTransactionStatus::Mempool,
                "confirmed" => BchTransactionStatus::Confirmed {
                    height: case.height.expect("confirmed height"),
                },
                "unknown" => BchTransactionStatus::Unknown,
                "conflicted" => BchTransactionStatus::Conflicted,
                other => panic!("{}: unknown status {other}", case.id),
            };
            assert_eq!(
                accepts_bch_settlement(
                    strategy,
                    &status,
                    case.tip_height,
                    case.double_spend_proof.unwrap_or(false),
                ),
                case.expected_accepted,
                "{}",
                case.id
            );
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementOutcomeFixture {
        cases: Vec<SettlementOutcomeCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementOutcomeCase {
        candidate_valid: bool,
        provider_observation: String,
        strategy: String,
        status: String,
        confirmations: Option<u64>,
        height: Option<u64>,
        tip_height: Option<u64>,
        double_spend_proof: Option<bool>,
        expected_outcome: String,
    }

    #[test]
    fn matches_the_shared_settlement_outcome_fixture() {
        let fixture: SettlementOutcomeFixture = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/settlement-outcome.json"
        ))
        .expect("valid settlement outcome fixture");
        assert_eq!(fixture.cases.len(), 8);
        for case in fixture.cases {
            let strategy = match case.strategy.as_str() {
                "mempool" => BchConfirmationStrategy::Mempool,
                "noDoubleSpendProof" => BchConfirmationStrategy::NoDoubleSpendProof,
                "confirmations" => BchConfirmationStrategy::Confirmations(
                    case.confirmations.expect("confirmation count"),
                ),
                other => panic!("unknown strategy {other}"),
            };
            let status = match case.status.as_str() {
                "notFound" => BchTransactionStatus::NotFound,
                "mempool" => BchTransactionStatus::Mempool,
                "confirmed" => BchTransactionStatus::Confirmed {
                    height: case.height.expect("confirmed height"),
                },
                "unknown" => BchTransactionStatus::Unknown,
                "conflicted" => BchTransactionStatus::Conflicted,
                other => panic!("unknown status {other}"),
            };
            assert_eq!(
                resolve_bch_settlement_outcome(
                    case.candidate_valid,
                    &case.provider_observation,
                    strategy,
                    &status,
                    case.tip_height,
                    case.double_spend_proof.unwrap_or(false),
                ),
                case.expected_outcome
            );
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementIntegrationFixture {
        cases: Vec<SettlementIntegrationCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementIntegrationCase {
        id: String,
        candidate_txid: String,
        candidate_valid: bool,
        binding_matches: bool,
        existing_claim: String,
        provider_observation: String,
        strategy: String,
        status: String,
        confirmations: Option<u64>,
        height: Option<u64>,
        tip_height: Option<u64>,
        broadcast_attempt: String,
        expected_state: String,
        expected_transaction_id: String,
        expected_action: String,
    }

    #[test]
    fn matches_the_shared_settlement_integration_fixture() {
        let fixture: SettlementIntegrationFixture = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/settlement-integration.json"
        ))
        .expect("valid settlement integration fixture");
        assert_eq!(fixture.cases.len(), 11);
        for case in fixture.cases {
            let strategy = match case.strategy.as_str() {
                "mempool" => BchConfirmationStrategy::Mempool,
                "noDoubleSpendProof" => BchConfirmationStrategy::NoDoubleSpendProof,
                "confirmations" => BchConfirmationStrategy::Confirmations(
                    case.confirmations.expect("confirmation count"),
                ),
                other => panic!("{}: unknown strategy {other}", case.id),
            };
            let status = match case.status.as_str() {
                "notFound" => BchTransactionStatus::NotFound,
                "mempool" => BchTransactionStatus::Mempool,
                "confirmed" => BchTransactionStatus::Confirmed {
                    height: case.height.expect("confirmed height"),
                },
                "unknown" => BchTransactionStatus::Unknown,
                "conflicted" => BchTransactionStatus::Conflicted,
                other => panic!("{}: unknown status {other}", case.id),
            };
            let result = resolve_bch_settlement_integration(
                &case.candidate_txid,
                case.candidate_valid,
                case.binding_matches,
                &case.existing_claim,
                &case.provider_observation,
                strategy,
                &status,
                case.tip_height,
                false,
                &case.broadcast_attempt,
            );
            assert_eq!(result.state, case.expected_state, "{}", case.id);
            assert_eq!(
                result.transaction_id, case.expected_transaction_id,
                "{}",
                case.id
            );
            assert_eq!(result.next_action, case.expected_action, "{}", case.id);
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderObservationFixture {
        cases: Vec<ProviderObservationCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderObservationCase {
        id: String,
        raw_transaction: Option<String>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementProviderFixture {
        cases: Vec<SettlementProviderCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SettlementProviderCase {
        id: String,
        provider_case: String,
        candidate_txid: String,
        candidate_valid: bool,
        binding_matches: bool,
        existing_claim: String,
        strategy: String,
        status: String,
        confirmations: Option<u64>,
        height: Option<u64>,
        tip_height: Option<u64>,
        broadcast_attempt: String,
        expected_observation: String,
        expected_state: String,
        expected_transaction_id: String,
        expected_action: String,
    }

    #[test]
    fn matches_the_shared_provider_settlement_fixture() {
        let observations: ProviderObservationFixture = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/provider-observation.json"
        ))
        .expect("valid provider observation fixture");
        let provider_bytes: HashMap<String, Option<Vec<u8>>> = observations
            .cases
            .into_iter()
            .map(|case| {
                (
                    case.id,
                    case.raw_transaction
                        .map(|raw| hex::decode(raw).expect("valid provider bytes")),
                )
            })
            .collect();
        let fixture: SettlementProviderFixture = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/settlement-provider.json"
        ))
        .expect("valid settlement provider fixture");
        assert_eq!(fixture.cases.len(), 7);
        for case in fixture.cases {
            let raw = provider_bytes
                .get(&case.provider_case)
                .expect("provider case")
                .as_ref()
                .map(Vec::as_slice);
            assert_eq!(
                observe_bch_provider_transaction(&case.candidate_txid, raw),
                case.expected_observation,
                "{}",
                case.id
            );
            let strategy = match case.strategy.as_str() {
                "mempool" => BchConfirmationStrategy::Mempool,
                "noDoubleSpendProof" => BchConfirmationStrategy::NoDoubleSpendProof,
                "confirmations" => BchConfirmationStrategy::Confirmations(
                    case.confirmations.expect("confirmation count"),
                ),
                other => panic!("{}: unknown strategy {other}", case.id),
            };
            let status = match case.status.as_str() {
                "notFound" => BchTransactionStatus::NotFound,
                "mempool" => BchTransactionStatus::Mempool,
                "confirmed" => BchTransactionStatus::Confirmed {
                    height: case.height.expect("confirmed height"),
                },
                "unknown" => BchTransactionStatus::Unknown,
                "conflicted" => BchTransactionStatus::Conflicted,
                other => panic!("{}: unknown status {other}", case.id),
            };
            let result = resolve_bch_settlement_from_provider(
                &case.candidate_txid,
                case.candidate_valid,
                case.binding_matches,
                &case.existing_claim,
                strategy,
                &status,
                case.tip_height,
                false,
                &case.broadcast_attempt,
                raw,
            );
            assert_eq!(result.state, case.expected_state, "{}", case.id);
            assert_eq!(
                result.transaction_id, case.expected_transaction_id,
                "{}",
                case.id
            );
            assert_eq!(result.next_action, case.expected_action, "{}", case.id);
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderSourceOutputFixture {
        cases: Vec<ProviderSourceOutputCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderSourceOutputCase {
        id: String,
        provider_case: String,
        source_txid: String,
        vout: u32,
        expected_observation: String,
        expected_value: Option<String>,
        expected_script_pub_key: Option<String>,
    }

    #[test]
    fn matches_the_shared_provider_source_output_fixture() {
        let observations: ProviderObservationFixture = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/provider-observation.json"
        ))
        .expect("valid provider observation fixture");
        let provider_bytes: HashMap<String, Option<Vec<u8>>> = observations
            .cases
            .into_iter()
            .map(|case| {
                (
                    case.id,
                    case.raw_transaction
                        .map(|raw| hex::decode(raw).expect("valid provider bytes")),
                )
            })
            .collect();
        let fixture: ProviderSourceOutputFixture = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/provider-source-output.json"
        ))
        .expect("valid provider source-output fixture");
        assert_eq!(fixture.cases.len(), 6);
        for case in fixture.cases {
            let raw = provider_bytes
                .get(&case.provider_case)
                .expect("provider case")
                .as_ref()
                .map(Vec::as_slice);
            let result = get_bch_provider_source_output(&case.source_txid, case.vout, raw);
            assert_eq!(result.observation, case.expected_observation, "{}", case.id);
            match (
                case.expected_value,
                case.expected_script_pub_key,
                result.source_output,
            ) {
                (Some(expected_value), Some(expected_script), Some(output)) => {
                    assert_eq!(output.value.to_string(), expected_value, "{}", case.id);
                    assert_eq!(
                        hex::encode(output.script_pubkey),
                        expected_script,
                        "{}",
                        case.id
                    );
                }
                (None, None, None) => {}
                _ => panic!("{}: source output mismatch", case.id),
            }
        }
    }

    #[test]
    fn canonicalizes_settlement_binding_fields_like_typescript() {
        let value = serde_json::json!({
            "resource": null,
            "accepted": {
                "scheme": "exact",
                "network": "bch:bitcoincash",
                "asset": "BCH",
                "amount": "1000",
                "payTo": "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "paymentFlow": "upfront",
                    "assetTransferMethod": "native"
                }
            }
        });

        assert_eq!(
            canonical_json(&value),
            "{\"accepted\":{\"amount\":\"1000\",\"asset\":\"BCH\",\"extra\":{\"assetTransferMethod\":\"native\",\"paymentFlow\":\"upfront\"},\"maxTimeoutSeconds\":300,\"network\":\"bch:bitcoincash\",\"payTo\":\"bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue\",\"scheme\":\"exact\"},\"resource\":null}"
        );
    }
}
