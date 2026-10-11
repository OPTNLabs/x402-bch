use serde::{Deserialize, Serialize};
use x402_types::lit_str;
use x402_types::proto::v2;

lit_str!(ExactScheme, "exact");

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BchTransactionNetwork {
    Mainnet,
    Chipnet,
}

/// The payment a wallet must build. It has the same shape as
/// `BchTransactionRequest` in the TypeScript package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BchTransactionRequest {
    pub network: BchTransactionNetwork,
    /// Merchant destination. The wallet may use another address for change.
    pub recipient: BchRecipient,
    /// Satoshis on the merchant output. CashToken requests include the quoted
    /// value, or the size-aware default when the price omitted it.
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<BchTokenRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BchRecipient {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BchExtra {
    pub asset_transfer_method: String,
    pub payment_flow: String,
    /// Satoshis on the CashToken merchant output.
    ///
    /// The x402 wire name is `value`, matching the TypeScript package. A
    /// message that still uses `tokenOutputValue` is accepted.
    #[serde(
        default,
        rename = "value",
        alias = "tokenOutputValue",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_output_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<BchTokenRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BchTokenRequest {
    pub category: String,
    pub amount: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nft: Option<BchNftRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BchNftRequest {
    pub capability: String,
    pub commitment: String,
}

impl Default for BchExtra {
    fn default() -> Self {
        Self {
            asset_transfer_method: "native".to_string(),
            payment_flow: "upfront".to_string(),
            token_output_value: None,
            token: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExactBchPayload {
    pub transaction: String,
}

pub type PaymentRequirements = v2::PaymentRequirements<ExactScheme, String, String, BchExtra>;
pub type PaymentPayload<TRequirements = PaymentRequirements> =
    v2::PaymentPayload<TRequirements, ExactBchPayload>;
pub type VerifyRequest = v2::VerifyRequest<PaymentPayload, PaymentRequirements>;
pub type SettleRequest = VerifyRequest;
