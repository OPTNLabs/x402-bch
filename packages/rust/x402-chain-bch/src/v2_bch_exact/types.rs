use serde::{Deserialize, Serialize};
use base64::Engine;
use sha2::{Digest, Sha256};
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

/// Validate the shared wallet-agnostic x402 BCH requirements contract.
pub fn validate_requirements(requirements: &PaymentRequirements) -> Result<(), String> {
    let value = serde_json::to_value(requirements).map_err(|error| error.to_string())?;
    if value["scheme"] != "exact" || (!value["x402Version"].is_null() && value["x402Version"] != 2) {
        return Err("unsupported x402 BCH requirements".to_string());
    }
    if value["network"] != "bch:bitcoincash" && value["network"] != "bch:bchtest" {
        return Err("unsupported BCH network".to_string());
    }
    let amount = value["amount"].as_str().ok_or("amount must be a decimal string")?;
    if amount.is_empty() || !amount.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("amount must be an unsigned decimal string".to_string());
    }
    if value["asset"].as_str().unwrap_or_default().is_empty()
        || value["payTo"].as_str().unwrap_or_default().is_empty()
    {
        return Err("asset and payTo are required".to_string());
    }
    if value["extra"]["paymentFlow"] != "upfront" {
        return Err("BCH exact requires upfront payment".to_string());
    }
    if let Some(request_hash) = value["extra"]["requestHash"].as_str() {
        if request_hash.len() != 64 || !request_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("requestHash must be 32-byte hexadecimal".to_string());
        }
    }
    Ok(())
}

/// Validate the x402 payment envelope and bind its accepted offer to the expected offer.
pub fn validate_payment_payload(
    payload: &PaymentPayload,
    expected: &PaymentRequirements,
) -> Result<(), String> {
    validate_requirements(expected)?;
    let value = serde_json::to_value(payload).map_err(|error| error.to_string())?;
    let expected_value = serde_json::to_value(expected).map_err(|error| error.to_string())?;
    if value["x402Version"] != 2 {
        return Err("unsupported x402 payment payload version".to_string());
    }
    for field in ["scheme", "network", "asset", "amount", "payTo"] {
        if value["accepted"][field] != expected_value[field] {
            return Err(format!("accepted requirements mismatch: {field}"));
        }
    }
    let transaction = value["payload"]["transaction"].as_str().ok_or("transaction is required")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(transaction)
        .map_err(|error| error.to_string())?;
    if decoded.is_empty() { return Err("transaction must not be empty".to_string()); }
    Ok(())
}

/// SHA-256 of the canonical request bytes supplied by the server.
pub fn request_hash(canonical_request: &str) -> String {
    hex::encode(Sha256::digest(canonical_request.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> PaymentRequirements {
        serde_json::from_value(serde_json::json!({
            "scheme": "exact",
            "network": "bch:bchtest",
            "amount": "1000",
            "asset": "BCH",
            "payTo": "bchtest:merchant",
            "maxTimeoutSeconds": 300,
            "extra": {"assetTransferMethod": "native", "paymentFlow": "upfront"}
        })).unwrap()
    }

    #[test]
    fn shared_protocol_core_validates_actual_v2_payload_shape() {
        let expected = requirements();
        let payload: PaymentPayload = serde_json::from_value(serde_json::json!({
            "x402Version": 2,
            "accepted": serde_json::to_value(&expected).unwrap(),
            "payload": {"transaction": "AQID"}
        })).unwrap();
        validate_requirements(&expected).unwrap();
        validate_payment_payload(&payload, &expected).unwrap();
        assert_eq!(request_hash("{\"url\":\"https://example.test/resource\"}"), "1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675");
    }
}
