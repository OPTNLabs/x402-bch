//! Stable, log-safe diagnostics for protocol and provider boundaries.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DIAGNOSTIC_REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BchDiagnostic {
    pub stage: String,
    pub code: String,
    pub message: String,
    pub context: BTreeMap<String, String>,
}

pub fn create_bch_diagnostic(
    stage: impl Into<String>,
    code: impl Into<String>,
    message: impl Into<String>,
    context: BTreeMap<String, String>,
) -> BchDiagnostic {
    let context = context
        .into_iter()
        .map(|(key, value)| {
            let safe = match key.to_ascii_lowercase().as_str() {
                "mnemonic" | "privatekey" | "seed" | "secret" | "authorization" | "transaction"
                | "rawtransaction" | "signedtransaction" => DIAGNOSTIC_REDACTED.to_string(),
                _ => value,
            };
            (key, safe)
        })
        .collect();
    BchDiagnostic {
        stage: stage.into(),
        code: code.into(),
        message: message.into(),
        context,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_context() {
        let mut context = BTreeMap::new();
        context.insert("txid".to_string(), "a".repeat(64));
        context.insert("rawTransaction".to_string(), "deadbeef".to_string());
        let diagnostic = create_bch_diagnostic(
            "provider",
            "transaction_identity_mismatch",
            "provider mismatch",
            context,
        );
        assert_eq!(diagnostic.context["rawTransaction"], DIAGNOSTIC_REDACTED);
        assert_eq!(diagnostic.context["txid"], "a".repeat(64));
    }
}
