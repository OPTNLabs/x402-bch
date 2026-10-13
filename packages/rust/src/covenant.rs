//! Registered BCH covenant-profile identity and successor validation.
//!
//! This module validates a deterministic profile boundary. It is deliberately
//! separate from the general BCH VM: a profile defines the exact successor
//! topology, state transition, token rule, and fee rule that it authorizes.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantProfile {
    pub id: String,
    pub family: String,
    #[serde(rename = "profileVersion")]
    pub profile_version: u64,
    pub network: String,
    #[serde(rename = "constructorParameters")]
    pub constructor_parameters: serde_json::Map<String, Value>,
    #[serde(rename = "successorPolicy")]
    pub successor_policy: SuccessorPolicy,
    #[serde(rename = "descriptorHash")]
    pub descriptor_hash: String,
    #[serde(rename = "lockingBytecodeHash")]
    pub locking_bytecode_hash: String,
    #[serde(rename = "successorPolicyHash")]
    pub successor_policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessorPolicy {
    #[serde(rename = "lockingBytecode")]
    pub locking_bytecode: String,
    #[serde(rename = "maxFee")]
    pub max_fee: String,
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    #[serde(rename = "stateTransition")]
    pub state_transition: String,
    pub token: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantState {
    #[serde(rename = "lockingBytecode")]
    pub locking_bytecode: String,
    pub value: String,
    pub epoch: String,
    #[serde(rename = "requestHash")]
    pub request_hash: String,
    pub token: Option<CovenantTokenState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantTokenState {
    pub category: String,
    pub amount: String,
    pub nft: Option<CovenantNftState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantNftState {
    pub capability: String,
    pub commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantTransition {
    #[serde(rename = "requestHash")]
    pub request_hash: String,
    #[serde(rename = "successorOutputIndex")]
    pub successor_output_index: u32,
    pub fee: String,
    pub source: CovenantState,
    pub successor: CovenantState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CovenantErrorCode {
    ProfileIdentityMismatch,
    LockingBytecodeMismatch,
    SuccessorOutputIndexMismatch,
    RequestHashMismatch,
    StateTransitionInvalid,
    FeeExceedsLimit,
    TokenStateMismatch,
}

pub fn validate_covenant_transition(
    profile: &CovenantProfile,
    transition: &CovenantTransition,
) -> Result<(), CovenantErrorCode> {
    if !profile_hashes_match(profile) {
        return Err(CovenantErrorCode::ProfileIdentityMismatch);
    }
    if transition.source.locking_bytecode != profile.successor_policy.locking_bytecode
        || transition.successor.locking_bytecode != profile.successor_policy.locking_bytecode
    {
        return Err(CovenantErrorCode::LockingBytecodeMismatch);
    }
    if transition.successor_output_index != profile.successor_policy.output_index {
        return Err(CovenantErrorCode::SuccessorOutputIndexMismatch);
    }
    if transition.request_hash != transition.source.request_hash
        || transition.request_hash != transition.successor.request_hash
    {
        return Err(CovenantErrorCode::RequestHashMismatch);
    }
    let source_epoch = parse_uint(&transition.source.epoch);
    let successor_epoch = parse_uint(&transition.successor.epoch);
    if profile.successor_policy.state_transition == "epoch-plus-one"
        && successor_epoch != source_epoch.saturating_add(1)
    {
        return Err(CovenantErrorCode::StateTransitionInvalid);
    }
    let fee = parse_uint(&transition.fee);
    if fee > parse_uint(&profile.successor_policy.max_fee) {
        return Err(CovenantErrorCode::FeeExceedsLimit);
    }
    if profile.successor_policy.value == "preserve-minus-fee"
        && parse_uint(&transition.source.value).checked_sub(parse_uint(&transition.successor.value))
            != Some(fee)
    {
        return Err(CovenantErrorCode::StateTransitionInvalid);
    }
    if profile.successor_policy.token == "preserve"
        && serde_json::to_value(&transition.source.token).unwrap()
            != serde_json::to_value(&transition.successor.token).unwrap()
    {
        return Err(CovenantErrorCode::TokenStateMismatch);
    }
    Ok(())
}

pub fn profile_hashes_match(profile: &CovenantProfile) -> bool {
    let descriptor = serde_json::json!({
        "id": profile.id,
        "family": profile.family,
        "profileVersion": profile.profile_version,
        "network": profile.network,
        "constructorParameters": profile.constructor_parameters,
        "successorPolicy": profile.successor_policy,
    });
    sha256_hex(canonical_json(&descriptor).as_bytes()) == profile.descriptor_hash
        && hex::decode(&profile.successor_policy.locking_bytecode)
            .map(|bytes| sha256_hex(&bytes) == profile.locking_bytecode_hash)
            .unwrap_or(false)
        && sha256_hex(
            canonical_json(&serde_json::to_value(&profile.successor_policy).unwrap()).as_bytes(),
        ) == profile.successor_policy_hash
}

fn parse_uint(value: &str) -> u128 {
    value.parse::<u128>().unwrap_or(u128::MAX)
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    serde_json::to_string(key).unwrap(),
                    canonical_json(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_registered_covenant_profile_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../spec/conformance/v1/covenant-profiles.json"
        ))
        .unwrap();
        let profile: CovenantProfile = serde_json::from_value(fixture["profile"].clone()).unwrap();
        assert!(profile_hashes_match(&profile));
        for case in fixture["cases"].as_array().unwrap() {
            let transition: CovenantTransition = serde_json::from_value(case.clone()).unwrap();
            let result = validate_covenant_transition(&profile, &transition);
            match case["expected"].as_str().unwrap() {
                "accept" => assert_eq!(result, Ok(()), "{}", case["id"]),
                "reject" => assert_eq!(
                    format!("{:?}", result.err().unwrap()),
                    rust_error_name(case["errorCode"].as_str().unwrap()),
                    "{}",
                    case["id"]
                ),
                other => panic!("unexpected fixture result {other}"),
            }
        }
    }

    fn rust_error_name(code: &str) -> String {
        match code {
            "locking-bytecode-mismatch" => "LockingBytecodeMismatch",
            "state-transition-invalid" => "StateTransitionInvalid",
            "fee-exceeds-limit" => "FeeExceedsLimit",
            "token-state-mismatch" => "TokenStateMismatch",
            "request-hash-mismatch" => "RequestHashMismatch",
            "successor-output-index-mismatch" => "SuccessorOutputIndexMismatch",
            "profile-identity-mismatch" => "ProfileIdentityMismatch",
            _ => panic!("unknown fixture error code"),
        }
        .to_string()
    }
}
