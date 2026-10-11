//! Bitcoin Cash transaction parsing, serialization, and P2PKH validation.

use secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey, ecdsa::Signature};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use crate::address::{CashAddr, CashAddrScript, CashAddrType, hash160, p2pkh_script};
use crate::chain::BchChainReference;

pub const BCH_SIGHASH_ALL_FORKID: u32 = 0x41;

pub fn parse_canonical_satoshi_amount(value: &str) -> Result<u64, TransactionError> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TransactionError::PolicyViolation(
            "BCH amount must be canonical satoshis".to_string(),
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| TransactionError::ArithmeticOverflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId(pub [u8; 32]);

impl TxId {
    pub fn from_hex(value: &str) -> Result<Self, TransactionError> {
        let bytes = hex::decode(value).map_err(|_| TransactionError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(TransactionError::InvalidHex);
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes);
        Ok(Self(txid))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for TxId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: TxId,
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub outpoint: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub token: Option<BchToken>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchTransaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub token: Option<BchToken>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BchTokenCapability {
    None,
    Mutable,
    Minting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchNft {
    pub capability: BchTokenCapability,
    pub commitment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchToken {
    /// CashToken category in user-interface byte order.
    pub category: [u8; 32],
    pub amount: u64,
    pub nft: Option<BchNft>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BchPaymentTarget {
    Native {
        amount: u64,
        merchant_value: u64,
    },
    CashToken {
        category: [u8; 32],
        amount: u64,
        merchant_value: u64,
        nft: Option<BchNft>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    #[error("transaction is truncated")]
    Truncated,
    #[error("transaction contains a non-canonical compact-size integer")]
    NonCanonicalVarInt,
    #[error("transaction contains an unsupported witness marker")]
    WitnessUnsupported,
    #[error("transaction contains too many inputs or outputs")]
    ExcessiveCount,
    #[error("transaction contains an invalid script")]
    InvalidScript,
    #[error("transaction contains an invalid signature")]
    InvalidSignature,
    #[error("transaction contains an unsupported sighash type")]
    UnsupportedSighash,
    #[error("transaction contains an invalid public key")]
    InvalidPublicKey,
    #[error("transaction contains an invalid hex value")]
    InvalidHex,
    #[error("transaction arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("transaction has an invalid input or output policy")]
    PolicyViolation(String),
}

impl BchTransaction {
    pub fn parse(raw: &[u8]) -> Result<Self, TransactionError> {
        let mut reader = Reader::new(raw);
        let version = reader.i32()?;
        let input_count = bounded_count(reader.varint()?, 10_000)?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let mut txid_wire = [0u8; 32];
            txid_wire.copy_from_slice(reader.take(32)?);
            txid_wire.reverse();
            let vout = reader.u32()?;
            let script_sig = reader.bytes()?;
            let sequence = reader.u32()?;
            inputs.push(TxInput {
                outpoint: OutPoint {
                    txid: TxId(txid_wire),
                    vout,
                },
                script_sig,
                sequence,
            });
        }
        let output_count = bounded_count(reader.varint()?, 10_000)?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let value = reader.u64()?;
            let field = reader.bytes()?;
            let (token, script_pubkey) = parse_token_prefix_and_script(&field)?;
            outputs.push(TxOutput {
                value,
                script_pubkey,
                token,
            });
        }
        let lock_time = reader.u32()?;
        if !reader.is_empty() {
            return Err(TransactionError::PolicyViolation(
                "trailing bytes after locktime".to_string(),
            ));
        }
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.version.to_le_bytes());
        write_varint(self.inputs.len() as u64, &mut result);
        for input in &self.inputs {
            let mut txid_wire = input.outpoint.txid.0;
            txid_wire.reverse();
            result.extend_from_slice(&txid_wire);
            result.extend_from_slice(&input.outpoint.vout.to_le_bytes());
            write_bytes(&input.script_sig, &mut result);
            result.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, &mut result);
        for output in &self.outputs {
            result.extend_from_slice(&output.value.to_le_bytes());
            let field =
                serialize_token_prefix_and_script(output.token.as_ref(), &output.script_pubkey)
                    .expect("BCH transaction output token data must be valid");
            write_bytes(&field, &mut result);
        }
        result.extend_from_slice(&self.lock_time.to_le_bytes());
        result
    }

    pub fn txid(&self) -> TxId {
        let digest = double_sha256(&self.serialize());
        let mut txid = digest;
        txid.reverse();
        TxId(txid)
    }

    pub fn signing_hash(
        &self,
        input_index: usize,
        source_output: &SourceOutput,
        sighash_type: u32,
    ) -> Result<[u8; 32], TransactionError> {
        if sighash_type != BCH_SIGHASH_ALL_FORKID {
            return Err(TransactionError::UnsupportedSighash);
        }
        let input = self
            .inputs
            .get(input_index)
            .ok_or(TransactionError::Truncated)?;
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.version.to_le_bytes());

        let mut prevouts = Vec::with_capacity(self.inputs.len() * 36);
        for candidate in &self.inputs {
            let mut txid_wire = candidate.outpoint.txid.0;
            txid_wire.reverse();
            prevouts.extend_from_slice(&txid_wire);
            prevouts.extend_from_slice(&candidate.outpoint.vout.to_le_bytes());
        }
        preimage.extend_from_slice(&double_sha256(&prevouts));

        let mut sequences = Vec::with_capacity(self.inputs.len() * 4);
        for candidate in &self.inputs {
            sequences.extend_from_slice(&candidate.sequence.to_le_bytes());
        }
        preimage.extend_from_slice(&double_sha256(&sequences));

        let mut txid_wire = input.outpoint.txid.0;
        txid_wire.reverse();
        preimage.extend_from_slice(&txid_wire);
        preimage.extend_from_slice(&input.outpoint.vout.to_le_bytes());
        let source_token_prefix = serialize_token_prefix(source_output.token.as_ref())
            .map_err(|_| TransactionError::InvalidScript)?;
        preimage.extend_from_slice(&source_token_prefix);
        write_bytes(&source_output.script_pubkey, &mut preimage);
        preimage.extend_from_slice(&source_output.value.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());

        let mut outputs = Vec::new();
        for output in &self.outputs {
            outputs.extend_from_slice(&output.value.to_le_bytes());
            let field =
                serialize_token_prefix_and_script(output.token.as_ref(), &output.script_pubkey)
                    .map_err(|_| TransactionError::InvalidScript)?;
            write_bytes(&field, &mut outputs);
        }
        preimage.extend_from_slice(&double_sha256(&outputs));
        preimage.extend_from_slice(&self.lock_time.to_le_bytes());
        preimage.extend_from_slice(&sighash_type.to_le_bytes());
        Ok(double_sha256(&preimage))
    }

    pub fn verify_p2pkh_input(
        &self,
        input_index: usize,
        source_output: &SourceOutput,
    ) -> Result<[u8; 20], TransactionError> {
        let input = self
            .inputs
            .get(input_index)
            .ok_or(TransactionError::Truncated)?;
        if !is_p2pkh_script(&source_output.script_pubkey) {
            return Err(TransactionError::PolicyViolation(
                "source output is not P2PKH".to_string(),
            ));
        }
        let pushes = parse_pushes(&input.script_sig)?;
        if pushes.len() != 2 || pushes[0].len() < 2 {
            return Err(TransactionError::InvalidScript);
        }
        let signature_bytes = pushes[0];
        let sighash_type = *signature_bytes
            .last()
            .ok_or(TransactionError::InvalidSignature)?;
        if u32::from(sighash_type) != BCH_SIGHASH_ALL_FORKID {
            return Err(TransactionError::UnsupportedSighash);
        }
        let signature = &signature_bytes[..signature_bytes.len() - 1];
        let public_key_bytes = pushes[1];
        let public_key = PublicKey::from_slice(public_key_bytes)
            .map_err(|_| TransactionError::InvalidPublicKey)?;
        let public_key_hash = hash160(public_key_bytes);
        if source_output.script_pubkey[3..23] != public_key_hash[..] {
            return Err(TransactionError::InvalidSignature);
        }
        let digest = self.signing_hash(input_index, source_output, BCH_SIGHASH_ALL_FORKID)?;
        // A 64-byte signature is BCH Schnorr; anything else must be DER ECDSA.
        let valid = if signature.len() == 64 {
            verify_bch_schnorr(signature, &public_key, &digest)
        } else {
            let signature =
                Signature::from_der(signature).map_err(|_| TransactionError::InvalidSignature)?;
            Secp256k1::verification_only()
                .verify_ecdsa(Message::from_digest(digest), &signature, &public_key)
                .is_ok()
        };
        if !valid {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(public_key_hash)
    }

    /// Check an input that is not P2PKH without running its script.
    ///
    /// The unlocking bytecode must be push-only, and a P2SH20 or P2SH32 input
    /// must push the redeem script its source output commits to. The BCH
    /// network runs the scripts when the transaction is broadcast, so a
    /// settlement fails if one of them is invalid.
    pub fn check_script_input(
        &self,
        input_index: usize,
        source_output: &SourceOutput,
    ) -> Result<(), TransactionError> {
        let input = self
            .inputs
            .get(input_index)
            .ok_or(TransactionError::Truncated)?;
        let stack = unlocking_stack(&input.script_sig)?;
        let script = &source_output.script_pubkey;
        let redeem_script = stack.last().map(Vec::as_slice).unwrap_or_default();
        let committed = if is_p2sh20_script(script) {
            hash160(redeem_script)[..] == script[2..22]
        } else if is_p2sh32_script(script) {
            double_sha256(redeem_script)[..] == script[2..34]
        } else {
            true
        };
        if !committed {
            return Err(TransactionError::PolicyViolation(
                "P2SH input does not push the redeem script its source output commits to"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Floor for a CashToken merchant output when the price omits `value`.
///
/// The omitted value is the greater of this floor, the configured policy dust
/// threshold, and the standard relay dust of the merchant output. CHIP-2024-12
/// raised the consensus commitment limit from 40 bytes to 128 bytes
/// (<https://github.com/bitjson/bch-p2s>), and a 128-byte commitment can push
/// that relay dust above 1,000 satoshis. The historical 828-satoshi figure is
/// the relay dust of a 40-byte commitment on the largest locking script this
/// crate pays; it is not the current maximum. An explicit value is preserved
/// and still has to meet the size-based dust check. Native outputs keep the
/// 546-satoshi dust floor.
pub(crate) const CASHTOKEN_OUTPUT_DUST: u64 = 1_000;

/// Maximum NFT commitment length after the May 2026 upgrade.
///
/// An empty commitment is valid: the commitment bit stays unset. A commitment
/// bit set to a compact-size length of zero is not a valid encoding.
pub const MAX_TOKEN_COMMITMENT_LENGTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BchPolicy {
    pub fee_rate_sat_per_byte: u64,
    pub dust_threshold: u64,
    pub max_transaction_size: usize,
    pub max_inputs: usize,
    /// Most outputs an exact payment may carry, including the merchant output.
    pub max_outputs: usize,
}

impl Default for BchPolicy {
    fn default() -> Self {
        Self {
            fee_rate_sat_per_byte: 1,
            dust_threshold: 546,
            max_transaction_size: 100_000,
            max_inputs: 100,
            max_outputs: 16,
        }
    }
}

pub fn parse_cash_token_category(value: &str) -> Result<[u8; 32], TransactionError> {
    if value != value.to_ascii_lowercase()
        || value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TransactionError::InvalidHex);
    }
    let bytes = hex::decode(value).map_err(|_| TransactionError::InvalidHex)?;
    if bytes.len() != 32 {
        return Err(TransactionError::PolicyViolation(
            "CashToken category must be 32 bytes".to_string(),
        ));
    }
    let mut category = [0u8; 32];
    category.copy_from_slice(&bytes);
    Ok(category)
}

pub fn payment_target(
    asset: &str,
    amount: &str,
    asset_transfer_method: &str,
    token_output_value: Option<&str>,
    policy: BchPolicy,
) -> Result<BchPaymentTarget, TransactionError> {
    payment_target_with_nft(
        asset,
        amount,
        asset_transfer_method,
        token_output_value,
        None,
        &[],
        policy,
    )
}

pub fn payment_target_with_nft(
    asset: &str,
    amount: &str,
    asset_transfer_method: &str,
    token_output_value: Option<&str>,
    nft: Option<BchNft>,
    merchant_script: &[u8],
    policy: BchPolicy,
) -> Result<BchPaymentTarget, TransactionError> {
    let amount = parse_canonical_satoshi_amount(amount)?;
    if asset == "BCH" {
        if asset_transfer_method != "native" {
            return Err(TransactionError::PolicyViolation(
                "BCH requires native asset transfer method".to_string(),
            ));
        }
        return Ok(BchPaymentTarget::Native {
            amount,
            merchant_value: amount,
        });
    }
    if asset_transfer_method != "cashtoken" {
        return Err(TransactionError::PolicyViolation(
            "CashToken requires the cashtoken asset transfer method".to_string(),
        ));
    }
    if (amount == 0 && nft.is_none()) || amount > i64::MAX as u64 {
        return Err(TransactionError::PolicyViolation(
            "CashToken amount is outside the BCH token range".to_string(),
        ));
    }
    let category = parse_cash_token_category(asset)?;
    let merchant_value = match token_output_value {
        Some(value) => parse_canonical_satoshi_amount(value)?,
        None => {
            omitted_token_output_value(merchant_script, category, amount, nft.as_ref(), policy)?
        }
    };
    Ok(BchPaymentTarget::CashToken {
        category,
        amount,
        merchant_value,
        nft,
    })
}

/// Satoshis to use when a CashToken price omits `value`.
///
/// Explicit quotes are not passed through this function. The result is at
/// least [`CASHTOKEN_OUTPUT_DUST`] and at least the policy dust threshold,
/// and it is large enough for the standard relay dust of `locking_script`
/// with this token prefix.
pub(crate) fn omitted_token_output_value(
    locking_script: &[u8],
    category: [u8; 32],
    amount: u64,
    nft: Option<&BchNft>,
    policy: BchPolicy,
) -> Result<u64, TransactionError> {
    if !is_supported_merchant_script(locking_script) {
        return Err(TransactionError::PolicyViolation(
            "omitted tokenOutputValue requires the merchant locking script".to_string(),
        ));
    }
    if nft.is_some_and(|nft| nft.commitment.len() > MAX_TOKEN_COMMITMENT_LENGTH) {
        return Err(TransactionError::PolicyViolation(
            "invalid CashToken NFT commitment".to_string(),
        ));
    }
    let output = TxOutput {
        value: 0,
        script_pubkey: locking_script.to_vec(),
        token: Some(BchToken {
            category,
            amount,
            nft: nft.cloned(),
        }),
    };
    Ok(standard_output_dust(&output, policy.dust_threshold)?.max(CASHTOKEN_OUTPUT_DUST))
}

pub fn parse_cash_token_nft(
    capability: Option<&str>,
    commitment: Option<&str>,
) -> Result<Option<BchNft>, TransactionError> {
    match (capability, commitment) {
        (None, None) => Ok(None),
        (Some(capability), Some(commitment)) => {
            let capability = match capability {
                "none" => BchTokenCapability::None,
                "mutable" => BchTokenCapability::Mutable,
                "minting" => BchTokenCapability::Minting,
                _ => {
                    return Err(TransactionError::PolicyViolation(
                        "invalid CashToken NFT capability".to_string(),
                    ));
                }
            };
            let commitment = hex::decode(commitment).map_err(|_| TransactionError::InvalidHex)?;
            if commitment.len() > MAX_TOKEN_COMMITMENT_LENGTH {
                return Err(TransactionError::PolicyViolation(
                    "invalid CashToken NFT commitment".to_string(),
                ));
            }
            Ok(Some(BchNft {
                capability,
                commitment,
            }))
        }
        _ => Err(TransactionError::PolicyViolation(
            "CashToken NFT capability and commitment must be provided together".to_string(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub txid: TxId,
    /// CashAddr of the first P2PKH input, or of the first input's script.
    pub payer: String,
    pub fee: u64,
    pub input_value: u64,
    pub output_value: u64,
}

pub fn verify_payment(
    transaction: &BchTransaction,
    source_outputs: &[SourceOutput],
    network: BchChainReference,
    merchant_script: &[u8],
    target: &BchPaymentTarget,
    policy: BchPolicy,
) -> Result<VerifiedPayment, TransactionError> {
    validate_payment_target(target)?;
    let serialized_size = transaction.serialize().len();
    if serialized_size > policy.max_transaction_size {
        return Err(TransactionError::PolicyViolation(
            "transaction exceeds maximum size".to_string(),
        ));
    }
    if transaction.inputs.is_empty() || transaction.inputs.len() > policy.max_inputs {
        return Err(TransactionError::ExcessiveCount);
    }
    if transaction.lock_time != 0 {
        return Err(TransactionError::PolicyViolation(
            "non-zero locktime is not supported by BCH exact".to_string(),
        ));
    }
    let merchant_value = match target {
        BchPaymentTarget::Native { merchant_value, .. }
        | BchPaymentTarget::CashToken { merchant_value, .. } => *merchant_value,
    };
    if merchant_value < policy.dust_threshold {
        return Err(TransactionError::PolicyViolation(
            "merchant output is below dust".to_string(),
        ));
    }
    if source_outputs.len() != transaction.inputs.len() {
        return Err(TransactionError::PolicyViolation(
            "source output count does not match transaction inputs".to_string(),
        ));
    }
    if transaction.outputs.is_empty() || transaction.outputs.len() > policy.max_outputs {
        return Err(TransactionError::PolicyViolation(
            "transaction output count exceeds BCH payment policy".to_string(),
        ));
    }

    let mut input_value = 0u64;
    let mut input_tokens = TokenLedger::default();
    let mut payer_hash = None;
    for (index, source_output) in source_outputs.iter().enumerate() {
        input_value = input_value
            .checked_add(source_output.value)
            .ok_or(TransactionError::ArithmeticOverflow)?;
        if is_p2pkh_script(&source_output.script_pubkey) {
            let hash = transaction.verify_p2pkh_input(index, source_output)?;
            payer_hash.get_or_insert(hash);
        } else {
            transaction.check_script_input(index, source_output)?;
        }
        if let Some(token) = &source_output.token {
            input_tokens.add(token);
        }
    }

    if let BchPaymentTarget::CashToken {
        category,
        amount,
        nft,
        ..
    } = target
    {
        if nft
            .as_ref()
            .is_some_and(|expected| !input_tokens.contains_nft(category, expected))
        {
            return Err(TransactionError::PolicyViolation(
                "CashToken inputs do not contain the requested NFT".to_string(),
            ));
        }
        if input_tokens.fungible_amount(category) < u128::from(*amount) {
            return Err(TransactionError::PolicyViolation(
                "CashToken inputs do not cover the requested amount".to_string(),
            ));
        }
    }

    let is_merchant_output = |output: &TxOutput| {
        output.value == merchant_value
            && output.script_pubkey == merchant_script
            && merchant_token_matches(output.token.as_ref(), target)
    };
    if transaction
        .outputs
        .iter()
        .filter(|output| is_merchant_output(output))
        .count()
        != 1
    {
        return Err(TransactionError::PolicyViolation(
            "transaction must contain exactly one exact merchant output".to_string(),
        ));
    }

    let mut output_value = 0u64;
    let mut output_tokens = TokenLedger::default();
    for output in &transaction.outputs {
        if let Some(token) = &output.token {
            output_tokens.add(token);
        }
        if !is_op_return_script(&output.script_pubkey)
            && output.value < standard_output_dust(output, policy.dust_threshold)?
        {
            return Err(TransactionError::PolicyViolation(
                "output is below the standard BCH dust threshold".to_string(),
            ));
        }
        output_value = output_value
            .checked_add(output.value)
            .ok_or(TransactionError::ArithmeticOverflow)?;
    }
    if input_tokens != output_tokens {
        return Err(TransactionError::PolicyViolation(
            "CashToken state is not conserved".to_string(),
        ));
    }
    let fee = input_value
        .checked_sub(output_value)
        .ok_or(TransactionError::PolicyViolation(
            "outputs exceed input value".to_string(),
        ))?;
    let minimum_fee = (serialized_size as u64)
        .checked_mul(policy.fee_rate_sat_per_byte)
        .ok_or(TransactionError::ArithmeticOverflow)?;
    if fee < minimum_fee {
        return Err(TransactionError::PolicyViolation(
            "transaction fee is below the BCH exact minimum".to_string(),
        ));
    }
    if transaction
        .outputs
        .iter()
        .any(|output| output.script_pubkey == merchant_script && !is_merchant_output(output))
    {
        return Err(TransactionError::PolicyViolation(
            "duplicate merchant output".to_string(),
        ));
    }

    let payer = match payer_hash {
        Some(hash160) => CashAddr { network, hash160 }.to_string(),
        None => script_payer(&source_outputs[0], network),
    };
    Ok(VerifiedPayment {
        txid: transaction.txid(),
        payer,
        fee,
        input_value,
        output_value,
    })
}

fn validate_payment_target(target: &BchPaymentTarget) -> Result<(), TransactionError> {
    if let BchPaymentTarget::CashToken { amount, nft, .. } = target
        && ((*amount == 0 && nft.is_none()) || *amount > i64::MAX as u64)
    {
        return Err(TransactionError::PolicyViolation(
            "CashToken amount is outside the BCH token range".to_string(),
        ));
    }
    Ok(())
}

/// CashToken state held by a set of outputs: the fungible amount of each
/// category and the multiset of NFTs. An exact payment must leave it unchanged.
#[derive(Debug, Default, PartialEq, Eq)]
struct TokenLedger {
    fungible: BTreeMap<[u8; 32], u128>,
    nfts: BTreeMap<([u8; 32], BchTokenCapability, Vec<u8>), usize>,
}

impl TokenLedger {
    fn add(&mut self, token: &BchToken) {
        *self.fungible.entry(token.category).or_default() += u128::from(token.amount);
        if let Some(nft) = &token.nft {
            *self
                .nfts
                .entry((token.category, nft.capability, nft.commitment.clone()))
                .or_default() += 1;
        }
    }

    fn fungible_amount(&self, category: &[u8; 32]) -> u128 {
        self.fungible.get(category).copied().unwrap_or_default()
    }

    fn contains_nft(&self, category: &[u8; 32], nft: &BchNft) -> bool {
        self.nfts
            .contains_key(&(*category, nft.capability, nft.commitment.clone()))
    }
}

/// Address of a payer whose inputs are all non-P2PKH, as the TypeScript
/// package reports it.
fn script_payer(source: &SourceOutput, network: BchChainReference) -> String {
    let script = &source.script_pubkey;
    let (kind, payload) = if is_p2sh20_script(script) {
        (CashAddrType::P2sh20, &script[2..22])
    } else if is_p2sh32_script(script) {
        (CashAddrType::P2sh32, &script[2..34])
    } else {
        return format!("bch:script:{}", hex::encode(script));
    };
    CashAddrScript {
        network,
        kind,
        payload: payload.to_vec(),
        token_support: source.token.is_some(),
    }
    .encode()
    .unwrap_or_else(|_| format!("bch:script:{}", hex::encode(script)))
}

fn is_op_return_script(script: &[u8]) -> bool {
    script.first() == Some(&0x6a)
}

fn merchant_token_matches(token: Option<&BchToken>, target: &BchPaymentTarget) -> bool {
    match target {
        BchPaymentTarget::Native { .. } => token.is_none(),
        BchPaymentTarget::CashToken {
            category,
            amount,
            nft,
            ..
        } => token.is_some_and(|token| {
            token.category == *category && token.amount == *amount && token.nft == *nft
        }),
    }
}

pub fn is_p2pkh_script(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
}

pub fn is_p2sh20_script(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

pub fn is_p2sh32_script(script: &[u8]) -> bool {
    script.len() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87
}

pub fn is_supported_merchant_script(script: &[u8]) -> bool {
    is_p2pkh_script(script) || is_p2sh20_script(script) || is_p2sh32_script(script)
}

fn parse_token_prefix_and_script(
    field: &[u8],
) -> Result<(Option<BchToken>, Vec<u8>), TransactionError> {
    if field.first().copied() != Some(0xef) {
        return Ok((None, field.to_vec()));
    }
    if field.len() < 34 {
        return Err(TransactionError::InvalidScript);
    }
    let mut category = [0u8; 32];
    category.copy_from_slice(&field[1..33]);
    category.reverse();
    let bitfield = field[33];
    if bitfield & 0x80 != 0 {
        return Err(TransactionError::InvalidScript);
    }
    let has_amount = bitfield & 0x10 != 0;
    let has_nft = bitfield & 0x20 != 0;
    let has_commitment = bitfield & 0x40 != 0;
    let capability = match bitfield & 0x0f {
        0 => BchTokenCapability::None,
        1 => BchTokenCapability::Mutable,
        2 => BchTokenCapability::Minting,
        _ => return Err(TransactionError::InvalidScript),
    };
    if !has_nft && (has_commitment || capability != BchTokenCapability::None) {
        return Err(TransactionError::InvalidScript);
    }
    let mut offset = 34usize;
    let commitment = if has_commitment {
        let (length, next) = read_compact_uint(&field[offset..])?;
        if length == 0 || length > MAX_TOKEN_COMMITMENT_LENGTH as u64 {
            return Err(TransactionError::InvalidScript);
        }
        offset = offset
            .checked_add(next)
            .ok_or(TransactionError::InvalidScript)?;
        let end = offset
            .checked_add(length as usize)
            .ok_or(TransactionError::InvalidScript)?;
        let bytes = field.get(offset..end).ok_or(TransactionError::Truncated)?;
        offset = end;
        bytes.to_vec()
    } else {
        Vec::new()
    };
    let amount = if has_amount {
        let (amount, next) = read_compact_uint(&field[offset..])?;
        if amount == 0 || amount > i64::MAX as u64 {
            return Err(TransactionError::InvalidScript);
        }
        offset = offset
            .checked_add(next)
            .ok_or(TransactionError::InvalidScript)?;
        amount
    } else {
        0
    };
    if !has_amount && !has_nft {
        return Err(TransactionError::InvalidScript);
    }
    let token = BchToken {
        category,
        amount,
        nft: has_nft.then_some(BchNft {
            capability,
            commitment,
        }),
    };
    Ok((Some(token), field[offset..].to_vec()))
}

fn serialize_token_prefix_and_script(
    token: Option<&BchToken>,
    script_pubkey: &[u8],
) -> Result<Vec<u8>, TransactionError> {
    let mut result = serialize_token_prefix(token)?;
    result.extend_from_slice(script_pubkey);
    Ok(result)
}

fn serialize_token_prefix(token: Option<&BchToken>) -> Result<Vec<u8>, TransactionError> {
    let Some(token) = token else {
        return Ok(Vec::new());
    };
    if token.amount > i64::MAX as u64 {
        return Err(TransactionError::InvalidScript);
    }
    if token.amount == 0 && token.nft.is_none() {
        return Err(TransactionError::InvalidScript);
    }
    let mut result = vec![0xef];
    result.extend(token.category.iter().rev());
    let mut bitfield = 0u8;
    if token.amount > 0 {
        bitfield |= 0x10;
    }
    if let Some(nft) = &token.nft {
        bitfield |= match nft.capability {
            BchTokenCapability::None => 0,
            BchTokenCapability::Mutable => 1,
            BchTokenCapability::Minting => 2,
        };
        bitfield |= 0x20;
        if !nft.commitment.is_empty() {
            if nft.commitment.len() > MAX_TOKEN_COMMITMENT_LENGTH {
                return Err(TransactionError::InvalidScript);
            }
            bitfield |= 0x40;
        }
    }
    result.push(bitfield);
    if let Some(nft) = &token.nft
        && !nft.commitment.is_empty()
    {
        write_varint(nft.commitment.len() as u64, &mut result);
        result.extend_from_slice(&nft.commitment);
    }
    if token.amount > 0 {
        write_varint(token.amount, &mut result);
    }
    Ok(result)
}

fn read_compact_uint(bytes: &[u8]) -> Result<(u64, usize), TransactionError> {
    let first = *bytes.first().ok_or(TransactionError::Truncated)?;
    match first {
        0..=252 => Ok((u64::from(first), 1)),
        253 => {
            let raw = bytes.get(1..3).ok_or(TransactionError::Truncated)?;
            let value = u16::from_le_bytes([raw[0], raw[1]]) as u64;
            if value < 253 {
                return Err(TransactionError::NonCanonicalVarInt);
            }
            Ok((value, 3))
        }
        254 => {
            let raw = bytes.get(1..5).ok_or(TransactionError::Truncated)?;
            let value = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as u64;
            if value <= u16::MAX as u64 {
                return Err(TransactionError::NonCanonicalVarInt);
            }
            Ok((value, 5))
        }
        255 => {
            let raw = bytes.get(1..9).ok_or(TransactionError::Truncated)?;
            let value = u64::from_le_bytes(raw.try_into().unwrap());
            if value <= u32::MAX as u64 {
                return Err(TransactionError::NonCanonicalVarInt);
            }
            Ok((value, 9))
        }
    }
}

pub fn make_p2pkh_script(public_key: &[u8]) -> Vec<u8> {
    p2pkh_script(&hash160(public_key))
}

pub fn push_data(data: &[u8]) -> Result<Vec<u8>, TransactionError> {
    if data.len() > 75 {
        return Err(TransactionError::InvalidScript);
    }
    let mut result = Vec::with_capacity(data.len() + 1);
    result.push(data.len() as u8);
    result.extend_from_slice(data);
    Ok(result)
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Check a BCH Schnorr signature (May 2019 upgrade) over `digest`.
///
/// With e = SHA256(r || compressed public key || digest) mod n and
/// R = sG - eP, the signature is valid when R is a point, x(R) = r, and
/// y(R) is a quadratic residue mod p.
fn verify_bch_schnorr(signature: &[u8], public_key: &PublicKey, digest: &[u8; 32]) -> bool {
    use alloy_primitives::{U256, uint};
    const P: U256 = uint!(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_U256);
    const N: U256 = uint!(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_U256);
    let (r, s) = signature.split_at(32);
    let Some(s) = <[u8; 32]>::try_from(s)
        .ok()
        .and_then(|s| SecretKey::from_byte_array(s).ok())
    else {
        return false;
    };
    let e = Sha256::new()
        .chain_update(r)
        .chain_update(public_key.serialize())
        .chain_update(digest)
        .finalize();
    let e = U256::from_be_slice(&e).reduce_mod(N);
    let Ok(e) = Scalar::from_be_bytes(e.to_be_bytes::<32>()) else {
        return false;
    };
    let secp = Secp256k1::new();
    let Ok(e_p) = public_key.mul_tweak(&secp, &e) else {
        return false;
    };
    let Ok(point) = PublicKey::from_secret_key(&secp, &s).combine(&e_p.negate(&secp)) else {
        return false;
    };
    let point = point.serialize_uncompressed();
    let y = U256::from_be_slice(&point[33..]);
    point[1..33] == *r && y.pow_mod(P >> 1, P) == U256::from(1)
}

/// Evaluate push-only unlocking bytecode into the stack it leaves.
fn unlocking_stack(script: &[u8]) -> Result<Vec<Vec<u8>>, TransactionError> {
    let mut stack = Vec::new();
    let mut offset = 0usize;
    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        let length = match opcode {
            0x00 => 0,
            0x01..=0x4b => usize::from(opcode),
            0x4c..=0x4e => {
                let width = match opcode {
                    0x4c => 1,
                    0x4d => 2,
                    _ => 4,
                };
                let bytes = script
                    .get(offset..offset + width)
                    .ok_or(TransactionError::InvalidScript)?;
                offset += width;
                let mut length = [0u8; 4];
                length[..width].copy_from_slice(bytes);
                usize::try_from(u32::from_le_bytes(length))
                    .map_err(|_| TransactionError::InvalidScript)?
            }
            0x4f => {
                stack.push(vec![0x81]);
                continue;
            }
            0x51..=0x60 => {
                stack.push(vec![opcode - 0x50]);
                continue;
            }
            _ => {
                return Err(TransactionError::PolicyViolation(
                    "unlocking bytecode must be push-only".to_string(),
                ));
            }
        };
        let end = offset
            .checked_add(length)
            .ok_or(TransactionError::InvalidScript)?;
        stack.push(
            script
                .get(offset..end)
                .ok_or(TransactionError::InvalidScript)?
                .to_vec(),
        );
        offset = end;
    }
    Ok(stack)
}

fn parse_pushes(script: &[u8]) -> Result<Vec<&[u8]>, TransactionError> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        let length = match opcode {
            0x01..=0x4b => opcode as usize,
            0x4c => usize::from(*script.get(offset).ok_or(TransactionError::InvalidScript)?),
            0x4d => {
                let bytes = script
                    .get(offset..offset + 2)
                    .ok_or(TransactionError::InvalidScript)?;
                offset += 2;
                usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
            }
            _ => return Err(TransactionError::InvalidScript),
        };
        if opcode == 0x4c {
            offset += 1;
        }
        let end = offset
            .checked_add(length)
            .ok_or(TransactionError::InvalidScript)?;
        let value = script
            .get(offset..end)
            .ok_or(TransactionError::InvalidScript)?;
        result.push(value);
        offset = end;
    }
    Ok(result)
}

fn write_bytes(value: &[u8], output: &mut Vec<u8>) {
    write_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn write_varint(value: u64, output: &mut Vec<u8>) {
    if value <= 252 {
        output.push(value as u8);
    } else if value <= u16::MAX as u64 {
        output.push(253);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u32::MAX as u64 {
        output.push(254);
        output.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        output.push(255);
        output.extend_from_slice(&value.to_le_bytes());
    }
}

fn varint_size(value: u64) -> u64 {
    if value <= 252 {
        1
    } else if value <= u64::from(u16::MAX) {
        3
    } else if value <= u64::from(u32::MAX) {
        5
    } else {
        9
    }
}

/// Standard BCH relay dust: 3 sat/byte over the output plus a 148-byte P2PKH spend.
pub(crate) fn standard_output_dust(output: &TxOutput, floor: u64) -> Result<u64, TransactionError> {
    let field = serialize_token_prefix_and_script(output.token.as_ref(), &output.script_pubkey)?;
    let output_len = 8u64
        .checked_add(varint_size(field.len() as u64))
        .and_then(|total| total.checked_add(field.len() as u64))
        .ok_or(TransactionError::ArithmeticOverflow)?;
    let spend_len = output_len
        .checked_add(148)
        .ok_or(TransactionError::ArithmeticOverflow)?;
    let standard = spend_len
        .checked_mul(3)
        .ok_or(TransactionError::ArithmeticOverflow)?;
    Ok(standard.max(floor))
}

fn bounded_count(value: u64, limit: u64) -> Result<usize, TransactionError> {
    if value == 0 || value > limit {
        return Err(TransactionError::ExcessiveCount);
    }
    usize::try_from(value).map_err(|_| TransactionError::ExcessiveCount)
}

fn field_len(value: u64) -> Result<usize, TransactionError> {
    if value > u64::from(u32::MAX) {
        return Err(TransactionError::ExcessiveCount);
    }
    usize::try_from(value).map_err(|_| TransactionError::ExcessiveCount)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TransactionError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TransactionError::Truncated)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(TransactionError::Truncated)?;
        self.offset = end;
        Ok(result)
    }

    fn u32(&mut self) -> Result<u32, TransactionError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn i32(&mut self) -> Result<i32, TransactionError> {
        let bytes = self.take(4)?;
        Ok(i32::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, TransactionError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn varint(&mut self) -> Result<u64, TransactionError> {
        let first = self.take(1)?[0];
        match first {
            0..=252 => Ok(u64::from(first)),
            253 => {
                let value = u16::from_le_bytes(self.take(2)?.try_into().expect("length checked"));
                if value < 253 {
                    Err(TransactionError::NonCanonicalVarInt)
                } else {
                    Ok(u64::from(value))
                }
            }
            254 => {
                let value = u32::from_le_bytes(self.take(4)?.try_into().expect("length checked"));
                if value <= u16::MAX as u32 {
                    Err(TransactionError::NonCanonicalVarInt)
                } else {
                    Ok(u64::from(value))
                }
            }
            255 => {
                let value = u64::from_le_bytes(self.take(8)?.try_into().expect("length checked"));
                if value <= u32::MAX as u64 {
                    Err(TransactionError::NonCanonicalVarInt)
                } else {
                    Ok(value)
                }
            }
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>, TransactionError> {
        let length = field_len(self.varint()?)?;
        Ok(self.take(length)?.to_vec())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::p2sh32_script;
    use x402_types::chain::ChainId;

    #[test]
    fn accepts_only_canonical_satoshi_amounts() {
        assert_eq!(parse_canonical_satoshi_amount("0").unwrap(), 0);
        assert_eq!(parse_canonical_satoshi_amount("1000").unwrap(), 1000);
        assert!(parse_canonical_satoshi_amount("01").is_err());
        assert!(parse_canonical_satoshi_amount("18446744073709551616").is_err());
    }

    #[test]
    fn serializes_and_parses_a_minimal_transaction() {
        let transaction = BchTransaction {
            version: 2,
            inputs: vec![TxInput {
                outpoint: OutPoint {
                    txid: TxId([1; 32]),
                    vout: 0,
                },
                script_sig: vec![0x01, 0x01],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 1_000,
                script_pubkey: p2pkh_script(&[2; 20]),
                token: None,
            }],
            lock_time: 0,
        };
        assert_eq!(
            BchTransaction::parse(&transaction.serialize()).unwrap(),
            transaction
        );
    }

    #[test]
    fn serializes_and_parses_a_fungible_cashtoken_output() {
        let category = std::array::from_fn(|index| index as u8);
        let transaction = BchTransaction {
            version: 2,
            inputs: vec![TxInput {
                outpoint: OutPoint {
                    txid: TxId([1; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 1_000,
                script_pubkey: p2sh32_script(&[0x22; 32]),
                token: Some(BchToken {
                    category,
                    amount: 1_000,
                    nft: None,
                }),
            }],
            lock_time: 0,
        };

        assert_eq!(
            BchTransaction::parse(&transaction.serialize()).unwrap(),
            transaction
        );
        assert_eq!(
            payment_target(
                &hex::encode(category),
                "1000",
                "cashtoken",
                Some("1000"),
                BchPolicy::default(),
            )
            .unwrap(),
            BchPaymentTarget::CashToken {
                category,
                amount: 1_000,
                merchant_value: 1_000,
                nft: None,
            }
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let transaction = BchTransaction {
            version: 1,
            inputs: vec![TxInput {
                outpoint: OutPoint {
                    txid: TxId([0; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 1,
                script_pubkey: p2pkh_script(&[0; 20]),
                token: None,
            }],
            lock_time: 0,
        };
        let mut raw = transaction.serialize();
        raw.push(0);
        assert!(BchTransaction::parse(&raw).is_err());
    }

    #[test]
    fn verifies_the_deterministic_interoperability_fixture() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Fixture {
            network: String,
            amount: String,
            pay_to: String,
            source_value: String,
            #[serde(rename = "sourceScriptPubKey")]
            source_script_pubkey: String,
            raw_transaction: String,
            txid: String,
            payer: String,
            serialized_size: usize,
            fee: String,
        }

        let fixture: Fixture =
            serde_json::from_str(include_str!("../test/fixtures/bch-exact-p2pkh.json")).unwrap();
        let network =
            BchChainReference::try_from(fixture.network.parse::<ChainId>().unwrap()).unwrap();
        let transaction =
            BchTransaction::parse(&hex::decode(fixture.raw_transaction).unwrap()).unwrap();
        let pay_to = CashAddr::decode(&fixture.pay_to, network).unwrap();
        let source_output = SourceOutput {
            value: fixture.source_value.parse().unwrap(),
            script_pubkey: hex::decode(fixture.source_script_pubkey).unwrap(),
            token: None,
        };
        let target =
            payment_target("BCH", &fixture.amount, "native", None, BchPolicy::default()).unwrap();
        let verified = verify_payment(
            &transaction,
            &[source_output],
            network,
            &pay_to.locking_script(),
            &target,
            BchPolicy::default(),
        )
        .unwrap();

        assert_eq!(verified.txid.to_string(), fixture.txid);
        assert_eq!(verified.payer.to_string(), fixture.payer);
        assert_eq!(verified.fee, fixture.fee.parse::<u64>().unwrap());
        assert_eq!(transaction.serialize().len(), fixture.serialized_size);
    }

    #[test]
    fn verifies_the_shared_two_input_interoperability_fixture() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Fixture {
            network: String,
            amount: String,
            pay_to: String,
            sources: Vec<SourceFixture>,
            raw_transaction: String,
            txid: String,
            serialized_size: usize,
            fee: String,
            payer: String,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SourceFixture {
            value: String,
            #[serde(rename = "scriptPubKey")]
            script_pubkey: String,
        }

        let fixture: Fixture = serde_json::from_str(include_str!(
            "../test/fixtures/bch-exact-p2pkh-two-inputs.json"
        ))
        .unwrap();
        let network =
            BchChainReference::try_from(fixture.network.parse::<ChainId>().unwrap()).unwrap();
        let transaction =
            BchTransaction::parse(&hex::decode(fixture.raw_transaction).unwrap()).unwrap();
        let pay_to = CashAddr::decode(&fixture.pay_to, network).unwrap();
        let sources = fixture
            .sources
            .iter()
            .map(|source| SourceOutput {
                value: source.value.parse().unwrap(),
                script_pubkey: hex::decode(&source.script_pubkey).unwrap(),
                token: None,
            })
            .collect::<Vec<_>>();
        let target =
            payment_target("BCH", &fixture.amount, "native", None, BchPolicy::default()).unwrap();
        let verified = verify_payment(
            &transaction,
            &sources,
            network,
            &pay_to.locking_script(),
            &target,
            BchPolicy::default(),
        )
        .unwrap();

        assert_eq!(transaction.inputs.len(), 2);
        assert_eq!(verified.txid.to_string(), fixture.txid);
        assert_eq!(verified.payer.to_string(), fixture.payer);
        assert_eq!(verified.fee, fixture.fee.parse::<u64>().unwrap());
        assert_eq!(transaction.serialize().len(), fixture.serialized_size);
    }

    #[test]
    fn verifies_the_shared_cash_token_p2sh32_fixture() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Fixture {
            network: String,
            asset: String,
            amount: String,
            #[serde(rename = "value")]
            token_output_value: String,
            pay_to: String,
            source_value: String,
            #[serde(rename = "sourceScriptPubKey")]
            source_script_pubkey: String,
            source_token: TokenFixture,
            raw_transaction: String,
            txid: String,
            serialized_size: usize,
            merchant_token_amount: String,
            change_token_amount: String,
        }

        #[derive(serde::Deserialize)]
        struct TokenFixture {
            category: String,
            amount: String,
        }

        let fixture: Fixture = serde_json::from_str(include_str!(
            "../test/fixtures/bch-exact-cashtoken-p2sh32.json"
        ))
        .unwrap();
        let network =
            BchChainReference::try_from(fixture.network.parse::<ChainId>().unwrap()).unwrap();
        let merchant = CashAddr::decode_script(&fixture.pay_to, network).unwrap();
        assert!(merchant.token_support);
        let transaction =
            BchTransaction::parse(&hex::decode(fixture.raw_transaction).unwrap()).unwrap();
        let category = parse_cash_token_category(&fixture.asset).unwrap();
        assert_eq!(fixture.source_token.category, fixture.asset);
        let target = payment_target(
            &fixture.asset,
            &fixture.amount,
            "cashtoken",
            Some(&fixture.token_output_value),
            BchPolicy::default(),
        )
        .unwrap();
        let verified = verify_payment(
            &transaction,
            &[SourceOutput {
                value: fixture.source_value.parse().unwrap(),
                script_pubkey: hex::decode(fixture.source_script_pubkey).unwrap(),
                token: Some(BchToken {
                    category,
                    amount: fixture.source_token.amount.parse().unwrap(),
                    nft: None,
                }),
            }],
            network,
            &merchant.locking_script(),
            &target,
            BchPolicy::default(),
        )
        .unwrap();

        assert_eq!(verified.txid.to_string(), fixture.txid);
        assert_eq!(transaction.serialize().len(), fixture.serialized_size);
        assert_eq!(
            transaction.outputs[0]
                .token
                .as_ref()
                .unwrap()
                .amount
                .to_string(),
            fixture.merchant_token_amount
        );
        assert_eq!(
            transaction.outputs[1]
                .token
                .as_ref()
                .unwrap()
                .amount
                .to_string(),
            fixture.change_token_amount
        );
    }

    fn signed_p2pkh(
        secp: &Secp256k1<secp256k1::All>,
        secret: &secp256k1::SecretKey,
        public_key: &[u8],
        source: &SourceOutput,
    ) -> BchTransaction {
        let mut transaction = BchTransaction {
            version: 2,
            inputs: vec![TxInput {
                outpoint: OutPoint {
                    txid: TxId([9; 32]),
                    vout: 1,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 1_000,
                script_pubkey: p2pkh_script(&[7; 20]),
                token: None,
            }],
            lock_time: 0,
        };
        let digest = transaction
            .signing_hash(0, source, BCH_SIGHASH_ALL_FORKID)
            .unwrap();
        let mut signature = secp
            .sign_ecdsa(Message::from_digest(digest), secret)
            .serialize_der()
            .to_vec();
        signature.push(BCH_SIGHASH_ALL_FORKID as u8);
        let mut script_sig = push_data(&signature).unwrap();
        script_sig.extend_from_slice(&push_data(public_key).unwrap());
        transaction.inputs[0].script_sig = script_sig;
        transaction
    }

    #[test]
    fn hashes_the_public_key_bytes_from_the_unlocking_script() {
        let secp = Secp256k1::new();
        let secret = secp256k1::SecretKey::from_byte_array([0x11; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret);
        let compressed = public_key.serialize();
        let uncompressed = public_key.serialize_uncompressed();
        assert_ne!(hash160(&compressed), hash160(&uncompressed));

        let uncompressed_source = SourceOutput {
            value: 2_000,
            script_pubkey: p2pkh_script(&hash160(&uncompressed)),
            token: None,
        };
        let uncompressed_tx = signed_p2pkh(&secp, &secret, &uncompressed, &uncompressed_source);
        assert_eq!(
            uncompressed_tx
                .verify_p2pkh_input(0, &uncompressed_source)
                .expect("uncompressed public-key bytes must hash as pushed"),
            hash160(&uncompressed)
        );

        let compressed_source = SourceOutput {
            value: 2_000,
            script_pubkey: p2pkh_script(&hash160(&compressed)),
            token: None,
        };
        let compressed_tx = signed_p2pkh(&secp, &secret, &compressed, &compressed_source);
        assert_eq!(
            compressed_tx
                .verify_p2pkh_input(0, &compressed_source)
                .unwrap(),
            hash160(&compressed)
        );

        let mismatched = signed_p2pkh(&secp, &secret, &uncompressed, &compressed_source);
        assert!(
            mismatched
                .verify_p2pkh_input(0, &compressed_source)
                .is_err(),
            "uncompressed unlocking bytes must not satisfy a compressed P2PKH script"
        );
    }

    #[test]
    fn rejects_script_length_above_32_bit_as_excessive_count() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&2i32.to_le_bytes());
        raw.push(1);
        raw.extend_from_slice(&[0u8; 32]);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        raw.push(1);
        raw.extend_from_slice(&1_000u64.to_le_bytes());
        raw.push(255);
        raw.extend_from_slice(&(u64::from(u32::MAX) + 1).to_le_bytes());
        let error = BchTransaction::parse(&raw).unwrap_err();
        assert!(
            matches!(error, TransactionError::ExcessiveCount),
            "script length above 32 bits must fail closed, got {error:?}"
        );
    }

    #[test]
    fn rejects_input_count_that_would_truncate_on_32_bit() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&2i32.to_le_bytes());
        raw.push(255);
        raw.extend_from_slice(&(u64::from(u32::MAX) + 1).to_le_bytes());
        let error = BchTransaction::parse(&raw).unwrap_err();
        assert!(
            matches!(error, TransactionError::ExcessiveCount),
            "{error:?}"
        );
    }

    #[test]
    fn commitment_codec_accepts_zero_through_128_and_rejects_129() {
        let script = p2pkh_script(&[0x11; 20]);
        for length in [0usize, 40, 41, 128] {
            let token = BchToken {
                category: [0x11; 32],
                amount: 0,
                nft: Some(BchNft {
                    capability: BchTokenCapability::None,
                    commitment: vec![0xab; length],
                }),
            };
            let field = serialize_token_prefix_and_script(Some(&token), &script).unwrap();
            let (parsed, parsed_script) = parse_token_prefix_and_script(&field).unwrap();
            assert_eq!(parsed, Some(token));
            assert_eq!(parsed_script, script);
        }

        let too_long = BchToken {
            category: [0x11; 32],
            amount: 1,
            nft: Some(BchNft {
                capability: BchTokenCapability::Mutable,
                commitment: vec![0xab; 129],
            }),
        };
        assert!(serialize_token_prefix_and_script(Some(&too_long), &script).is_err());

        let mut zero_length = vec![0xef];
        zero_length.extend([0x11u8; 32]);
        zero_length.push(0x60);
        zero_length.push(0x00);
        zero_length.extend_from_slice(&script);
        assert!(parse_token_prefix_and_script(&zero_length).is_err());

        let mut over_limit = vec![0xef];
        over_limit.extend([0x11u8; 32]);
        over_limit.push(0x60);
        over_limit.push(129);
        over_limit.extend(std::iter::repeat_n(0xab, 129));
        over_limit.extend_from_slice(&script);
        assert!(parse_token_prefix_and_script(&over_limit).is_err());

        assert!(
            parse_cash_token_nft(Some("none"), Some(""))
                .unwrap()
                .is_some()
        );
        assert!(parse_cash_token_nft(Some("none"), Some(&"aa".repeat(128))).is_ok());
        assert!(parse_cash_token_nft(Some("none"), Some(&"aa".repeat(129))).is_err());
    }

    #[test]
    fn omitted_token_output_value_tracks_commitment_size() {
        let script = p2pkh_script(&[0x11; 20]);
        let short = omitted_token_output_value(
            &script,
            [0x11; 32],
            0,
            Some(&BchNft {
                capability: BchTokenCapability::None,
                commitment: vec![0xab; 40],
            }),
            BchPolicy::default(),
        )
        .unwrap();
        let long = omitted_token_output_value(
            &script,
            [0x11; 32],
            0,
            Some(&BchNft {
                capability: BchTokenCapability::None,
                commitment: vec![0xab; 128],
            }),
            BchPolicy::default(),
        )
        .unwrap();
        assert_eq!(short, CASHTOKEN_OUTPUT_DUST);
        assert!(long > CASHTOKEN_OUTPUT_DUST);
        let quoted = payment_target_with_nft(
            &hex::encode([0x11u8; 32]),
            "0",
            "cashtoken",
            Some("1000"),
            Some(BchNft {
                capability: BchTokenCapability::None,
                commitment: vec![0xab; 128],
            }),
            &script,
            BchPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            quoted,
            BchPaymentTarget::CashToken {
                category: [0x11; 32],
                amount: 0,
                merchant_value: 1_000,
                nft: Some(BchNft {
                    capability: BchTokenCapability::None,
                    commitment: vec![0xab; 128],
                }),
            }
        );
        let raised = BchPolicy {
            dust_threshold: 5_000,
            ..BchPolicy::default()
        };
        let floored = omitted_token_output_value(&script, [0x11; 32], 1, None, raised).unwrap();
        assert_eq!(floored, 5_000);
    }
    /// P2PKH inputs signed with BCH Schnorr, as wallets such as Electron Cash
    /// do. The vectors are signed with Libauth.
    #[test]
    fn verifies_bch_schnorr_p2pkh_signatures() {
        let source = SourceOutput {
            value: 100_000,
            script_pubkey: hex::decode("76a9142bc6096176ef885673b6ccd4cae63b298c36e0c088ac")
                .unwrap(),
            token: None,
        };
        let merchant = p2pkh_script(&[0x11; 20]);
        let target = payment_target("BCH", "1000", "native", None, BchPolicy::default()).unwrap();
        let verify = |raw: &str| {
            let transaction = BchTransaction::parse(&hex::decode(raw).unwrap()).unwrap();
            verify_payment(
                &transaction,
                std::slice::from_ref(&source),
                BchChainReference::Mainnet,
                &merchant,
                &target,
                BchPolicy::default(),
            )
        };
        let valid = "0200000001f6e0da94cf431a01b230c306a051402cf7ea53b49ed1ad22dfff5b58db2a486a000000006441c5d7260f6feb925a12f7121a0763a12b2c115c9b89157cc481fcbb6141155a025e5a95f30770d6541676488ede2ca9b4ac9cfb063cff20b5d141356921fa9610412102c1aa98aa906b0982db1bcd54e5093de08a6e63697d4ab9d47d68d2c34fdf52b6ffffffff02e8030000000000001976a914111111111111111111111111111111111111111188ace87a0100000000001976a9142bc6096176ef885673b6ccd4cae63b298c36e0c088ac00000000";
        verify(valid).expect("Schnorr P2PKH signature");
        assert!(verify("0200000001f2ce96d57deb4f4f677d7e5256f5a9c0ab5b93f16b3bf39dd6063090fc457296000000006441649c0e9ada9276d83267465d5fac08c2eb75721527d1f8208b8f651374f4c210b7f1178030221038ad63a3e4818b2a4da58229e5c539cda455d7c45de8e49e3b412102c1aa98aa906b0982db1bcd54e5093de08a6e63697d4ab9d47d68d2c34fdf52b6ffffffff02e8030000000000001976a914111111111111111111111111111111111111111188ace87a0100000000001976a9142bc6096176ef885673b6ccd4cae63b298c36e0c088ac00000000").is_err());
        let mut flipped = hex::decode(valid).unwrap();
        flipped[50] ^= 0x01;
        assert!(verify(&hex::encode(flipped)).is_err());
    }
}
