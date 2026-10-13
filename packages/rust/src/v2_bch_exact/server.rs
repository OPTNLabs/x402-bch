//! Server-side price requirements for native BCH exact payments.

use std::sync::Arc;
use x402_types::chain::ChainId;
use x402_types::proto;
use x402_types::proto::v2;

use crate::address::CashAddr;
use crate::chain::BchChainReference;
use crate::transaction::{BchNft, BchPolicy, BchTokenCapability};
use crate::v2_bch_exact::V2BchExact;
use crate::v2_bch_exact::types::{BchExtra, BchNftRequest, BchTokenRequest, ExactScheme};

pub type BchPaymentRequirements = v2::PaymentRequirements;

impl V2BchExact {
    pub fn price_tag(
        pay_to: impl Into<String>,
        amount: u64,
        network: BchChainReference,
    ) -> v2::PriceTag {
        Self::price_tag_with_request_hash(pay_to, amount, network, None)
    }

    /// Build a native BCH price with an optional canonical-request commitment.
    pub fn price_tag_with_request_hash(
        pay_to: impl Into<String>,
        amount: u64,
        network: BchChainReference,
        request_hash: Option<String>,
    ) -> v2::PriceTag {
        let extra = BchExtra {
            request_hash,
            ..BchExtra::default()
        };
        v2::PriceTag {
            requirements: v2::PaymentRequirements {
                scheme: ExactScheme.to_string(),
                network: ChainId::from(network),
                amount: amount.to_string(),
                pay_to: pay_to.into(),
                max_timeout_seconds: 300,
                asset: "BCH".to_string(),
                extra: Some(
                    serde_json::to_value(extra.clone()).expect("BCH extra is serializable"),
                ),
            },
            enricher: Some(Arc::new(
                move |price_tag: &mut v2::PriceTag, _supported: &proto::SupportedResponse| {
                    if price_tag.requirements.extra.is_none() {
                        price_tag.requirements.extra = Some(
                            serde_json::to_value(extra.clone()).expect("BCH extra is serializable"),
                        );
                    }
                },
            )),
        }
    }

    /// Build a fungible CashToken price.
    ///
    /// An omitted `extra.value` advertises the size-aware default for
    /// `pay_to` under [`BchPolicy::default`]: at least 1,000 satoshis, the
    /// policy dust threshold, and the output's standard relay dust. An
    /// explicit value is preserved, including a value that is too small to relay.
    pub fn cash_token_price_tag(
        pay_to: impl Into<String>,
        category: impl Into<String>,
        amount: u64,
        token_output_value: Option<u64>,
        network: BchChainReference,
    ) -> v2::PriceTag {
        Self::cash_token_nft_price_tag_with_request_hash(
            pay_to,
            category,
            amount,
            None,
            token_output_value,
            network,
            BchPolicy::default(),
            None,
        )
    }

    /// Build a fungible CashToken price with an optional request commitment.
    pub fn cash_token_price_tag_with_request_hash(
        pay_to: impl Into<String>,
        category: impl Into<String>,
        amount: u64,
        token_output_value: Option<u64>,
        network: BchChainReference,
        request_hash: Option<String>,
    ) -> v2::PriceTag {
        Self::cash_token_nft_price_tag_with_request_hash(
            pay_to,
            category,
            amount,
            None,
            token_output_value,
            network,
            BchPolicy::default(),
            request_hash,
        )
    }

    /// Build a CashToken price that may carry an NFT.
    ///
    /// `policy.dust_threshold` participates in the omitted-value default.
    /// Pass `Some(value)` to keep an explicit quote unchanged.
    pub fn cash_token_nft_price_tag(
        pay_to: impl Into<String>,
        category: impl Into<String>,
        amount: u64,
        nft: Option<BchNft>,
        token_output_value: Option<u64>,
        network: BchChainReference,
        policy: BchPolicy,
    ) -> v2::PriceTag {
        Self::cash_token_nft_price_tag_with_request_hash(
            pay_to,
            category,
            amount,
            nft,
            token_output_value,
            network,
            policy,
            None,
        )
    }

    /// Build a CashToken price with optional NFT state and request commitment.
    pub fn cash_token_nft_price_tag_with_request_hash(
        pay_to: impl Into<String>,
        category: impl Into<String>,
        amount: u64,
        nft: Option<BchNft>,
        token_output_value: Option<u64>,
        network: BchChainReference,
        policy: BchPolicy,
        request_hash: Option<String>,
    ) -> v2::PriceTag {
        let pay_to = pay_to.into();
        let category = category.into();
        let sized = crate::transaction::parse_cash_token_category(&category)
            .ok()
            .and_then(|category_bytes| {
                let script = CashAddr::decode_script(&pay_to, network)
                    .ok()?
                    .locking_script();
                crate::transaction::omitted_token_output_value(
                    &script,
                    category_bytes,
                    amount,
                    nft.as_ref(),
                    policy,
                )
                .ok()
            });
        let value = token_output_value.unwrap_or_else(|| {
            sized.unwrap_or_else(|| {
                policy
                    .dust_threshold
                    .max(crate::transaction::CASHTOKEN_OUTPUT_DUST)
            })
        });
        let nft_request = nft.map(|nft| BchNftRequest {
            capability: match nft.capability {
                BchTokenCapability::None => "none",
                BchTokenCapability::Mutable => "mutable",
                BchTokenCapability::Minting => "minting",
            }
            .to_string(),
            commitment: hex::encode(nft.commitment),
        });
        let extra = BchExtra {
            asset_transfer_method: "cashtoken".to_string(),
            payment_flow: "upfront".to_string(),
            request_hash,
            token_output_value: Some(value.to_string()),
            token: Some(BchTokenRequest {
                category: category.clone(),
                amount: amount.to_string(),
                nft: nft_request,
            }),
        };
        v2::PriceTag {
            requirements: v2::PaymentRequirements {
                scheme: ExactScheme.to_string(),
                network: ChainId::from(network),
                amount: amount.to_string(),
                pay_to,
                max_timeout_seconds: 300,
                asset: category,
                extra: Some(serde_json::to_value(&extra).expect("BCH extra is serializable")),
            },
            enricher: Some(Arc::new(move |price_tag: &mut v2::PriceTag, _supported| {
                if price_tag.requirements.extra.is_none() {
                    price_tag.requirements.extra =
                        Some(serde_json::to_value(&extra).expect("BCH extra is serializable"));
                }
            })),
        }
    }

    pub fn validate_price_tag(
        requirements: &v2::PaymentRequirements,
    ) -> Result<(), crate::address::CashAddrError> {
        let network = BchChainReference::try_from(requirements.network.clone()).map_err(|_| {
            crate::address::CashAddrError::UnsupportedPrefix(requirements.network.to_string())
        })?;
        CashAddr::decode_script(&requirements.pay_to, network).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn server_requirements_cover_the_shared_role_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../spec/conformance/v1/server-requirements.json"
        ))
        .unwrap();
        assert_eq!(fixture["version"], 1);
        assert_eq!(fixture["cases"].as_array().unwrap().len(), 4);
        for id in [
            "native-default",
            "native-request-hash",
            "fungible-cashtoken-explicit-value",
            "nft-only-cashtoken",
        ] {
            assert!(
                fixture["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|case| case["id"] == id)
            );
        }

        let native = V2BchExact::price_tag_with_request_hash(
            "bchtest:merchant",
            1000,
            BchChainReference::CHIPNET,
            None,
        )
        .requirements;
        assert_eq!(native.scheme, "exact");
        assert_eq!(native.network.to_string(), "bch:bchtest");
        assert_eq!(native.amount, "1000");
        assert_eq!(native.asset, "BCH");
        assert_eq!(native.pay_to, "bchtest:merchant");
        assert_eq!(native.max_timeout_seconds, 300);
        assert_eq!(native.extra.unwrap()["assetTransferMethod"], "native");

        let nft = BchNft {
            capability: BchTokenCapability::None,
            commitment: vec![0x5a, 0x5a, 0x5a, 0x5a],
        };
        let token = V2BchExact::cash_token_nft_price_tag_with_request_hash(
            "bchtest:tokenmerchant",
            "2222222222222222222222222222222222222222222222222222222222222222",
            0,
            Some(nft),
            Some(1000),
            BchChainReference::CHIPNET,
            BchPolicy::default(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        )
        .requirements;
        let extra = token.extra.unwrap();
        assert_eq!(token.scheme, "exact");
        assert_eq!(
            token.asset,
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
        assert_eq!(extra["assetTransferMethod"], "cashtoken");
        assert_eq!(extra["value"], "1000");
        assert_eq!(
            extra["requestHash"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(extra["token"]["amount"], "0");
        assert_eq!(extra["token"]["nft"]["commitment"], "5a5a5a5a");
    }

    #[test]
    fn sdk_lifecycle_fixture_has_a_parseable_wallet_transaction() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../spec/conformance/v1/sdk-lifecycle.json"))
                .unwrap();
        assert_eq!(fixture["version"], 1);
        assert_eq!(fixture["walletRequest"]["network"], "mainnet");
        assert_eq!(fixture["walletRequest"]["value"], "1000");
        assert!(fixture["settlement"]["accepted"].as_bool().unwrap());
        let encoded = fixture["transaction"]["base64"].as_str().unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let transaction = crate::transaction::BchTransaction::parse(&raw).unwrap();
        assert_eq!(transaction.inputs.len(), 1);
        assert_eq!(transaction.outputs.len(), 2);
    }
}
