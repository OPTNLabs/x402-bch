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
        v2::PriceTag {
            requirements: v2::PaymentRequirements {
                scheme: ExactScheme.to_string(),
                network: ChainId::from(network),
                amount: amount.to_string(),
                pay_to: pay_to.into(),
                max_timeout_seconds: 300,
                asset: "BCH".to_string(),
                extra: Some(
                    serde_json::to_value(BchExtra::default()).expect("BCH extra is serializable"),
                ),
            },
            enricher: Some(Arc::new(
                |price_tag: &mut v2::PriceTag, _supported: &proto::SupportedResponse| {
                    if price_tag.requirements.extra.is_none() {
                        price_tag.requirements.extra = Some(
                            serde_json::to_value(BchExtra::default())
                                .expect("BCH extra is serializable"),
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
        Self::cash_token_nft_price_tag(
            pay_to,
            category,
            amount,
            None,
            token_output_value,
            network,
            BchPolicy::default(),
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
