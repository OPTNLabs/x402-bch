#include "sdk_support.hpp"
#include <algorithm>

namespace x402bch {
using namespace detail;

TransactionRequest to_transaction_request(const Requirements& requirements) {
  validate_requirements(requirements);
  TransactionRequest request{
      requirements.network == "bch:bitcoincash" ? "mainnet" : "chipnet",
      requirements.pay_to,
      requirements.asset_transfer_method == "cashtoken" ? requirements.token_value : requirements.amount,
      requirements.asset,
      requirements.asset_transfer_method == "cashtoken" ? requirements.amount : "",
      std::nullopt,
      requirements.request_hash};
  if (requirements.asset_transfer_method == "cashtoken") {
    request.token = CashToken{
        requirements.token_category.empty() ? requirements.asset : requirements.token_category,
        canonical_uint(requirements.token_amount.empty() ? requirements.amount : requirements.token_amount,
                       "CashToken amount"),
        requirements.token_capability.empty() ? "none" : requirements.token_capability,
        requirements.token_commitment};
  }
  return request;
}

namespace {
void verify_wallet_payment(const PaymentPayload& payload, const Requirements& requirements,
                           Provider& provider) {
  validate_payment_payload(payload, requirements);
  const auto transaction = parse_transaction(payload.transaction);
  const auto merchant = decode_cash_address(requirements.pay_to, requirements.network);
  std::vector<std::string> source_values;
  std::vector<CashToken> source_tokens;
  source_values.reserve(transaction.inputs.size());
  source_tokens.reserve(transaction.inputs.size());
  for (const auto& input : transaction.inputs) {
    const auto source = provider.source_output(input.txid, input.vout);
    source_values.push_back(std::to_string(source.value));
    if (requirements.asset_transfer_method == "cashtoken") {
      source_tokens.push_back(source.token.value_or(CashToken{requirements.asset, 0, "none", {}}));
    }
  }
  if (!requirements.request_hash.empty()) assert_request_hash_commitment(transaction, requirements.request_hash);
  if (requirements.asset_transfer_method == "cashtoken") {
    verify_cash_token_payment(transaction, source_values, source_tokens,
                             requirements.token_value.empty() ? "1000" : requirements.token_value,
                             bytes_to_hex(merchant.script_pubkey), requirements.asset,
                             requirements.token_amount.empty() ? requirements.amount : requirements.token_amount,
                             requirements.token_capability.empty() ? "none" : requirements.token_capability,
                             requirements.token_commitment, 1, 1000);
  } else {
    verify_native_payment(transaction, source_values, requirements.amount,
                          bytes_to_hex(merchant.script_pubkey), 1, 546);
  }
}
}  // namespace

PaymentPayload ExactBchClient::create_payment_payload(const Requirements& requirements) const {
  const auto request = to_transaction_request(requirements);
  const auto raw = wallet_.create_payment(request);
  if (raw.empty()) throw std::invalid_argument("wallet returned empty transaction");
  const auto encoded = encode_base64(raw);
  const PaymentPayload payload{2, encoded, requirements};
  verify_wallet_payment(payload, requirements, provider_);
  return payload;
}

PaymentPayload ExactBchSignerClient::create_payment_payload(const Requirements& requirements) const {
  validate_requirements(requirements);
  const auto merchant = decode_cash_address(requirements.pay_to, requirements.network);
  const auto payer_address = signer_.address(requirements.network);
  const auto payer = decode_cash_address(payer_address, requirements.network);
  if (requirements.asset != "BCH" && !merchant.token_support)
    throw std::invalid_argument("CashToken payments require a token-support merchant CashAddr");
  auto candidates = provider_.list_utxos(payer_address);
  candidates.erase(std::remove_if(candidates.begin(), candidates.end(), [&](const Utxo& utxo) {
    if (utxo.script_pubkey != payer.script_pubkey) return true;
    if (requirements.asset == "BCH") return utxo.token.has_value();
    return utxo.token.has_value() && utxo.token->category != requirements.asset;
  }), candidates.end());
  std::sort(candidates.begin(), candidates.end(), [](const Utxo& left, const Utxo& right) {
    return left.value > right.value;
  });
  if (candidates.empty()) throw std::invalid_argument("no compatible BCH UTXOs available");
  const bool is_token = requirements.asset != "BCH";
  const auto merchant_value = canonical_uint(is_token ? requirements.token_value : requirements.amount,
                                             "merchant value");
  const auto token_amount = is_token ? canonical_uint(requirements.token_amount.empty() ? requirements.amount : requirements.token_amount,
                                                       "CashToken amount") : 0;
  std::vector<Utxo> selected;
  uint64_t value = 0, tokens = 0;
  for (const auto& utxo : candidates) {
    selected.push_back(utxo);
    if (std::numeric_limits<uint64_t>::max() - value < utxo.value) throw std::invalid_argument("input value exceeds u64");
    value += utxo.value;
    if (utxo.token.has_value()) tokens += utxo.token->amount;
    if (value >= merchant_value && (!is_token || tokens >= token_amount)) break;
  }
  if (value < merchant_value || (is_token && tokens < token_amount))
    throw std::invalid_argument("insufficient BCH/CashToken UTXOs for payment and fee");
  const auto request_hash = requirements.request_hash;
  std::vector<uint8_t> raw;
  if (is_token) {
    raw = build_and_sign_cash_token_payment(
        selected, merchant.script_pubkey, merchant_value, token_amount, requirements.asset,
        requirements.token_capability, requirements.token_commitment, signer_,
        requirements.network, fee_rate_, std::max<uint64_t>(1000, dust_threshold_), request_hash);
  } else {
    raw = build_and_sign_native_payment(
        selected, merchant.script_pubkey, merchant_value, signer_, requirements.network,
        fee_rate_, dust_threshold_, request_hash);
  }
  class FixedWallet final : public Wallet {
   public:
    explicit FixedWallet(std::vector<uint8_t> raw) : raw_(std::move(raw)) {}
    std::vector<uint8_t> create_payment(const TransactionRequest&) override { return raw_; }
   private:
    std::vector<uint8_t> raw_;
  } wallet(std::move(raw));
  return ExactBchClient(wallet, provider_).create_payment_payload(requirements);
}

}  // namespace x402bch
