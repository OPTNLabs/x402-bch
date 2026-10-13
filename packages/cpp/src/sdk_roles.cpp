#include "sdk_support.hpp"
#include <algorithm>
#include <regex>
#include <sstream>
namespace x402bch {
using namespace detail;
std::string InMemorySettlementStore::claim(const std::string& txid, const std::string& binding) {
  std::lock_guard lock(mutex_);
  auto found = records_.find(txid);
  if (found == records_.end()) {
    records_.emplace(txid, Record{binding, false});
    return "acquired";
  }
  return found->second.binding == binding ? "same" : "conflict";
}

void InMemorySettlementStore::mark_accepted(const std::string& txid) {
  std::lock_guard lock(mutex_);
  auto found = records_.find(txid);
  if (found != records_.end()) found->second.accepted = true;
}

void InMemorySettlementStore::release(const std::string& txid) {
  std::lock_guard lock(mutex_);
  auto found = records_.find(txid);
  if (found != records_.end() && !found->second.accepted) records_.erase(found);
}

VerifyResponse ExactBchFacilitator::verify(const PaymentPayload& payload,
                                           const Requirements& requirements) const {
  try {
    const auto result = verify_payment(payload, requirements, true);
    return {true, result.txid, {}};
  } catch (const std::exception& error) {
    return {false, {}, std::string("invalid_exact_bch_payment:") + error.what()};
  }
}

PaymentVerification ExactBchFacilitator::verify_payment(const PaymentPayload& payload,
                                                        const Requirements& requirements,
                                                        bool require_unspent) const {
  validate_payment_payload(payload, requirements);
  const auto transaction = parse_transaction(payload.transaction);
  if (!requirements.request_hash.empty()) assert_request_hash_commitment(transaction, requirements.request_hash);
  const auto merchant = decode_cash_address(requirements.pay_to, requirements.network);
  std::vector<std::string> source_values;
  std::vector<CashToken> source_tokens;
  source_values.reserve(transaction.inputs.size());
  source_tokens.reserve(transaction.inputs.size());
  for (const auto& input : transaction.inputs) {
    const auto source = provider_.source_output(input.txid, input.vout);
    if (require_unspent && provider_.outpoint_status(input.txid, input.vout) != "unspent")
      throw std::invalid_argument("source output is not unspent");
    source_values.push_back(std::to_string(source.value));
    if (requirements.asset_transfer_method == "cashtoken")
      source_tokens.push_back(source.token.value_or(CashToken{requirements.asset, 0, "none", {}}));
  }
  if (requirements.asset_transfer_method == "cashtoken") {
    if (source_tokens.size() != transaction.inputs.size())
      throw std::invalid_argument("CashToken source state is required");
    return verify_cash_token_payment(
        transaction, source_values, source_tokens,
        requirements.token_value.empty() ? "1000" : requirements.token_value,
        bytes_to_hex(merchant.script_pubkey), requirements.asset, requirements.amount,
        requirements.token_capability.empty() ? "none" : requirements.token_capability,
        requirements.token_commitment, 1, 1000);
  }
  return verify_native_payment(transaction, source_values, requirements.amount,
                               bytes_to_hex(merchant.script_pubkey), 1, 546);
}

bool ExactBchFacilitator::accepted(const std::string& txid, const std::string& strategy,
                                   uint64_t confirmations) const {
  const auto status = provider_.transaction_status(txid);
  if (strategy == "mempool") return status.kind == "mempool" || status.kind == "confirmed";
  if (strategy == "noDoubleSpendProof")
    return status.kind == "confirmed" ||
           (status.kind == "mempool" && !provider_.has_double_spend_proof(txid));
  if (status.kind != "confirmed") return false;
  const auto tip = provider_.tip_height();
  return confirmations >= 1 && tip >= status.height && tip - status.height + 1 >= confirmations;
}

SettleResponse ExactBchFacilitator::settle(const PaymentPayload& payload,
                                           const Requirements& requirements,
                                           const std::string& strategy,
                                           uint64_t confirmations) {
  try {
    const auto candidate = transaction_id(payload.transaction);
    // Chain/provider bytes are authoritative for retries. If this txid is
    // already observed, validate those bytes and skip rebroadcasting it.
    if (const auto observed = provider_.transaction(candidate); observed.has_value() &&
        provider_transaction_matches(candidate, *observed)) {
      auto observed_payload = payload;
      observed_payload.transaction = encode_base64(*observed);
      verify_payment(observed_payload, requirements, false);
      if (accepted(candidate, strategy, confirmations)) {
        store_.mark_accepted(candidate);
        return {true, candidate, {}};
      }
    }
    const auto binding = requirements.network + "|" + requirements.pay_to + "|" + requirements.amount + "|" + requirements.asset;
    const auto claim = store_.claim(candidate, binding);
    if (claim == "conflict") return {false, candidate, "transaction_already_claimed_for_another_request"};
    if (claim == "same") {
      if (!accepted(candidate, strategy, confirmations))
        return {false, candidate, "settlement_pending"};
      store_.mark_accepted(candidate);
      return {true, candidate, {}};
    }
    const auto verified = verify_payment(payload, requirements, true);
    const auto raw = decode_base64(payload.transaction);
    const auto broadcast_id = provider_.broadcast(raw);
    auto normalized_broadcast = broadcast_id;
    auto normalized_candidate = candidate;
    std::transform(normalized_broadcast.begin(), normalized_broadcast.end(), normalized_broadcast.begin(),
                   [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    std::transform(normalized_candidate.begin(), normalized_candidate.end(), normalized_candidate.begin(),
                   [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    if (normalized_broadcast != normalized_candidate)
      return {false, broadcast_id, "broadcast_returned_mismatched_txid"};
    if (!accepted(candidate, strategy, confirmations)) return {false, candidate, "settlement_pending"};
    store_.mark_accepted(candidate);
    return {true, verified.txid, {}};
  } catch (const std::exception& error) {
    return {false, {}, std::string("invalid_exact_bch_payment:") + error.what()};
  }
}

}
