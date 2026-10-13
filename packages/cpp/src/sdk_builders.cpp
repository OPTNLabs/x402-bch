#include "sdk_support.hpp"
#include <algorithm>
#include <regex>
#include <sstream>
namespace x402bch {
using namespace detail;
std::vector<uint8_t> build_and_sign_native_payment(
    const std::vector<Utxo>& selected, const std::vector<uint8_t>& merchant_script,
    uint64_t merchant_value, Signer& signer, const std::string& network,
    uint64_t fee_rate, uint64_t dust_threshold, const std::string& request_hash) {
  if (selected.empty() || selected.size() > 100) throw std::invalid_argument("invalid BCH input count");
  if (merchant_value < dust_threshold) throw std::invalid_argument("merchant output is dust");
  uint64_t input_value = 0;
  std::vector<std::string> source_values;
  std::vector<TransactionInput> inputs;
  for (const auto& utxo : selected) {
    if (std::numeric_limits<uint64_t>::max() - input_value < utxo.value)
      throw std::invalid_argument("input value exceeds u64");
    input_value += utxo.value;
    source_values.push_back(std::to_string(utxo.value));
    inputs.push_back({utxo.txid, utxo.vout, {}, 0xffffffff});
  }
  if (input_value < merchant_value) throw std::invalid_argument("selected BCH UTXOs do not cover payment");
  const auto chain = network == "mainnet" ? "bch:bitcoincash" : (network == "chipnet" ? "bch:bchtest" : network);
  const auto change_address = decode_cash_address(signer.address(network), chain);
  uint64_t change = input_value - merchant_value;
  for (size_t attempt = 0; attempt < 32; ++attempt) {
    const bool include_change = change >= dust_threshold;
    std::vector<TransactionOutput> outputs{{merchant_value, merchant_script, std::nullopt}};
    if (include_change) outputs.push_back({change, change_address.script_pubkey, std::nullopt});
    if (!request_hash.empty()) outputs.push_back({0, request_hash_script(request_hash), std::nullopt});
    Transaction unsigned_transaction{2, inputs, outputs, 0};
    const auto public_key = signer.public_key();
    for (size_t index = 0; index < selected.size(); ++index) {
      const auto digest = signing_hash(unsigned_transaction, index, selected[index].value, selected[index].script_pubkey);
      auto signature = signer.sign_digest(digest);
      signature.push_back(0x41);
      if (signature.size() > 75 || public_key.size() > 75) throw std::invalid_argument("push value is too large");
      std::vector<uint8_t> script_sig{static_cast<uint8_t>(signature.size())};
      script_sig.insert(script_sig.end(), signature.begin(), signature.end());
      script_sig.push_back(static_cast<uint8_t>(public_key.size()));
      script_sig.insert(script_sig.end(), public_key.begin(), public_key.end());
      unsigned_transaction.inputs[index].script_sig = std::move(script_sig);
    }
    const auto raw = serialize_transaction(unsigned_transaction);
    if (raw.size() > std::numeric_limits<uint64_t>::max() / fee_rate)
      throw std::invalid_argument("required fee exceeds u64");
    const auto required_fee = static_cast<uint64_t>(raw.size()) * fee_rate;
    const auto available = input_value - merchant_value;
    if (!include_change) {
      if (available < required_fee) throw std::invalid_argument("selected BCH UTXOs do not cover fee");
      verify_native_payment(unsigned_transaction, source_values, std::to_string(merchant_value), bytes_to_hex(merchant_script), fee_rate, dust_threshold);
      return raw;
    }
    if (available < required_fee) throw std::invalid_argument("selected BCH UTXOs do not cover fee");
    const auto desired_change = available - required_fee;
    if (desired_change < dust_threshold) { change = 0; continue; }
    if (change > desired_change) { change = desired_change; continue; }
    verify_native_payment(unsigned_transaction, source_values, std::to_string(merchant_value), bytes_to_hex(merchant_script), fee_rate, dust_threshold);
    return raw;
  }
  throw std::invalid_argument("BCH fee/change calculation did not converge");
}

std::vector<uint8_t> build_and_sign_cash_token_payment(
    const std::vector<Utxo>& selected, const std::vector<uint8_t>& merchant_script,
    uint64_t merchant_value, uint64_t token_amount, const std::string& category,
    const std::string& merchant_capability, const std::vector<uint8_t>& merchant_commitment,
    Signer& signer, const std::string& network, uint64_t fee_rate, uint64_t dust_threshold,
    const std::string& request_hash) {
  if (selected.empty() || !std::regex_match(category, std::regex("[0-9a-fA-F]{64}")))
    throw std::invalid_argument("invalid CashToken payment");
  uint64_t input_value = 0, source_amount = 0;
  std::vector<std::string> source_values;
  std::vector<CashToken> source_tokens;
  std::vector<TransactionInput> inputs;
  for (const auto& utxo : selected) {
    if (utxo.token.has_value() && utxo.token->category != category)
      throw std::invalid_argument("selected UTXOs do not contain the requested CashToken");
    if (std::numeric_limits<uint64_t>::max() - input_value < utxo.value) throw std::invalid_argument("input value exceeds u64");
    input_value += utxo.value;
    const CashToken source_token = utxo.token.value_or(CashToken{category, 0, "none", {}});
    if (std::numeric_limits<uint64_t>::max() - source_amount < source_token.amount) throw std::invalid_argument("CashToken amount exceeds u64");
    source_amount += source_token.amount;
    source_values.push_back(std::to_string(utxo.value)); source_tokens.push_back(source_token);
    inputs.push_back({utxo.txid, utxo.vout, {}, 0xffffffff});
  }
  if (source_amount < token_amount || input_value < merchant_value)
    throw std::invalid_argument("selected UTXOs do not cover CashToken payment");
  const auto chain = network == "mainnet" ? "bch:bitcoincash" : (network == "chipnet" ? "bch:bchtest" : network);
  const auto change_address = decode_cash_address(signer.address(network), chain);
  uint64_t change_value = input_value - merchant_value, token_change = source_amount - token_amount;
  for (size_t attempt = 0; attempt < 32; ++attempt) {
    if (token_change > 0 && change_value < dust_threshold) throw std::invalid_argument("CashToken change requires dust-valued BCH output");
    std::vector<TransactionOutput> outputs{{merchant_value, merchant_script, CashToken{category, token_amount, merchant_capability.empty() ? "none" : merchant_capability, merchant_commitment}}};
    if (token_change > 0) outputs.push_back({change_value, change_address.script_pubkey, CashToken{category, token_change, "none", {}}});
    if (!request_hash.empty()) outputs.push_back({0, request_hash_script(request_hash), std::nullopt});
    Transaction transaction{2, inputs, outputs, 0};
    const auto public_key = signer.public_key();
    for (size_t index = 0; index < selected.size(); ++index) {
      const auto digest = signing_hash(transaction, index, selected[index].value, selected[index].script_pubkey);
      auto signature = signer.sign_digest(digest); signature.push_back(0x41);
      if (signature.size() > 75 || public_key.size() > 75) throw std::invalid_argument("push value is too large");
      std::vector<uint8_t> script_sig{static_cast<uint8_t>(signature.size())}; script_sig.insert(script_sig.end(), signature.begin(), signature.end());
      script_sig.push_back(static_cast<uint8_t>(public_key.size())); script_sig.insert(script_sig.end(), public_key.begin(), public_key.end());
      transaction.inputs[index].script_sig = std::move(script_sig);
    }
    const auto raw = serialize_transaction(transaction);
    if (raw.size() > std::numeric_limits<uint64_t>::max() / fee_rate) throw std::invalid_argument("required fee exceeds u64");
    const auto required_fee = static_cast<uint64_t>(raw.size()) * fee_rate;
    const auto available = input_value - merchant_value;
    if (available < required_fee) throw std::invalid_argument("selected BCH UTXOs do not cover fee");
    auto desired = available - required_fee;
    if (token_change == 0 && desired < 546) desired = 0;
    if (token_change > 0 && desired < dust_threshold) throw std::invalid_argument("selected BCH UTXOs do not cover token change dust");
    if (change_value > desired) { change_value = desired; continue; }
    verify_cash_token_payment(transaction, source_values, source_tokens, std::to_string(merchant_value), bytes_to_hex(merchant_script), category, std::to_string(token_amount), merchant_capability, merchant_commitment, fee_rate, dust_threshold);
    return raw;
  }
  throw std::invalid_argument("BCH fee/change calculation did not converge");
}

}
