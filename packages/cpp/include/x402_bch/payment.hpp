#pragma once
#include "crypto.hpp"
namespace x402bch {
inline std::vector<uint8_t> signing_hash(const Transaction& transaction, size_t input_index, uint64_t source_value, const std::vector<uint8_t>& source_script) {
  if (input_index >= transaction.inputs.size()) throw std::invalid_argument("invalid input index"); const auto& input = transaction.inputs[input_index]; std::vector<uint8_t> prevouts, sequences, outputs; for (const auto& candidate : transaction.inputs) { auto txid = hex_to_bytes(candidate.txid); if (txid.size() != 32) throw std::invalid_argument("input txid must be 32-byte hexadecimal"); std::reverse(txid.begin(), txid.end()); prevouts.insert(prevouts.end(), txid.begin(), txid.end()); append_little_endian(prevouts, candidate.vout, 4); append_little_endian(sequences, candidate.sequence, 4); } auto txid = hex_to_bytes(input.txid); std::reverse(txid.begin(), txid.end()); for (const auto& output : transaction.outputs) { append_little_endian(outputs, output.value, 8); auto field = encode_token_prefix(output.token); field.insert(field.end(), output.script_pubkey.begin(), output.script_pubkey.end()); append_compact_size(outputs, field.size()); outputs.insert(outputs.end(), field.begin(), field.end()); } std::vector<uint8_t> preimage; append_little_endian(preimage, static_cast<uint32_t>(transaction.version), 4); const auto prevout_hash = double_sha256_bytes(prevouts); preimage.insert(preimage.end(), prevout_hash.begin(), prevout_hash.end()); const auto sequence_hash = double_sha256_bytes(sequences); preimage.insert(preimage.end(), sequence_hash.begin(), sequence_hash.end()); preimage.insert(preimage.end(), txid.begin(), txid.end()); append_little_endian(preimage, input.vout, 4); append_compact_size(preimage, source_script.size()); preimage.insert(preimage.end(), source_script.begin(), source_script.end()); append_little_endian(preimage, source_value, 8); append_little_endian(preimage, input.sequence, 4); const auto output_hash = double_sha256_bytes(outputs); preimage.insert(preimage.end(), output_hash.begin(), output_hash.end()); append_little_endian(preimage, transaction.locktime, 4); append_little_endian(preimage, 0x41, 4); return double_sha256_bytes(preimage);
}

inline std::vector<uint8_t> verify_p2pkh_input(const Transaction& transaction, size_t input_index, uint64_t source_value, const std::vector<uint8_t>& source_script) {
  if (source_script.size() != 25 || source_script[0] != 0x76 || source_script[1] != 0xa9 || source_script[2] != 0x14 || source_script[23] != 0x88 || source_script[24] != 0xac) throw std::invalid_argument("source output is not P2PKH"); if (input_index >= transaction.inputs.size()) throw std::invalid_argument("invalid input index"); const auto& script = transaction.inputs[input_index].script_sig; if (script.size() < 2) throw std::invalid_argument("invalid P2PKH scriptSig"); const size_t signature_length = script[0]; if (signature_length < 2 || signature_length > 75 || 1 + signature_length >= script.size()) throw std::invalid_argument("invalid P2PKH scriptSig"); const size_t public_key_length_index = 1 + signature_length; if (script[public_key_length_index] != 33 || public_key_length_index + 34 != script.size()) throw std::invalid_argument("invalid P2PKH scriptSig"); std::vector<uint8_t> signature(script.begin() + 1, script.begin() + static_cast<std::ptrdiff_t>(public_key_length_index)); std::vector<uint8_t> public_key(script.begin() + static_cast<std::ptrdiff_t>(public_key_length_index + 1), script.end()); if (signature.back() != 0x41) throw std::invalid_argument("unsupported BCH sighash type");
  const auto payer_hash = hash160(public_key); if (!std::equal(payer_hash.begin(), payer_hash.end(), source_script.begin() + 3)) throw std::invalid_argument("P2PKH public key does not match source output"); signature.pop_back(); const auto [r, s] = parse_der_signature(signature); if (!verify_secp_ecdsa(signing_hash(transaction, input_index, source_value, source_script), r, s, decode_secp_public_key(public_key))) throw std::invalid_argument("invalid signature"); return payer_hash;
}

inline std::string transaction_id_from_raw(const std::vector<uint8_t>& raw) {
  if (raw.empty()) throw std::invalid_argument("transaction must be non-empty");
  const auto first_hex = request_hash(std::string(raw.begin(), raw.end()));
  std::vector<uint8_t> first = hex_to_bytes(first_hex);
  const auto second_hex = request_hash(std::string(first.begin(), first.end()));
  std::string result;
  for (size_t index = second_hex.size(); index > 0; index -= 2) result.append(second_hex.substr(index - 2, 2));
  return result;
}

inline uint64_t canonical_uint(const std::string& value, const std::string& label) {
  if (!std::regex_match(value, std::regex("(0|[1-9][0-9]*)"))) throw std::invalid_argument(label + " must be canonical unsigned units");
  try { return std::stoull(value); } catch (...) { throw std::invalid_argument(label + " exceeds u64"); }
}

inline PaymentVerification verify_native_payment(const Transaction& transaction, const std::vector<std::string>& source_values, const std::string& merchant_value, const std::string& merchant_script_hex, uint64_t fee_rate, uint64_t dust_threshold) {
  if (source_values.size() != transaction.inputs.size()) throw std::invalid_argument("source output count mismatch");
  if (transaction.locktime != 0) throw std::invalid_argument("non-zero locktime is unsupported");
  const auto merchant_amount = canonical_uint(merchant_value, "merchant value"); const auto merchant_script = hex_to_bytes(merchant_script_hex);
  uint64_t input_value = 0;
  for (const auto& source : source_values) { const auto value = canonical_uint(source, "source value"); if (std::numeric_limits<uint64_t>::max() - input_value < value) throw std::invalid_argument("input value exceeds u64"); input_value += value; }
  size_t merchant_matches = 0;
  for (const auto& output : transaction.outputs) if (output.value == merchant_amount && output.script_pubkey == merchant_script) merchant_matches++;
  if (merchant_matches != 1) throw std::invalid_argument("merchant output must match exactly once");
  uint64_t output_value = 0;
  for (const auto& output : transaction.outputs) { if (output.token.has_value()) throw std::invalid_argument("native BCH payment contains CashTokens"); if ((output.script_pubkey.empty() || output.script_pubkey[0] != 0x6a) && output.value < dust_threshold) throw std::invalid_argument("transaction output is dust"); if (std::numeric_limits<uint64_t>::max() - output_value < output.value) throw std::invalid_argument("output value exceeds u64"); output_value += output.value; }
  if (output_value > input_value) throw std::invalid_argument("transaction outputs exceed inputs");
  const auto raw = serialize_transaction(transaction); const auto fee = input_value - output_value;
  if (fee_rate != 0 && (raw.size() > std::numeric_limits<uint64_t>::max() / fee_rate || fee < raw.size() * fee_rate)) throw std::invalid_argument("transaction fee is below the required BCH fee rate");
  for (const auto& output : transaction.outputs) if (output.script_pubkey == merchant_script && output.value != merchant_amount) throw std::invalid_argument("duplicate merchant output");
  return {transaction_id_from_raw(raw), std::to_string(fee), raw.size()};
}

inline std::string nft_key(const CashToken& token) { return token.capability + ":" + bytes_to_hex(token.commitment); }

inline PaymentVerification verify_cash_token_payment(const Transaction& transaction, const std::vector<std::string>& source_values, const std::vector<CashToken>& source_tokens, const std::string& merchant_value, const std::string& merchant_script_hex, const std::string& category, const std::string& amount, const std::string& merchant_capability, const std::vector<uint8_t>& merchant_commitment, uint64_t fee_rate, uint64_t dust_threshold) {
  if (source_values.size() != transaction.inputs.size() || source_tokens.size() != transaction.inputs.size()) throw std::invalid_argument("source output count mismatch");
  if (transaction.locktime != 0) throw std::invalid_argument("non-zero locktime is unsupported");
  if (!std::regex_match(category, std::regex("[0-9a-fA-F]{64}"))) throw std::invalid_argument("CashToken category must be 32-byte hexadecimal");
  const auto merchant_amount = canonical_uint(merchant_value, "merchant value"); const auto target_amount = canonical_uint(amount, "CashToken amount"); const auto merchant_script = hex_to_bytes(merchant_script_hex); uint64_t input_value = 0; uint64_t source_amount = 0; std::map<std::string, size_t> source_nfts;
  for (size_t index = 0; index < source_values.size(); index++) { const auto value = canonical_uint(source_values[index], "source value"); if (std::numeric_limits<uint64_t>::max() - input_value < value) throw std::invalid_argument("input value exceeds u64"); input_value += value; if (source_tokens[index].category != category) throw std::invalid_argument("CashToken source category mismatch"); if (std::numeric_limits<uint64_t>::max() - source_amount < source_tokens[index].amount) throw std::invalid_argument("CashToken amount exceeds u64"); source_amount += source_tokens[index].amount; if (source_tokens[index].capability != "none" || !source_tokens[index].commitment.empty()) source_nfts[nft_key(source_tokens[index])]++; }
  uint64_t output_amount = 0; uint64_t output_value = 0; std::map<std::string, size_t> output_nfts; size_t merchant_matches = 0;
  for (const auto& output : transaction.outputs) { if (output.token.has_value()) { const auto& token = *output.token; if (token.category != category) throw std::invalid_argument("CashToken output category mismatch"); if (std::numeric_limits<uint64_t>::max() - output_amount < token.amount) throw std::invalid_argument("CashToken amount exceeds u64"); output_amount += token.amount; if (token.capability != "none" || !token.commitment.empty()) output_nfts[nft_key(token)]++; if (output.value < dust_threshold) throw std::invalid_argument("CashToken output is dust"); const bool nft_matches = merchant_capability.empty() ? token.capability == "none" && token.commitment.empty() : token.capability == merchant_capability && token.commitment == merchant_commitment; if (output.value == merchant_amount && output.script_pubkey == merchant_script && token.amount == target_amount && nft_matches) merchant_matches++; } else if ((output.script_pubkey.empty() || output.script_pubkey[0] != 0x6a) && output.value < 546) throw std::invalid_argument("transaction output is dust"); if (std::numeric_limits<uint64_t>::max() - output_value < output.value) throw std::invalid_argument("output value exceeds u64"); output_value += output.value; }
  if (output_amount != source_amount || output_nfts != source_nfts) throw std::invalid_argument("CashToken state is not conserved"); if (merchant_matches != 1) throw std::invalid_argument("merchant output must match exactly once"); if (output_value > input_value) throw std::invalid_argument("transaction outputs exceed inputs"); const auto raw = serialize_transaction(transaction); const auto fee = input_value - output_value; if (fee_rate != 0 && (raw.size() > std::numeric_limits<uint64_t>::max() / fee_rate || fee < raw.size() * fee_rate)) throw std::invalid_argument("transaction fee is below the required BCH fee rate"); return {transaction_id_from_raw(raw), std::to_string(fee), raw.size()};
}

inline std::string transaction_id_from_hex(const std::string& raw_hex) {
  if (raw_hex.empty() || raw_hex.size() % 2 != 0) throw std::invalid_argument("transaction must be non-empty hex");
  std::string raw;
  for (size_t index = 0; index < raw_hex.size(); index += 2) {
    const auto high = std::stoi(raw_hex.substr(index, 1), nullptr, 16);
    const auto low = std::stoi(raw_hex.substr(index + 1, 1), nullptr, 16);
    raw.push_back(static_cast<char>((high << 4) | low));
  }
  const auto first_hex = request_hash(raw);
  std::string first;
  for (size_t index = 0; index < first_hex.size(); index += 2) first.push_back(static_cast<char>(std::stoi(first_hex.substr(index, 2), nullptr, 16)));
  const auto second_hex = request_hash(first);
  std::string result;
  for (size_t index = second_hex.size(); index > 0; index -= 2) result.append(second_hex.substr(index - 2, 2));
  return result;
}

inline std::string transaction_id(const std::string& encoded) {
  const auto raw_bytes = decode_base64(encoded);
  if (raw_bytes.empty()) throw std::invalid_argument("transaction must be non-empty base64");
  const std::string raw(raw_bytes.begin(), raw_bytes.end());
  const auto first_hex = request_hash(raw);
  std::string first;
  for (size_t index = 0; index < first_hex.size(); index += 2) first.push_back(static_cast<char>(std::stoi(first_hex.substr(index, 2), nullptr, 16)));
  const auto second_hex = request_hash(first);
  std::string result;
  for (size_t index = second_hex.size(); index > 0; index -= 2) result.append(second_hex.substr(index - 2, 2));
  return result;
}

inline std::string encode_base64(const std::vector<uint8_t>& raw) {
  static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  for (size_t offset = 0; offset < raw.size(); offset += 3) {
    const uint32_t value = (static_cast<uint32_t>(raw[offset]) << 16) |
        (offset + 1 < raw.size() ? static_cast<uint32_t>(raw[offset + 1]) << 8 : 0) |
        (offset + 2 < raw.size() ? static_cast<uint32_t>(raw[offset + 2]) : 0);
    encoded.push_back(alphabet[(value >> 18) & 63]);
    encoded.push_back(alphabet[(value >> 12) & 63]);
    encoded.push_back(offset + 1 < raw.size() ? alphabet[(value >> 6) & 63] : '=');
    encoded.push_back(offset + 2 < raw.size() ? alphabet[value & 63] : '=');
  }
  return encoded;
}

inline bool provider_transaction_matches(const std::string& candidate_txid,
                                         const std::vector<uint8_t>& raw_transaction) {
  if (raw_transaction.empty() || !std::regex_match(candidate_txid, std::regex("[0-9a-fA-F]{64}"))) return false;
  try {
    const auto encoded = encode_base64(raw_transaction);
    parse_transaction(encoded);
    auto observed = transaction_id(encoded);
    std::string candidate = candidate_txid;
    std::transform(observed.begin(), observed.end(), observed.begin(), [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    std::transform(candidate.begin(), candidate.end(), candidate.begin(), [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return observed == candidate;
  } catch (const std::exception&) {
    return false;
  }
}

inline std::string observe_bch_provider_transaction(
    const std::string& candidate_txid,
    const std::optional<std::vector<uint8_t>>& raw_transaction) {
  if (!raw_transaction.has_value()) return "missing";
  return provider_transaction_matches(candidate_txid, *raw_transaction) ? "match" : "mismatch";
}

struct ProviderSourceOutputResult {
  std::string observation;
  std::optional<TransactionOutput> source_output;
};

inline ProviderSourceOutputResult get_bch_provider_source_output(
    const std::string& source_txid, uint32_t vout,
    const std::optional<std::vector<uint8_t>>& raw_transaction) {
  const auto observation = observe_bch_provider_transaction(source_txid, raw_transaction);
  if (observation != "match") return {observation, std::nullopt};
  try {
    const auto transaction = parse_transaction(encode_base64(*raw_transaction));
    if (static_cast<uint64_t>(vout) >= transaction.outputs.size()) return {"notFound", std::nullopt};
    return {"match", transaction.outputs[vout]};
  } catch (const std::exception&) {
    return {"notFound", std::nullopt};
  }
}

inline SettlementIntegrationResult resolve_bch_settlement_from_provider(
    const std::string& candidate_txid, bool candidate_valid, bool binding_matches,
    const std::string& existing_claim, const std::string& strategy,
    const std::string& status, uint64_t confirmations = 0,
    std::optional<uint64_t> height = std::nullopt,
    std::optional<uint64_t> tip_height = std::nullopt,
    const std::string& broadcast_attempt = "none",
    const std::optional<std::vector<uint8_t>>& raw_transaction = std::nullopt) {
  return resolve_bch_settlement_integration(
      candidate_txid, candidate_valid, binding_matches, existing_claim,
      observe_bch_provider_transaction(candidate_txid, raw_transaction), strategy, status,
      confirmations, height, tip_height, broadcast_attempt);
}

inline void validate_payment_payload(const PaymentPayload& payload, const Requirements& expected) {
  validate_requirements(expected);
  if (payload.version != 2 || payload.accepted.scheme != expected.scheme || payload.accepted.network != expected.network || payload.accepted.asset != expected.asset || payload.accepted.amount != expected.amount || payload.accepted.pay_to != expected.pay_to || payload.accepted.payment_flow != expected.payment_flow || payload.accepted.request_hash != expected.request_hash)
    throw std::invalid_argument("accepted requirements mismatch");
  if (!valid_base64(payload.transaction)) throw std::invalid_argument("transaction must be non-empty base64");
}
}
