#pragma once
#include <algorithm>
#include <gmpxx.h>
#include <regex>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace x402bch {
struct Requirements {
  int version;
  std::string scheme;
  std::string network;
  std::string amount;
  std::string asset;
  std::string pay_to;
  std::string payment_flow;
  std::string request_hash;
};

struct PaymentPayload {
  int version;
  std::string transaction;
  Requirements accepted;
};

struct TransactionInput {
  std::string txid;
  uint32_t vout;
  std::vector<uint8_t> script_sig;
  uint32_t sequence;
};

struct CashToken {
  std::string category;
  uint64_t amount;
  std::string capability;
  std::vector<uint8_t> commitment;
};

struct TransactionOutput {
  uint64_t value;
  std::vector<uint8_t> script_pubkey;
  std::optional<CashToken> token;
};

struct Transaction {
  int32_t version;
  std::vector<TransactionInput> inputs;
  std::vector<TransactionOutput> outputs;
  uint32_t locktime;
};

struct PaymentVerification {
  std::string txid;
  std::string fee;
  size_t serialized_size;
};

struct AddressResult {
  std::vector<uint8_t> script_pubkey;
  bool token_support;
};

inline bool accepts_bch_settlement(const std::string& strategy, const std::string& status,
                                   uint64_t confirmations = 0,
                                   std::optional<uint64_t> height = std::nullopt,
                                   std::optional<uint64_t> tip_height = std::nullopt,
                                   bool double_spend_proof = false) {
  if (strategy == "mempool") return status == "mempool" || status == "confirmed";
  if (strategy == "noDoubleSpendProof")
    return status == "confirmed" || (status == "mempool" && !double_spend_proof);
  if (strategy != "confirmations" || confirmations < 1 || status != "confirmed" ||
      !height.has_value() || !tip_height.has_value() || *tip_height < *height)
    return false;
  return *tip_height - *height + 1 >= confirmations;
}

inline std::string resolve_bch_settlement_outcome(
    bool candidate_valid, const std::string& provider_observation,
    const std::string& strategy, const std::string& status,
    uint64_t confirmations = 0,
    std::optional<uint64_t> height = std::nullopt,
    std::optional<uint64_t> tip_height = std::nullopt,
    bool double_spend_proof = false) {
  if (!candidate_valid || provider_observation == "mismatch" ||
      (provider_observation != "missing" && provider_observation != "match") ||
      status == "conflicted")
    return "rejected";
  if (provider_observation == "missing") return "pending";
  return accepts_bch_settlement(strategy, status, confirmations, height, tip_height,
                                double_spend_proof)
             ? "accepted"
             : "pending";
}

struct SettlementIntegrationResult {
  std::string state;
  std::string transaction_id;
  std::string next_action;
};

inline SettlementIntegrationResult resolve_bch_settlement_integration(
    const std::string& candidate_txid, bool candidate_valid, bool binding_matches,
    const std::string& existing_claim, const std::string& provider_observation,
    const std::string& strategy, const std::string& status,
    uint64_t confirmations = 0, std::optional<uint64_t> height = std::nullopt,
    std::optional<uint64_t> tip_height = std::nullopt,
    const std::string& broadcast_attempt = "none") {
  const auto transaction_id = candidate_valid ? candidate_txid : std::string();
  if (!candidate_valid || !binding_matches || provider_observation == "mismatch")
    return {"rejected", transaction_id, "reject"};
  if (existing_claim == "different") return {"rejected", transaction_id, "conflict"};
  const auto state = resolve_bch_settlement_outcome(
      true, provider_observation, strategy, status, confirmations, height, tip_height, false);
  if (state != "pending") return {state, transaction_id, state == "accepted" ? "skip" : "reject"};
  if (provider_observation == "missing" && existing_claim == "none" && broadcast_attempt == "none")
    return {state, transaction_id, "broadcast"};
  if (provider_observation == "missing" && broadcast_attempt == "lost")
    return {state, transaction_id, "retry"};
  return {state, transaction_id, "retain"};
}

inline void validate_requirements(int version, const std::string& scheme, const std::string& amount, const std::string& flow) {
  if ((version != 0 && version != 2) || scheme != "exact" || !std::regex_match(amount, std::regex("[0-9]+")) || flow != "upfront") throw std::invalid_argument("unsupported x402 requirements");
}

inline void validate_requirements(const Requirements& requirements) {
  validate_requirements(requirements.version, requirements.scheme, requirements.amount, requirements.payment_flow);
  if (requirements.network != "bch:bitcoincash" && requirements.network != "bch:bchtest") throw std::invalid_argument("unsupported BCH network");
  if (requirements.asset.empty() || requirements.pay_to.empty()) throw std::invalid_argument("asset and payTo are required");
  if (!requirements.request_hash.empty() && !std::regex_match(requirements.request_hash, std::regex("[0-9a-fA-F]{64}")))
    throw std::invalid_argument("requestHash must be 32-byte hexadecimal");
}

inline bool valid_base64(const std::string& value) {
  if (value.empty() || value.size() % 4 != 0) return false;
  const size_t padding = value.size() - value.find_last_not_of('=') - 1;
  if (padding > 2 || value.find('=') != (padding == 0 ? std::string::npos : value.size() - padding)) return false;
  return value.substr(0, value.size() - padding).find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") == std::string::npos;
}

inline std::vector<uint8_t> decode_base64(const std::string& encoded) {
  if (!valid_base64(encoded)) throw std::invalid_argument("value must be valid base64");
  static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<uint8_t> raw;
  int buffer = 0, bits = 0;
  for (char value : encoded) {
    if (value == '=') break;
    const auto position = alphabet.find(value);
    if (position == std::string::npos) throw std::invalid_argument("value must be valid base64");
    buffer = (buffer << 6) | static_cast<int>(position);
    bits += 6;
    if (bits >= 8) { bits -= 8; raw.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff)); }
  }
  return raw;
}

inline void validate_transaction_envelope(const std::string& encoded) {
  const auto raw = decode_base64(encoded);
  if (raw.size() < 10) throw std::invalid_argument("transaction envelope is incomplete");
  const uint32_t version = static_cast<uint32_t>(raw[0]) | (static_cast<uint32_t>(raw[1]) << 8) |
      (static_cast<uint32_t>(raw[2]) << 16) | (static_cast<uint32_t>(raw[3]) << 24);
  if (version != 1 && version != 2) throw std::invalid_argument("unsupported transaction version");
  if (raw[4] == 0) throw std::invalid_argument("transaction must contain an input");
}

inline std::string request_hash(const std::string& canonical_json) {
  constexpr std::array<uint32_t, 64> k = {
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  auto rotr = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };
  std::vector<uint8_t> data(canonical_json.begin(), canonical_json.end());
  const uint64_t bit_length = static_cast<uint64_t>(data.size()) * 8;
  data.push_back(0x80);
  while (data.size() % 64 != 56) data.push_back(0);
  for (int shift = 56; shift >= 0; shift -= 8) data.push_back(static_cast<uint8_t>(bit_length >> shift));
  std::array<uint32_t, 8> h = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  for (size_t offset = 0; offset < data.size(); offset += 64) {
    std::array<uint32_t, 64> w{};
    for (size_t i = 0; i < 16; ++i) w[i] = (static_cast<uint32_t>(data[offset+i*4]) << 24) | (static_cast<uint32_t>(data[offset+i*4+1]) << 16) | (static_cast<uint32_t>(data[offset+i*4+2]) << 8) | data[offset+i*4+3];
    for (size_t i = 16; i < 64; ++i) { const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3); const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10); w[i] = w[i-16] + s0 + w[i-7] + s1; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],x=h[7];
    for (size_t i = 0; i < 64; ++i) { const uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25); const uint32_t ch=(e&f)^((~e)&g); const uint32_t temp1=x+S1+ch+k[i]+w[i]; const uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22); const uint32_t maj=(a&b)^(a&c)^(b&c); const uint32_t temp2=S0+maj; x=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2; }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=x;
  }
  std::ostringstream out; out << std::hex << std::setfill('0'); for (uint32_t word : h) out << std::setw(8) << word; return out.str();
}

inline uint64_t read_little_endian(const std::vector<uint8_t>& raw, size_t& offset, size_t width) {
  if (width == 0 || width > 8 || offset + width > raw.size()) throw std::invalid_argument("transaction ended while reading bytes");
  uint64_t result = 0;
  for (size_t index = 0; index < width; index++) result |= static_cast<uint64_t>(raw[offset + index]) << (index * 8);
  offset += width;
  return result;
}

inline uint64_t read_compact_size(const std::vector<uint8_t>& raw, size_t& offset) {
  const auto prefix = read_little_endian(raw, offset, 1);
  if (prefix < 253) return prefix;
  const size_t width = prefix == 253 ? 2 : prefix == 254 ? 4 : 8;
  const auto value = read_little_endian(raw, offset, width);
  const auto minimum = width == 2 ? 253ULL : width == 4 ? 65536ULL : 4294967296ULL;
  if (value < minimum) throw std::invalid_argument("non-canonical compact size");
  return value;
}

inline void append_little_endian(std::vector<uint8_t>& output, uint64_t value, size_t width) {
  for (size_t index = 0; index < width; index++) output.push_back(static_cast<uint8_t>(value >> (index * 8)));
}

inline void append_compact_size(std::vector<uint8_t>& output, uint64_t value) {
  if (value < 253) { append_little_endian(output, value, 1); return; }
  if (value <= 0xffff) { append_little_endian(output, 253, 1); append_little_endian(output, value, 2); return; }
  if (value <= 0xffffffff) { append_little_endian(output, 254, 1); append_little_endian(output, value, 4); return; }
  append_little_endian(output, 255, 1); append_little_endian(output, value, 8);
}

inline uint8_t hex_nibble(char value) {
  if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
  if (value >= 'a' && value <= 'f') return static_cast<uint8_t>(value - 'a' + 10);
  if (value >= 'A' && value <= 'F') return static_cast<uint8_t>(value - 'A' + 10);
  throw std::invalid_argument("invalid hexadecimal value");
}

inline std::vector<uint8_t> hex_to_bytes(const std::string& value) {
  if (value.size() % 2 != 0) throw std::invalid_argument("hexadecimal value must have even length");
  std::vector<uint8_t> result; result.reserve(value.size() / 2);
  for (size_t index = 0; index < value.size(); index += 2) result.push_back(static_cast<uint8_t>((hex_nibble(value[index]) << 4) | hex_nibble(value[index + 1])));
  return result;
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& value) {
  std::ostringstream output; output << std::hex << std::setfill('0');
  for (uint8_t item : value) output << std::setw(2) << static_cast<unsigned int>(item);
  return output.str();
}

inline std::string cash_addr_prefix(const std::string& network) {
  if (network == "bch:bitcoincash") return "bitcoincash";
  if (network == "bch:bchtest") return "bchtest";
  throw std::invalid_argument("unsupported BCH network");
}

inline uint64_t cash_addr_polymod(const std::vector<uint8_t>& values) {
  constexpr std::array<uint64_t, 5> generator = {0x98f2bc8e61ULL, 0x79b76d99e2ULL, 0xf33e5fb3c4ULL, 0xae2eabe2a8ULL, 0x1e4f43e470ULL};
  uint64_t checksum = 1;
  for (uint8_t value : values) { const auto top = checksum >> 35; checksum = ((checksum & 0x07ffffffffULL) << 5) ^ value; for (size_t index = 0; index < generator.size(); index++) if ((top >> index) & 1) checksum ^= generator[index]; }
  return checksum;
}

inline std::vector<uint8_t> cash_addr_prefix_expand(const std::string& prefix) {
  std::vector<uint8_t> result; result.reserve(prefix.size() + 1); for (char value : prefix) result.push_back(static_cast<uint8_t>(value & 0x1f)); result.push_back(0); return result;
}

inline std::vector<uint8_t> cash_addr_convert_bits(const std::vector<uint8_t>& values, unsigned from_bits, unsigned to_bits, bool pad) {
  uint32_t accumulator = 0; unsigned bits = 0; const auto maximum = static_cast<uint32_t>((1U << to_bits) - 1); std::vector<uint8_t> result;
  for (uint8_t value : values) { if (static_cast<uint32_t>(value) >> from_bits) throw std::invalid_argument("CashAddr data contains an invalid value"); accumulator = (accumulator << from_bits) | value; bits += from_bits; while (bits >= to_bits) { bits -= to_bits; result.push_back(static_cast<uint8_t>((accumulator >> bits) & maximum)); } }
  if (pad) { if (bits != 0) result.push_back(static_cast<uint8_t>((accumulator << (to_bits - bits)) & maximum)); }
  else if (bits >= from_bits || ((accumulator << (to_bits - bits)) & maximum) != 0) throw std::invalid_argument("CashAddr has non-zero padding");
  return result;
}

inline AddressResult decode_cash_address(const std::string& address, const std::string& network) {
  const auto prefix = cash_addr_prefix(network); std::string lowered = address; std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
  const auto separator = address.find(':'); if (address != lowered || separator == std::string::npos || address.substr(0, separator) != prefix) throw std::invalid_argument("CashAddr network mismatch");
  const auto encoded = address.substr(separator + 1); if (encoded.empty()) throw std::invalid_argument("invalid CashAddr characters");
  static const std::string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"; std::vector<uint8_t> values; values.reserve(encoded.size());
  for (char value : encoded) { const auto position = charset.find(value); if (position == std::string::npos) throw std::invalid_argument("invalid CashAddr characters"); values.push_back(static_cast<uint8_t>(position)); }
  if (values.size() < 9 || cash_addr_polymod([&] { auto result = cash_addr_prefix_expand(prefix); result.insert(result.end(), values.begin(), values.end()); return result; }()) != 1) throw std::invalid_argument("invalid CashAddr checksum");
  values.resize(values.size() - 8); const auto payload = cash_addr_convert_bits(values, 5, 8, false); if (payload.empty()) throw std::invalid_argument("invalid CashAddr payload");
  const auto version = payload[0]; const bool token_support = (version & 0x10) != 0; const auto base_version = static_cast<uint8_t>(version & 0x0f); const auto kind = static_cast<uint8_t>(base_version >> 3); const auto size_code = static_cast<uint8_t>(base_version & 7); constexpr std::array<size_t, 8> lengths = {20, 24, 28, 32, 40, 48, 56, 64};
  if ((kind != 0 && kind != 1) || size_code >= lengths.size() || payload.size() - 1 != lengths[size_code]) throw std::invalid_argument("unsupported CashAddr type");
  const std::vector<uint8_t> hash(payload.begin() + 1, payload.end());
  if (kind == 0) { auto script = std::vector<uint8_t>{0x76, 0xa9, 0x14}; script.insert(script.end(), hash.begin(), hash.end()); script.insert(script.end(), {0x88, 0xac}); return {script, token_support}; }
  if (hash.size() == 20) { auto script = std::vector<uint8_t>{0xa9, 0x14}; script.insert(script.end(), hash.begin(), hash.end()); script.push_back(0x87); return {script, token_support}; }
  if (hash.size() == 32) { auto script = std::vector<uint8_t>{0xaa, 0x20}; script.insert(script.end(), hash.begin(), hash.end()); script.push_back(0x87); return {script, token_support}; }
  throw std::invalid_argument("unsupported CashAddr payload");
}

inline std::string encode_cash_address(const std::vector<uint8_t>& script, const std::string& network, bool token_support) {
  const auto prefix = cash_addr_prefix(network); uint8_t version; std::vector<uint8_t> payload;
  if (script.size() == 25 && std::equal(script.begin(), script.begin() + 3, std::vector<uint8_t>{0x76, 0xa9, 0x14}.begin()) && script[23] == 0x88 && script[24] == 0xac) { version = 0; payload = std::vector<uint8_t>(script.begin() + 3, script.begin() + 23); }
  else if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) { version = 8; payload = std::vector<uint8_t>(script.begin() + 2, script.begin() + 22); }
  else if (script.size() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87) { version = 11; payload = std::vector<uint8_t>(script.begin() + 2, script.begin() + 34); }
  else throw std::invalid_argument("unsupported locking script for CashAddr");
  if (token_support) version |= 0x10; payload.insert(payload.begin(), version); auto data = cash_addr_convert_bits(payload, 8, 5, true); auto checksum_input = cash_addr_prefix_expand(prefix); checksum_input.insert(checksum_input.end(), data.begin(), data.end()); checksum_input.insert(checksum_input.end(), 8, 0); const auto checksum = cash_addr_polymod(checksum_input) ^ 1;
  static const std::string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"; std::string result = prefix + ":"; for (auto value : data) result.push_back(charset[value]); for (int index = 0; index < 8; index++) result.push_back(charset[(checksum >> (5 * (7 - index))) & 0x1f]); return result;
}

inline std::pair<std::optional<CashToken>, std::vector<uint8_t>> parse_token_prefix(const std::vector<uint8_t>& field) {
  if (field.empty() || field[0] != 0xef) return {std::nullopt, field};
  if (field.size() < 34) throw std::invalid_argument("CashToken prefix is too short");
  std::vector<uint8_t> category(field.begin() + 1, field.begin() + 33); std::reverse(category.begin(), category.end()); const auto bitfield = field[33]; const auto structure = static_cast<uint8_t>(bitfield & 0xf0); const auto capability = static_cast<uint8_t>(bitfield & 0x0f);
  if ((structure & 0x80) != 0) throw std::invalid_argument("CashToken prefix has a reserved bit"); if (capability > 2) throw std::invalid_argument("CashToken NFT capability is invalid"); const bool has_nft = (structure & 0x20) != 0, has_commitment = (structure & 0x40) != 0, has_amount = (structure & 0x10) != 0;
  if (has_commitment && !has_nft) throw std::invalid_argument("CashToken commitment requires an NFT"); if (capability != 0 && !has_nft) throw std::invalid_argument("CashToken capability requires an NFT"); size_t offset = 34; std::vector<uint8_t> commitment;
  if (has_nft && has_commitment) { const auto length = read_compact_size(field, offset); if (length == 0 || length > 40 || length > field.size() - offset) throw std::invalid_argument("CashToken NFT commitment length is invalid"); commitment.assign(field.begin() + static_cast<std::ptrdiff_t>(offset), field.begin() + static_cast<std::ptrdiff_t>(offset + length)); offset += static_cast<size_t>(length); }
  uint64_t amount = 0; if (has_amount) { amount = read_compact_size(field, offset); if (amount == 0 || amount > (std::numeric_limits<uint64_t>::max() >> 1)) throw std::invalid_argument("CashToken amount is outside the supported range"); }
  if (!has_nft && !has_amount) throw std::invalid_argument("CashToken prefix does not encode a token");
  const std::array<std::string, 3> capabilities = {"none", "mutable", "minting"};
  return {CashToken{bytes_to_hex(category), amount, has_nft ? capabilities[capability] : "none", std::move(commitment)}, std::vector<uint8_t>(field.begin() + static_cast<std::ptrdiff_t>(offset), field.end())};
}

inline std::vector<uint8_t> encode_token_prefix(const std::optional<CashToken>& token) {
  if (!token.has_value() || (token->amount == 0 && token->commitment.empty())) return {};
  auto category = hex_to_bytes(token->category); if (category.size() != 32) throw std::invalid_argument("CashToken category must be 32-byte hexadecimal"); std::reverse(category.begin(), category.end()); if (token->amount > (std::numeric_limits<uint64_t>::max() >> 1)) throw std::invalid_argument("CashToken amount is outside the supported range");
  std::vector<uint8_t> prefix{0xef}; prefix.insert(prefix.end(), category.begin(), category.end()); uint8_t bitfield = 0;
  if (!token->commitment.empty() || token->capability != "none") { bitfield |= 0x20; if (token->capability == "mutable") bitfield |= 1; else if (token->capability == "minting") bitfield |= 2; else if (token->capability != "none") throw std::invalid_argument("CashToken NFT capability is invalid"); if (token->commitment.size() > 40) throw std::invalid_argument("CashToken NFT commitment is too large"); if (!token->commitment.empty()) bitfield |= 0x40; }
  if (token->amount > 0) bitfield |= 0x10; prefix.push_back(bitfield); if (!token->commitment.empty()) { append_compact_size(prefix, token->commitment.size()); prefix.insert(prefix.end(), token->commitment.begin(), token->commitment.end()); } if (token->amount > 0) append_compact_size(prefix, token->amount); return prefix;
}

inline Transaction parse_transaction(const std::string& encoded) {
  const auto raw = decode_base64(encoded);
  if (raw.empty()) throw std::invalid_argument("transaction must be non-empty base64");
  size_t offset = 0;
  const auto version = static_cast<int32_t>(read_little_endian(raw, offset, 4));
  if (version != 1 && version != 2) throw std::invalid_argument("unsupported transaction version");
  const auto input_count = read_compact_size(raw, offset);
  if (input_count == 0 || input_count > 100) throw std::invalid_argument("invalid transaction input count");
  Transaction result{version, {}, {}, 0}; result.inputs.reserve(static_cast<size_t>(input_count));
  for (uint64_t index = 0; index < input_count; index++) {
    if (offset + 32 > raw.size()) throw std::invalid_argument("transaction ended while reading outpoint hash");
    auto hash = std::vector<uint8_t>(raw.begin() + static_cast<std::ptrdiff_t>(offset), raw.begin() + static_cast<std::ptrdiff_t>(offset + 32)); offset += 32; std::reverse(hash.begin(), hash.end());
    const auto vout = static_cast<uint32_t>(read_little_endian(raw, offset, 4));
    const auto script_length = read_compact_size(raw, offset);
    if (script_length > raw.size() - offset) throw std::invalid_argument("transaction ended while reading unlocking script");
    std::vector<uint8_t> script(raw.begin() + static_cast<std::ptrdiff_t>(offset), raw.begin() + static_cast<std::ptrdiff_t>(offset + script_length)); offset += static_cast<size_t>(script_length);
    const auto sequence = static_cast<uint32_t>(read_little_endian(raw, offset, 4));
    result.inputs.push_back({bytes_to_hex(hash), vout, std::move(script), sequence});
  }
  const auto output_count = read_compact_size(raw, offset);
  if (output_count == 0 || output_count > 16) throw std::invalid_argument("invalid transaction output count");
  result.outputs.reserve(static_cast<size_t>(output_count));
  for (uint64_t index = 0; index < output_count; index++) {
    const auto value = read_little_endian(raw, offset, 8); const auto script_length = read_compact_size(raw, offset);
    if (script_length > raw.size() - offset) throw std::invalid_argument("transaction ended while reading locking script");
    std::vector<uint8_t> field(raw.begin() + static_cast<std::ptrdiff_t>(offset), raw.begin() + static_cast<std::ptrdiff_t>(offset + script_length)); offset += static_cast<size_t>(script_length); auto [token, script] = parse_token_prefix(field);
    result.outputs.push_back({value, std::move(script), std::move(token)});
  }
  result.locktime = static_cast<uint32_t>(read_little_endian(raw, offset, 4));
  if (offset != raw.size()) throw std::invalid_argument("trailing transaction bytes");
  return result;
}

inline std::string get_request_hash_commitment(const Transaction& transaction) {
  for (const auto& output : transaction.outputs) {
    if (output.value == 0 && output.script_pubkey.size() == 34 && output.script_pubkey[0] == 0x6a && output.script_pubkey[1] == 0x20) {
      return bytes_to_hex(std::vector<uint8_t>(output.script_pubkey.begin() + 2, output.script_pubkey.end()));
    }
  }
  return {};
}

inline void assert_request_hash_commitment(const Transaction& transaction, const std::string& request_hash) {
  const auto expected = hex_to_bytes(request_hash);
  if (expected.size() != 32 || get_request_hash_commitment(transaction) != bytes_to_hex(expected)) {
    throw std::invalid_argument("payment transaction does not commit to the requested resource hash");
  }
}

inline std::vector<uint8_t> serialize_transaction(const Transaction& transaction) {
  if (transaction.inputs.empty() || transaction.inputs.size() > 100) throw std::invalid_argument("invalid transaction input count");
  if (transaction.outputs.empty() || transaction.outputs.size() > 16) throw std::invalid_argument("invalid transaction output count");
  std::vector<uint8_t> result; append_little_endian(result, static_cast<uint32_t>(transaction.version), 4); append_compact_size(result, transaction.inputs.size());
  for (const auto& input : transaction.inputs) {
    auto hash = hex_to_bytes(input.txid); if (hash.size() != 32) throw std::invalid_argument("input txid must be 32-byte hexadecimal"); std::reverse(hash.begin(), hash.end()); result.insert(result.end(), hash.begin(), hash.end());
    append_little_endian(result, input.vout, 4); append_compact_size(result, input.script_sig.size()); result.insert(result.end(), input.script_sig.begin(), input.script_sig.end()); append_little_endian(result, input.sequence, 4);
  }
  append_compact_size(result, transaction.outputs.size());
  for (const auto& output : transaction.outputs) { append_little_endian(result, output.value, 8); auto prefix = encode_token_prefix(output.token); prefix.insert(prefix.end(), output.script_pubkey.begin(), output.script_pubkey.end()); append_compact_size(result, prefix.size()); result.insert(result.end(), prefix.begin(), prefix.end()); }
  append_little_endian(result, transaction.locktime, 4); return result;
}

inline std::vector<uint8_t> double_sha256_bytes(const std::vector<uint8_t>& value) {
  const auto first = hex_to_bytes(request_hash(std::string(value.begin(), value.end())));
  return hex_to_bytes(request_hash(std::string(first.begin(), first.end())));
}

inline std::vector<uint8_t> ripemd160(const std::vector<uint8_t>& message) {
  const std::array<int, 80> r_left = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
  const std::array<int, 80> r_right = {5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
  const std::array<unsigned, 80> s_left = {11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
  const std::array<unsigned, 80> s_right = {8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
  const std::array<uint32_t, 5> k_left = {0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
  const std::array<uint32_t, 5> k_right = {0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000};
  std::vector<uint8_t> data = message; const uint64_t bit_length = static_cast<uint64_t>(data.size()) * 8; data.push_back(0x80); while (data.size() % 64 != 56) data.push_back(0); append_little_endian(data, bit_length, 8);
  std::array<uint32_t, 5> h = {0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
  const auto rol = [](uint32_t value, unsigned shift) { return (value << shift) | (value >> (32 - shift)); };
  const auto f = [](size_t index, uint32_t x, uint32_t y, uint32_t z) { if (index < 16) return x ^ y ^ z; if (index < 32) return (x & y) | (~x & z); if (index < 48) return (x | ~y) ^ z; if (index < 64) return (x & z) | (y & ~z); return x ^ (y | ~z); };
  for (size_t offset = 0; offset < data.size(); offset += 64) {
    std::array<uint32_t, 16> words{}; for (size_t index = 0; index < 16; index++) words[index] = static_cast<uint32_t>(data[offset + index * 4]) | (static_cast<uint32_t>(data[offset + index * 4 + 1]) << 8) | (static_cast<uint32_t>(data[offset + index * 4 + 2]) << 16) | (static_cast<uint32_t>(data[offset + index * 4 + 3]) << 24);
    std::array<uint32_t, 5> left = h, right = h;
    for (size_t index = 0; index < 80; index++) {
      const auto left_value = rol(left[0] + f(index, left[1], left[2], left[3]) + words[r_left[index]] + k_left[index / 16], s_left[index]) + left[4]; left = {left[4], left_value, left[1], rol(left[2], 10), left[3]};
      const auto right_value = rol(right[0] + f(79 - index, right[1], right[2], right[3]) + words[r_right[index]] + k_right[index / 16], s_right[index]) + right[4]; right = {right[4], right_value, right[1], rol(right[2], 10), right[3]};
    }
    const auto t = h[1] + left[2] + right[3]; h = {t, h[2] + left[3] + right[4], h[3] + left[4] + right[0], h[4] + left[0] + right[1], h[0] + left[1] + right[2]};
  }
  std::vector<uint8_t> result; result.reserve(20); for (const auto value : h) append_little_endian(result, value, 4); return result;
}

inline std::vector<uint8_t> hash160(const std::vector<uint8_t>& value) {
  return ripemd160(hex_to_bytes(request_hash(std::string(value.begin(), value.end()))));
}

struct BchVmResult {
  bool accepted = false;
  std::string error_code;
};

inline bool bch_vm_truthy(const std::vector<uint8_t>& value) {
  for (size_t index = 0; index < value.size(); index++) {
    if (value[index] != 0) return !(index == value.size() - 1 && value[index] == 0x80);
  }
  return false;
}

inline std::string execute_bch_script(const std::vector<uint8_t>& script,
                                      std::vector<std::vector<uint8_t>>& stack) {
  size_t offset = 0;
  while (offset < script.size()) {
    const uint8_t opcode = script[offset++];
    if (opcode == 0) { stack.emplace_back(); continue; }
    if (opcode >= 1 && opcode <= 75) {
      const size_t length = opcode;
      if (offset + length > script.size()) return "TRUNCATED_PUSH";
      stack.emplace_back(script.begin() + static_cast<std::ptrdiff_t>(offset),
                         script.begin() + static_cast<std::ptrdiff_t>(offset + length));
      offset += length;
      continue;
    }
    if (opcode == 0x4c || opcode == 0x4d || opcode == 0x4e) {
      const size_t width = opcode == 0x4c ? 1 : (opcode == 0x4d ? 2 : 4);
      if (offset + width > script.size()) return "TRUNCATED_PUSH";
      size_t length = 0;
      for (size_t index = 0; index < width; index++) length |= static_cast<size_t>(script[offset + index]) << (8 * index);
      offset += width;
      if (length > 520) return "PUSH_SIZE";
      if (offset + length > script.size()) return "TRUNCATED_PUSH";
      stack.emplace_back(script.begin() + static_cast<std::ptrdiff_t>(offset),
                         script.begin() + static_cast<std::ptrdiff_t>(offset + length));
      offset += length;
      continue;
    }
    if (opcode >= 0x51 && opcode <= 0x60) { stack.push_back({static_cast<uint8_t>(opcode - 0x50)}); continue; }
    switch (opcode) {
      case 0x69:
        if (stack.empty()) return "INVALID_STACK_OPERATION";
        if (!bch_vm_truthy(stack.back())) return "VERIFY";
        stack.pop_back();
        break;
      case 0x76:
        if (stack.empty()) return "INVALID_STACK_OPERATION";
        stack.push_back(stack.back());
        break;
      case 0x87: {
        if (stack.size() < 2) return "INVALID_STACK_OPERATION";
        const auto right = stack.back(); stack.pop_back();
        const auto left = stack.back(); stack.pop_back();
        stack.push_back(left == right ? std::vector<uint8_t>{1} : std::vector<uint8_t>{});
        break;
      }
      case 0x88: {
        if (stack.size() < 2) return "INVALID_STACK_OPERATION";
        const auto right = stack.back(); stack.pop_back();
        const auto left = stack.back(); stack.pop_back();
        if (left != right) return "EQUALVERIFY";
        break;
      }
      case 0xa9:
        if (stack.empty()) return "INVALID_STACK_OPERATION";
        { const auto value = stack.back(); stack.pop_back(); stack.push_back(hash160(value)); }
        break;
      case 0x6a: return "OP_RETURN";
      default: return "BAD_OPCODE";
    }
  }
  return {};
}

inline BchVmResult evaluate_bch_vm(const std::vector<uint8_t>& unlocking_script,
                                   const std::vector<uint8_t>& locking_script) {
  std::vector<std::vector<uint8_t>> stack;
  auto error = execute_bch_script(unlocking_script, stack);
  if (error.empty()) error = execute_bch_script(locking_script, stack);
  if (error.empty() && stack.size() != 1) error = "CLEANSTACK";
  if (error.empty() && !bch_vm_truthy(stack.back())) error = "FALSE";
  return {error.empty(), error};
}

// Check push-only unlocking and the committed P2SH20/P2SH32 redeem script.
// This validates the hash boundary only; it does not execute arbitrary BCH VM.
inline void verify_p2sh_redeem_script(const Transaction& transaction, size_t input_index, const std::vector<uint8_t>& source_script) {
  const bool p2sh20 = source_script.size() == 23 && source_script[0] == 0xa9 && source_script[1] == 0x14 && source_script[22] == 0x87;
  const bool p2sh32 = source_script.size() == 35 && source_script[0] == 0xaa && source_script[1] == 0x20 && source_script[34] == 0x87;
  if (!p2sh20 && !p2sh32) throw std::invalid_argument("source output is not P2SH20 or P2SH32");
  if (input_index >= transaction.inputs.size()) throw std::invalid_argument("invalid input index");
  const auto& script = transaction.inputs[input_index].script_sig;
  std::vector<std::vector<uint8_t>> pushes;
  size_t offset = 0;
  while (offset < script.size()) {
    const auto opcode = script[offset++];
    if (opcode == 0) { pushes.emplace_back(); continue; }
    uint64_t length = 0;
    if (opcode >= 1 && opcode <= 75) length = opcode;
    else if (opcode == 0x4c) length = read_little_endian(script, offset, 1);
    else if (opcode == 0x4d) length = read_little_endian(script, offset, 2);
    else if (opcode == 0x4e) length = read_little_endian(script, offset, 4);
    else throw std::invalid_argument("P2SH unlocking script is not push-only");
    if (length > script.size() - offset) throw std::invalid_argument("P2SH unlocking script push is truncated");
    pushes.emplace_back(script.begin() + static_cast<std::ptrdiff_t>(offset), script.begin() + static_cast<std::ptrdiff_t>(offset + length));
    offset += static_cast<size_t>(length);
  }
  if (pushes.empty()) throw std::invalid_argument("P2SH unlocking script does not push a redeem script");
  const auto& redeem_script = pushes.back();
  const auto committed = p2sh20 ? hash160(redeem_script) : double_sha256_bytes(redeem_script);
  if (!std::equal(committed.begin(), committed.end(), source_script.begin() + 2)) throw std::invalid_argument("P2SH redeem script commitment mismatch");
}

using BigInt = mpz_class;
struct SecpPoint { BigInt x; BigInt y; bool infinity = false; };
inline BigInt secp_mod(BigInt value, const BigInt& modulus) { value %= modulus; if (value < 0) value += modulus; return value; }
inline BigInt secp_pow(BigInt base, BigInt exponent, const BigInt& modulus) { BigInt result = 1; base = secp_mod(base, modulus); while (exponent > 0) { if ((exponent & 1) != 0) result = secp_mod(result * base, modulus); base = secp_mod(base * base, modulus); exponent >>= 1; } return result; }
inline const BigInt& secp_p() { static const BigInt value("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16); return value; }
inline const BigInt& secp_n() { static const BigInt value("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16); return value; }
inline SecpPoint secp_g() { return {BigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16), BigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16), false}; }
inline SecpPoint secp_add(const SecpPoint& left, const SecpPoint& right) {
  if (left.infinity) return right; if (right.infinity) return left;
  const auto& modulus = secp_p(); if (left.x == right.x && secp_mod(left.y + right.y, modulus) == 0) return {{}, {}, true};
  BigInt lambda; if (left.x == right.x && left.y == right.y) lambda = secp_mod(BigInt(3) * left.x * left.x * secp_pow(BigInt(2) * left.y, modulus - 2, modulus), modulus); else lambda = secp_mod((right.y - left.y) * secp_pow(right.x - left.x, modulus - 2, modulus), modulus);
  const auto x = secp_mod(lambda * lambda - left.x - right.x, modulus); return {x, secp_mod(lambda * (left.x - x) - left.y, modulus), false};
}
inline SecpPoint secp_mul(BigInt scalar, SecpPoint point) { SecpPoint result{{}, {}, true}; while (scalar > 0) { const BigInt bit = scalar & 1; if (bit.get_ui() != 0) result = secp_add(result, point); point = secp_add(point, point); scalar >>= 1; } return result; }
inline SecpPoint decode_secp_public_key(const std::vector<uint8_t>& encoded) {
  if (encoded.size() != 33 || (encoded[0] != 2 && encoded[0] != 3)) throw std::invalid_argument("invalid compressed public key");
  BigInt x = 0; for (size_t index = 1; index < encoded.size(); index++) x = (x << 8) + encoded[index]; if (x >= secp_p()) throw std::invalid_argument("invalid compressed public key");
  const auto rhs = secp_mod(x * x * x + 7, secp_p()); auto y = secp_pow(rhs, (secp_p() + 1) / 4, secp_p()); if (secp_mod(y * y, secp_p()) != rhs) throw std::invalid_argument("invalid compressed public key"); const BigInt parity = y & 1; if (parity.get_ui() != (encoded[0] & 1)) y = secp_p() - y; return {x, y, false};
}
inline BigInt big_int_from_bytes(const std::vector<uint8_t>& value) { BigInt result = 0; for (auto item : value) result = (result << 8) + item; return result; }
inline std::pair<BigInt, BigInt> parse_der_signature(const std::vector<uint8_t>& value) {
  if (value.size() < 8 || value[0] != 0x30 || static_cast<size_t>(value[1]) + 2 != value.size()) throw std::invalid_argument("malformed DER signature"); size_t offset = 2; if (value[offset++] != 2) throw std::invalid_argument("malformed DER r"); const size_t r_length = value[offset++]; if (r_length == 0 || offset + r_length + 2 > value.size()) throw std::invalid_argument("malformed DER r"); std::vector<uint8_t> r(value.begin() + static_cast<std::ptrdiff_t>(offset), value.begin() + static_cast<std::ptrdiff_t>(offset + r_length)); offset += r_length; if (value[offset++] != 2) throw std::invalid_argument("malformed DER s"); const size_t s_length = value[offset++]; if (s_length == 0 || offset + s_length != value.size()) throw std::invalid_argument("malformed DER s"); std::vector<uint8_t> s(value.begin() + static_cast<std::ptrdiff_t>(offset), value.end()); if ((r[0] & 0x80) != 0 || (r.size() > 1 && r[0] == 0 && (r[1] & 0x80) == 0) || (s[0] & 0x80) != 0 || (s.size() > 1 && s[0] == 0 && (s[1] & 0x80) == 0)) throw std::invalid_argument("non-canonical DER integer"); return {big_int_from_bytes(r), big_int_from_bytes(s)};
}
inline bool verify_secp_ecdsa(const std::vector<uint8_t>& digest, const BigInt& r, const BigInt& s, const SecpPoint& public_key) {
  if (r <= 0 || r >= secp_n() || s <= 0 || s >= secp_n()) return false; const auto inverse = secp_pow(s, secp_n() - 2, secp_n()); const auto e = big_int_from_bytes(digest); const auto point = secp_add(secp_mul(secp_mod(e * inverse, secp_n()), secp_g()), secp_mul(secp_mod(r * inverse, secp_n()), public_key)); return !point.infinity && secp_mod(point.x, secp_n()) == r;
}

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
