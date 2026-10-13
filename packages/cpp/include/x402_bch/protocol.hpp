#pragma once
#include "types.hpp"
namespace x402bch {
Requirements build_native_requirements(const std::string& network, const std::string& pay_to,
                                       const std::string& amount,
                                       const std::string& request_hash = {});

Requirements build_cash_token_requirements(
    const std::string& network, const std::string& pay_to, const std::string& category,
    const std::string& amount, std::string value = {}, const std::string& request_hash = {},
    const std::string& capability = "", const std::vector<uint8_t>& commitment = {});

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

}
