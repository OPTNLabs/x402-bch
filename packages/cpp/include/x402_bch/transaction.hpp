#pragma once
#include "address.hpp"
namespace x402bch {
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

inline std::vector<uint8_t> request_hash_script(const std::string& request_hash) {
  const auto value = hex_to_bytes(request_hash);
  if (value.size() != 32) throw std::invalid_argument("request hash must be 32-byte hexadecimal");
  std::vector<uint8_t> script{0x6a, 0x20};
  script.insert(script.end(), value.begin(), value.end());
  return script;
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

}
