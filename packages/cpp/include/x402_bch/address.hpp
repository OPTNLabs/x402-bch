#pragma once
#include "protocol.hpp"
namespace x402bch {
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

}
