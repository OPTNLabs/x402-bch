#pragma once
#include "x402_bch_sdk.hpp"
#include <fstream>
#include <sodium/crypto_auth_hmacsha512.h>
#include <sodium/crypto_auth_hmacsha256.h>
namespace x402bch { namespace detail {
inline std::string json_string(const std::string& json, const std::string& key) {
  const std::regex pattern("\\\"" + key + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
  std::smatch match;
  if (!std::regex_search(json, match, pattern)) throw std::invalid_argument("missing Fulcrum field: " + key);
  return match[1].str();
}

inline uint64_t json_number(const std::string& json, const std::string& key) {
  const std::regex pattern("\\\"" + key + "\\\"\\s*:\\s*(?:\\\"(-?[0-9]+)\\\"|(-?[0-9]+))");
  std::smatch match;
  if (!std::regex_search(json, match, pattern)) throw std::invalid_argument("missing Fulcrum field: " + key);
  const auto value = std::stoll(match[1].matched ? match[1].str() : match[2].str());
  if (value < 0) throw std::invalid_argument("negative Fulcrum number: " + key);
  return static_cast<uint64_t>(value);
}

inline std::optional<CashToken> json_token(const std::string& json) {
  std::smatch token_match;
  if (!std::regex_search(json, token_match,
                         std::regex("\\\"(?:tokenData|token_data)\\\"\\s*:\\s*\\{([^{}]*)\\}")))
    return std::nullopt;
  const auto token_json = token_match[1].str();
  const auto category = json_string(token_json, "category");
  const auto amount = json_number(token_json, "amount");
  std::string capability = "none";
  std::vector<uint8_t> commitment;
  std::smatch nft_match;
  if (std::regex_search(json, nft_match,
                        std::regex("\\\"nft\\\"\\s*:\\s*\\{([^{}]*)\\}"))) {
    const auto nft_json = nft_match[1].str();
    capability = json_string(nft_json, "capability");
    const auto commitment_hex = json_string(nft_json, "commitment");
    commitment = hex_to_bytes(commitment_hex);
  }
  return CashToken{category, amount, capability, commitment};
}

inline std::string quoted_or_raw(const std::string& response) {
  const auto first = response.find_first_not_of(" \t\r\n");
  const auto last = response.find_last_not_of(" \t\r\n");
  if (first == std::string::npos) return {};
  if (response[first] == '"' && response[last] == '"' && last > first)
    return response.substr(first + 1, last - first - 1);
  return response.substr(first, last - first + 1);
}

inline std::string reverse_hex_bytes(std::string value) {
  if (value.size() % 2 != 0) throw std::invalid_argument("invalid hash length");
  std::string result;
  for (size_t offset = value.size(); offset > 0; offset -= 2)
    result += value.substr(offset - 2, 2);
  return result;
}

inline std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
  crypto_auth_hmacsha512_state state;
  if (crypto_auth_hmacsha512_init(&state, key.data(), key.size()) != 0 || crypto_auth_hmacsha512_update(&state, message.data(), message.size()) != 0) throw std::runtime_error("HMAC-SHA512 failed");
  std::vector<uint8_t> result(64); if (crypto_auth_hmacsha512_final(&state, result.data()) != 0) throw std::runtime_error("HMAC-SHA512 failed"); return result;
}
inline std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
  crypto_auth_hmacsha256_state state;
  if (crypto_auth_hmacsha256_init(&state, key.data(), key.size()) != 0 || crypto_auth_hmacsha256_update(&state, message.data(), message.size()) != 0) throw std::runtime_error("HMAC-SHA256 failed");
  std::vector<uint8_t> result(32); if (crypto_auth_hmacsha256_final(&state, result.data()) != 0) throw std::runtime_error("HMAC-SHA256 failed"); return result;
}
inline std::vector<uint8_t> fixed_bytes(const BigInt& value, size_t length) {
  std::vector<uint8_t> result(length); size_t written = 0; mpz_export(result.data(), &written, 1, 1, 1, 0, value.get_mpz_t());
  if (written > length) throw std::invalid_argument("derived key exceeds 32 bytes");
  if (written < length) std::move_backward(result.begin(), result.begin() + written, result.end());
  return result;
}
inline std::vector<uint8_t> pbkdf2_sha512(const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt, uint32_t iterations) {
  std::vector<uint8_t> result;
  for (uint32_t block = 1; result.size() < 64; ++block) { auto input = salt; input.insert(input.end(), {static_cast<uint8_t>(block >> 24), static_cast<uint8_t>(block >> 16), static_cast<uint8_t>(block >> 8), static_cast<uint8_t>(block)}); auto u = hmac_sha512(password, input); auto t = u; for (uint32_t round = 1; round < iterations; ++round) { u = hmac_sha512(password, u); for (size_t i = 0; i < t.size(); ++i) t[i] ^= u[i]; } result.insert(result.end(), t.begin(), t.end()); }
  result.resize(64); return result;
}
inline void validate_bip39_mnemonic(const std::string& mnemonic) {
  std::istringstream input(mnemonic); std::vector<std::string> words; std::string word;
  while (input >> word) words.push_back(word);
  if (words.size() != 12 && words.size() != 15 && words.size() != 18 && words.size() != 21 && words.size() != 24) throw std::invalid_argument("invalid BIP39 English mnemonic");
  std::ifstream file("spec/conformance/v1/bip39-english.txt");
#ifdef X402_BCH_BIP39_WORDLIST_PATH
  if (!file) file.open(X402_BCH_BIP39_WORDLIST_PATH);
#endif
  if (!file) throw std::runtime_error("BIP39 English wordlist is unavailable");
  std::vector<std::string> list; while (std::getline(file, word)) list.push_back(word); if (list.size() != 2048) throw std::runtime_error("invalid BIP39 English wordlist");
  std::map<std::string, size_t> indices; for (size_t i = 0; i < list.size(); ++i) indices[list[i]] = i;
  std::string bits; for (const auto& item : words) { auto found = indices.find(item); if (found == indices.end()) throw std::invalid_argument("invalid BIP39 English mnemonic"); for (int bit = 10; bit >= 0; --bit) bits.push_back(((found->second >> bit) & 1) ? '1' : '0'); }
  const size_t entropy_bits = words.size() * 11 * 32 / 33; std::vector<uint8_t> entropy(entropy_bits / 8); for (size_t i = 0; i < entropy.size(); ++i) for (int bit = 0; bit < 8; ++bit) entropy[i] = static_cast<uint8_t>((entropy[i] << 1) | (bits[i * 8 + bit] == '1'));
  const auto digest = hex_to_bytes(request_hash(std::string(entropy.begin(), entropy.end()))); const size_t checksum_bits = bits.size() - entropy_bits; for (size_t bit = 0; bit < checksum_bits; ++bit) if (bits[entropy_bits + bit] != (((digest[0] >> (7 - bit)) & 1) ? '1' : '0')) throw std::invalid_argument("invalid BIP39 mnemonic checksum");
}
inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>> bip32_child(const std::vector<uint8_t>& parent, const std::vector<uint8_t>& chain, uint32_t index) {
  const auto point = secp_mul(big_int_from_bytes(parent), secp_g()); auto public_key = std::vector<uint8_t>{static_cast<uint8_t>(2 | (point.y.get_ui() & 1))}; auto x = fixed_bytes(point.x, 32); public_key.insert(public_key.end(), x.begin(), x.end()); auto data = index >= 0x80000000 ? std::vector<uint8_t>{0} : public_key; if (index >= 0x80000000) data.insert(data.end(), parent.begin(), parent.end()); data.insert(data.end(), {static_cast<uint8_t>(index >> 24), static_cast<uint8_t>(index >> 16), static_cast<uint8_t>(index >> 8), static_cast<uint8_t>(index)}); const auto digest = hmac_sha512(chain, data); auto scalar = secp_mod(big_int_from_bytes(std::vector<uint8_t>(digest.begin(), digest.begin() + 32)) + big_int_from_bytes(parent), secp_n()); return {fixed_bytes(scalar, 32), std::vector<uint8_t>(digest.begin() + 32, digest.end())};
}
inline std::vector<uint8_t> derive_private_key(const std::string& mnemonic, const std::string& network, const std::string& passphrase, uint32_t change, uint32_t index, uint32_t account) {
  const uint32_t coin = network == "bch:bitcoincash" || network == "mainnet" ? 145 : 1;
  std::vector<uint8_t> password(mnemonic.begin(), mnemonic.end()), salt{'m','n','e','m','o','n','i','c'}; salt.insert(salt.end(), passphrase.begin(), passphrase.end()); auto seed = pbkdf2_sha512(password, salt, 2048); auto root = hmac_sha512(std::vector<uint8_t>{'B','i','t','c','o','i','n',' ','s','e','e','d'}, seed); std::vector<uint8_t> key(root.begin(), root.begin()+32), chain(root.begin()+32, root.end());
  for (auto child : std::array<uint32_t,5>{0x8000002c, coin | 0x80000000, account | 0x80000000, change, index}) { auto next = bip32_child(key, chain, child); key = std::move(next.first); chain = std::move(next.second); } return key;
}
inline std::vector<uint8_t> der_signature(const BigInt& r, const BigInt& s) {
  auto integer = [](const BigInt& value) { auto raw = fixed_bytes(value, 32); while (raw.size() > 1 && raw.front() == 0) raw.erase(raw.begin()); if ((raw.front() & 0x80) != 0) raw.insert(raw.begin(), 0); std::vector<uint8_t> result{2, static_cast<uint8_t>(raw.size())}; result.insert(result.end(), raw.begin(), raw.end()); return result; };
  auto rb = integer(r), sb = integer(s); std::vector<uint8_t> body = rb; body.insert(body.end(), sb.begin(), sb.end()); std::vector<uint8_t> result{0x30, static_cast<uint8_t>(body.size())}; result.insert(result.end(), body.begin(), body.end()); return result;
}
} }
