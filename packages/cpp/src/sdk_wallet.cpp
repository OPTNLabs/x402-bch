#include "sdk_support.hpp"
#include <algorithm>
#include <regex>
#include <sstream>
namespace x402bch {
using namespace detail;
WalletAddress derive_bch_wallet_address(const std::string& mnemonic, const std::string& network,
                                        uint32_t change, uint32_t index, uint32_t account,
                                        const std::string& passphrase, std::optional<uint32_t> coin_type) {
  validate_bip39_mnemonic(mnemonic); if (change > 1 || (network != "bch:bitcoincash" && network != "bch:bchtest")) throw std::invalid_argument("invalid BCH HD derivation request");
  const uint32_t coin = coin_type.value_or(network == "bch:bitcoincash" ? 145 : 1);
  if (coin >= 0x80000000 || account >= 0x80000000) throw std::invalid_argument("invalid BIP44 derivation index");
  std::vector<uint8_t> password(mnemonic.begin(), mnemonic.end()), salt{'m','n','e','m','o','n','i','c'}; salt.insert(salt.end(), passphrase.begin(), passphrase.end());
  const auto seed = pbkdf2_sha512(password, salt, 2048); const auto root = hmac_sha512(std::vector<uint8_t>{'B','i','t','c','o','i','n',' ','s','e','e','d'}, seed);
  std::vector<uint8_t> key(root.begin(), root.begin() + 32), chain(root.begin() + 32, root.end());
  for (const auto child : std::array<uint32_t, 5>{0x8000002c, coin | 0x80000000, account | 0x80000000, change, index}) { auto next = bip32_child(key, chain, child); key = std::move(next.first); chain = std::move(next.second); }
  const auto point = secp_mul(big_int_from_bytes(key), secp_g()); std::vector<uint8_t> public_key{static_cast<uint8_t>(2 | (point.y.get_ui() & 1))}; auto x = fixed_bytes(point.x, 32); public_key.insert(public_key.end(), x.begin(), x.end()); auto script = std::vector<uint8_t>{0x76, 0xa9, 0x14}; const auto hash = hash160(public_key); script.insert(script.end(), hash.begin(), hash.end()); script.insert(script.end(), {0x88, 0xac});
  return {encode_cash_address(script, network, false), "m/44'/" + std::to_string(coin) + "'/" + std::to_string(account) + "'/" + std::to_string(change) + "/" + std::to_string(index), change, index, public_key};
}

std::vector<DiscoveredAddress> discover_bch_hd_wallet_addresses(
    const std::string& mnemonic, const std::string& network, Provider& provider,
    uint32_t gap_limit, uint32_t max_addresses, uint32_t account, const std::string& passphrase) {
  if (gap_limit == 0 || max_addresses < gap_limit) throw std::invalid_argument("invalid HD discovery limits");
  std::vector<DiscoveredAddress> result;
  for (uint32_t change = 0; change <= 1; ++change) { uint32_t unused = 0; for (uint32_t index = 0; index < max_addresses && unused < gap_limit; ++index) { auto wallet = derive_bch_wallet_address(mnemonic, network, change, index, account, passphrase); auto utxos = provider.list_utxos(wallet.address); result.push_back({wallet, std::move(utxos)}); unused = result.back().utxos.empty() ? unused + 1 : 0; } }
  return result;
}

Secp256k1BchSigner::Secp256k1BchSigner(const std::string& mnemonic, const std::string& network,
                                       const std::string& passphrase, uint32_t change,
                                       uint32_t index, uint32_t account)
    : private_key_(derive_private_key(mnemonic, network, passphrase, change, index, account)), default_network_(network) { validate_bip39_mnemonic(mnemonic); }

std::vector<uint8_t> Secp256k1BchSigner::public_key() const {
  const auto point = secp_mul(big_int_from_bytes(private_key_), secp_g());
  auto result = std::vector<uint8_t>{static_cast<uint8_t>(2 | (point.y.get_ui() & 1))}; auto x = fixed_bytes(point.x, 32); result.insert(result.end(), x.begin(), x.end()); return result;
}

std::string Secp256k1BchSigner::address(const std::string& network) const {
  const auto chain = network == "mainnet" ? "bch:bitcoincash" : (network == "chipnet" ? "bch:bchtest" : network); auto script = std::vector<uint8_t>{0x76, 0xa9, 0x14}; auto hash = hash160(public_key()); script.insert(script.end(), hash.begin(), hash.end()); script.insert(script.end(), {0x88, 0xac}); return encode_cash_address(script, chain, false);
}

std::vector<uint8_t> Secp256k1BchSigner::sign_digest(const std::vector<uint8_t>& digest) {
  if (digest.size() != 32) throw std::invalid_argument("BCH signing digest must be 32 bytes");
  std::vector<uint8_t> v(32, 1), k(32, 0); auto mix = [&](uint8_t marker) { std::vector<uint8_t> message = v; message.push_back(marker); message.insert(message.end(), private_key_.begin(), private_key_.end()); message.insert(message.end(), digest.begin(), digest.end()); k = hmac_sha256(k, message); v = hmac_sha256(k, v); };
  mix(0); std::vector<uint8_t> message = v; message.push_back(1); message.insert(message.end(), private_key_.begin(), private_key_.end()); message.insert(message.end(), digest.begin(), digest.end()); k = hmac_sha256(k, message); v = hmac_sha256(k, v);
  while (true) { v = hmac_sha256(k, v); const auto nonce = big_int_from_bytes(v); if (nonce > 0 && nonce < secp_n()) { const auto point = secp_mul(nonce, secp_g()); const auto r = secp_mod(point.x, secp_n()); if (r != 0) { auto s = secp_mod(secp_pow(nonce, secp_n() - 2, secp_n()) * (big_int_from_bytes(digest) + r * big_int_from_bytes(private_key_)), secp_n()); if (s > secp_n() / 2) s = secp_n() - s; return der_signature(r, s); } } message = v; message.push_back(0); k = hmac_sha256(k, message); v = hmac_sha256(k, v); }
}

FailoverFulcrumTransport::FailoverFulcrumTransport(std::vector<FulcrumTransport*> transports)
    : transports_(std::move(transports)) {
  if (transports_.empty()) throw std::invalid_argument("at least one Fulcrum transport is required");
}

FulcrumProvider::FulcrumProvider(std::string network, FulcrumTransport& transport)
    : network_(std::move(network)), transport_(transport) {
  if (network_ != "bch:bitcoincash" && network_ != "bch:bchtest")
    throw std::invalid_argument("unsupported BCH network");
}

}
