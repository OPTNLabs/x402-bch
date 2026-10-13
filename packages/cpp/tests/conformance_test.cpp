#include <fstream>
#include <algorithm>
#include <iostream>
#include <regex>
#include <string>
#include <tuple>
#include "x402_bch.hpp"
#include "x402_bch_sdk.hpp"
#include "x402_bch/address.hpp"
#include "x402_bch/builder.hpp"
#include "x402_bch/client.hpp"
#include "x402_bch/crypto.hpp"
#include "x402_bch/facilitator.hpp"
#include "x402_bch/payment.hpp"
#include "x402_bch/protocol.hpp"
#include "x402_bch/provider.hpp"
#include "x402_bch/settlement.hpp"
#include "x402_bch/server.hpp"
#include "x402_bch/transaction.hpp"
#include "x402_bch/vm.hpp"
#include "x402_bch/wallet.hpp"

namespace {
struct SdkWallet final : x402bch::Wallet {
  std::vector<uint8_t> raw;
  x402bch::TransactionRequest request;
  std::vector<uint8_t> create_payment(const x402bch::TransactionRequest& value) override {
    request = value;
    return raw;
  }
};

struct SdkSigner final : x402bch::Signer {
  std::vector<uint8_t> public_key() const override { return std::vector<uint8_t>(33, 0x11); }
  std::vector<uint8_t> sign_digest(const std::vector<uint8_t>&) override { return {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}; }
  std::string address(const std::string&) const override { return "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf"; }
};

struct SdkProvider final : x402bch::Provider {
  int broadcasts = 0;
  std::string network() const override { return "bch:bitcoincash"; }
  std::vector<x402bch::Utxo> list_utxos(const std::string&) override { return {}; }
  x402bch::TransactionOutput source_output(const std::string&, uint32_t) override {
    return {100000, {}, std::nullopt};
  }
  std::string outpoint_status(const std::string&, uint32_t) override { return "unspent"; }
  std::string broadcast(const std::vector<uint8_t>& raw) override {
    broadcasts++;
    return x402bch::transaction_id(x402bch::encode_base64(raw));
  }
  std::optional<std::vector<uint8_t>> transaction(const std::string&) override { return std::nullopt; }
  x402bch::ProviderStatus transaction_status(const std::string&) override { return {"confirmed", 100}; }
  uint64_t tip_height() override { return 100; }
  bool has_double_spend_proof(const std::string&) override { return false; }
};

struct FailingTransport final : x402bch::FulcrumTransport {
  std::string request(const std::string&, const std::string&) override {
    throw std::runtime_error("offline");
  }
};

struct WorkingTransport final : x402bch::FulcrumTransport {
  std::string request(const std::string&, const std::string&) override { return "ok"; }
};
}  // namespace

int main() {
  std::ifstream input("spec/conformance/v1/payment-requirements.json");
  const std::string json((std::istreambuf_iterator<char>(input)), {});
  if (json.find("\"version\": 1") == std::string::npos ||
      json.find("\"scheme\": \"exact\"") == std::string::npos) return 1;
  if (!std::regex_match("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        std::regex("[0-9a-f]{64}"))) return 1;
  x402bch::validate_requirements(2, "exact", "1000", "upfront");
  if (x402bch::request_hash("{\"url\":\"https://example.test/resource\"}") != "1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675") return 1;
  x402bch::Requirements requirements{2, "exact", "bch:bchtest", "1000", "BCH", "bchtest:merchant", "upfront", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
  x402bch::PaymentPayload payload{2, "AQID", requirements};
  x402bch::validate_payment_payload(payload, requirements);
  auto mismatched_payload = payload;
  mismatched_payload.accepted.request_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  try { x402bch::validate_payment_payload(mismatched_payload, requirements); return 1; }
  catch (const std::invalid_argument&) {}
  payload.transaction = "bad";
  try { x402bch::validate_payment_payload(payload, requirements); return 1; }
  catch (const std::invalid_argument&) {}
  std::ifstream server_input("spec/conformance/v1/server-requirements.json");
  const std::string server_json((std::istreambuf_iterator<char>(server_input)), {});
  if (server_json.find("\"id\": \"native-default\"") == std::string::npos ||
      server_json.find("\"id\": \"nft-only-cashtoken\"") == std::string::npos) return 1;
  const auto native_requirements = x402bch::build_native_requirements(
      "bch:bchtest", "bchtest:merchant", "1000");
  if (native_requirements.version != 2 || native_requirements.scheme != "exact" ||
      native_requirements.network != "bch:bchtest" || native_requirements.amount != "1000" ||
      native_requirements.asset != "BCH" || native_requirements.pay_to != "bchtest:merchant" ||
      native_requirements.max_timeout_seconds != 300 ||
      native_requirements.asset_transfer_method != "native") return 1;
  const auto token_requirements = x402bch::build_cash_token_requirements(
      "bch:bchtest", "bchtest:tokenmerchant",
      "2222222222222222222222222222222222222222222222222222222222222222", "0", "1000",
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "none",
      x402bch::hex_to_bytes("5a5a5a5a"));
  if (token_requirements.asset_transfer_method != "cashtoken" ||
      token_requirements.token_value != "1000" ||
      token_requirements.token_category != "2222222222222222222222222222222222222222222222222222222222222222" ||
      token_requirements.token_amount != "0" || token_requirements.token_capability != "none" ||
      token_requirements.token_commitment != x402bch::hex_to_bytes("5a5a5a5a")) return 1;
  std::ifstream sdk_input("spec/conformance/v1/sdk-lifecycle.json");
  const std::string sdk_json((std::istreambuf_iterator<char>(sdk_input)), {});
  if (sdk_json.find("\"version\": 1") == std::string::npos ||
      sdk_json.find("\"walletRequest\"") == std::string::npos) return 1;
  const auto sdk_requirements = x402bch::build_native_requirements(
      "bch:bitcoincash", "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf", "1000");
  const auto sdk_encoded = "AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiATJrlQh+1HHiXNlhiWdL97/QnR0aAE//NQGIuj0NB4AAIgO7sholeiC2XV4xGiBYgm8x/lzDrqhumDiMjzVjDE+oZBIQMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0Hj/////8C6AMAAAAAAAAZdqkUIiIiIiIiIiIiIiIiIiIiIiIiIiKIrNaBAQAAAAAAGXapFHmwAIh2JrKUqRRQGkzSJrWLI1mDiKwAAAAA";
  SdkWallet sdk_wallet;
  sdk_wallet.raw = x402bch::decode_base64(sdk_encoded);
  SdkProvider sdk_provider;
  const auto sdk_payload = x402bch::ExactBchClient(sdk_wallet, sdk_provider).create_payment_payload(sdk_requirements);
  if (sdk_wallet.request.network != "mainnet" || sdk_wallet.request.value != "1000") return 1;
  x402bch::InMemorySettlementStore sdk_store;
  x402bch::ExactBchFacilitator sdk_facilitator(sdk_provider, sdk_store);
  if (!sdk_facilitator.verify(sdk_payload, sdk_requirements).is_valid) return 1;
  if (!sdk_facilitator.settle(sdk_payload, sdk_requirements).success || sdk_provider.broadcasts != 1) return 1;
  SdkSigner sdk_signer;
  const auto built = x402bch::build_and_sign_native_payment(
      {{std::string(64, 'a'), 0, 5000, x402bch::hex_to_bytes("76a914111111111111111111111111111111111111111188ac"), std::nullopt, std::nullopt}},
      x402bch::hex_to_bytes("76a914333333333333333333333333333333333333333388ac"), 1000, sdk_signer, "mainnet");
  if (built.empty()) return 1;
  FailingTransport failing_transport;
  WorkingTransport working_transport;
  x402bch::FailoverFulcrumTransport failover({&failing_transport, &working_transport});
  if (failover.request("server.version", "[]") != "ok") return 1;
  const std::string hd_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const std::vector<std::tuple<std::string, uint32_t, uint32_t, std::string, std::string>> hd_vectors = {
      {"bch:bchtest", 1, 0, "bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4", "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6"},
      {"bch:bchtest", 1, 1, "bchtest:qqwtwwfqkkkr3arquwx7k6ztn39yprlncq2gq6et74", "0320282ac6b3782721b1742c294530a9f250413361abbff659acc8352bc4c1f3f1"},
      {"bch:bitcoincash", 145, 0, "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6", "02bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217"},
      {"bch:bitcoincash", 145, 1, "bitcoincash:qr8aeharupyrmhfu0d4tdmsnc5y8cfk47y6qrsjsrx", "02f178b9410d11e47e10bef8a8e4bc53e48d9ae15864a024a54f87a802dad5f514"}};
  for (const auto& vector : hd_vectors) {
    const auto derived = x402bch::derive_bch_wallet_address(hd_mnemonic, std::get<0>(vector), std::get<2>(vector), 0, 0, {}, std::get<1>(vector));
    if (derived.address != std::get<3>(vector) || x402bch::bytes_to_hex(derived.public_key) != std::get<4>(vector)) return 1;
  }
  bool rejected = false;
  try { (void)x402bch::derive_bch_wallet_address("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo", "bch:bchtest", 0, 0, 0, {}, std::nullopt); } catch (const std::exception&) { rejected = true; }
  if (!rejected) throw std::runtime_error("invalid BIP39 checksum must be rejected");
  x402bch::Secp256k1BchSigner hd_signer(hd_mnemonic, "bch:bchtest");
  if (hd_signer.address("bch:bchtest") != std::get<3>(hd_vectors[0]) || x402bch::bytes_to_hex(hd_signer.public_key()) != std::get<4>(hd_vectors[0]) || hd_signer.sign_digest(std::vector<uint8_t>(32)).empty()) return 1;
  x402bch::validate_transaction_envelope("AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiATJrlQh+1HHiXNlhiWdL97/QnR0aAE//NQGIuj0NB4AAIgO7sholeiC2XV4xGiBYgm8x/lzDrqhumDiMjzVjDE+oZBIQMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0Hj/////8C6AMAAAAAAAAZdqkUIiIiIiIiIiIiIiIiIiIiIiIiIiKIrNaBAQAAAAAAGXapFHmwAIh2JrKUqRRQGkzSJrWLI1mDiKwAAAAA");
  try { x402bch::validate_transaction_envelope("AQID"); return 1; }
  catch (const std::invalid_argument&) {}
  std::ifstream transaction_input("spec/conformance/v1/transaction.json");
  const std::string transaction_json((std::istreambuf_iterator<char>(transaction_input)), {});
  std::smatch raw_match, txid_match;
  if (!std::regex_search(transaction_json, raw_match, std::regex("\\\"rawTransaction\\\": \\\"([0-9a-f]+)\\\"")) ||
      !std::regex_search(transaction_json, txid_match, std::regex("\\\"txid\\\": \\\"([0-9a-f]+)\\\"")) ||
      x402bch::transaction_id("AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiATJrlQh+1HHiXNlhiWdL97/QnR0aAE//NQGIuj0NB4AAIgO7sholeiC2XV4xGiBYgm8x/lzDrqhumDiMjzVjDE+oZBIQMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0Hj/////8C6AMAAAAAAAAZdqkUIiIiIiIiIiIiIiIiIiIiIiIiIiKIrNaBAQAAAAAAGXapFHmwAIh2JrKUqRRQGkzSJrWLI1mDiKwAAAAA") != txid_match[1]) return 1;
  const auto encoded_transaction = "AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiATJrlQh+1HHiXNlhiWdL97/QnR0aAE//NQGIuj0NB4AAIgO7sholeiC2XV4xGiBYgm8x/lzDrqhumDiMjzVjDE+oZBIQMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0Hj/////8C6AMAAAAAAAAZdqkUIiIiIiIiIiIiIiIiIiIiIiIiIiKIrNaBAQAAAAAAGXapFHmwAIh2JrKUqRRQGkzSJrWLI1mDiKwAAAAA";
  const auto parsed = x402bch::parse_transaction(encoded_transaction);
  if (x402bch::bytes_to_hex(x402bch::serialize_transaction(parsed)) != raw_match[1]) return 1;
  const auto verified = x402bch::verify_native_payment(parsed, {"100000"}, "1000", "76a914222222222222222222222222222222222222222288ac", 1, 546);
  if (verified.txid != txid_match[1] || verified.fee != "226" || verified.serialized_size != 225) return 1;
  const auto address_script = x402bch::hex_to_bytes("76a914111111111111111111111111111111111111111188ac");
  const auto decoded_address = x402bch::decode_cash_address("bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue", "bch:bitcoincash");
  if (decoded_address.token_support || decoded_address.script_pubkey != address_script) return 1;
  if (x402bch::encode_cash_address(address_script, "bch:bitcoincash", false) != "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue") return 1;
  try { x402bch::decode_cash_address("bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue", "bch:bchtest"); return 1; }
  catch (const std::invalid_argument&) {}
  const auto token_encoded = "AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiAWmSA8KUc2jz9Vo6U9E/iL6d/2ZTPC3rdRKmGLJhxqcgIgBMx/+JD+oilVx2SicznxB9Y+WWyTGJS94ywsRlgOFLFBIQIID6q4M8R4e6q6wutH9komVPkqG3DKjcLwlnkXmsNiof////8C6AMAAAAAAABI7wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEP3oA6ogIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiKHgoEBAAAAAAA+7wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEP30AXapFHwibJ3dlYToZkNdjqDOFsnQSQW0iKwAAAAA";
  const auto token_transaction = x402bch::parse_transaction(token_encoded);
  if (x402bch::bytes_to_hex(x402bch::serialize_transaction(token_transaction)) != "02000000010000000000000000000000000000000000000000000000000000000000000000000000006a47304402201699203c2947368f3f55a3a53d13f88be9dff66533c2deb7512a618b261c6a72022004cc7ff890fea22955c764a27339f107d63e596c931894bde32c2c46580e14b1412102080faab833c4787baabac2eb47f64a2654f92a1b70ca8dc2f09679179ac362a1ffffffff02e80300000000000048ef010000000000000000000000000000000000000000000000000000000000000010fde803aa2022222222222222222222222222222222222222222222222222222222222222228782810100000000003eef010000000000000000000000000000000000000000000000000000000000000010fdf40176a9147c226c9ddd9584e866435d8ea0ce16c9d04905b488ac00000000") return 1;
  if (!token_transaction.outputs[0].token.has_value() || token_transaction.outputs[0].token->amount != 1000 || !token_transaction.outputs[1].token.has_value() || token_transaction.outputs[1].token->amount != 500) return 1;
  const auto verified_token = x402bch::verify_cash_token_payment(token_transaction, {"100000"}, {{"0000000000000000000000000000000000000000000000000000000000000001", 1500, "none", {}}}, "1000", "aa20222222222222222222222222222222222222222222222222222222222222222287", "0000000000000000000000000000000000000000000000000000000000000001", "1000", "", {}, 1, 1000);
  if (verified_token.txid != "278112a293e95223910de4747c15c0d51ab7195d43254fb8e837d8d8ef191609" || verified_token.fee != "310") return 1;
const auto nft_encoded = "AgAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAABqRzBEAiBr4fuvWuiOstaOVbLu2/flHqinVuv8wOUuLRLtJifaWgIgbkmcYSzjV0Ku4DOq575B0SPPjkF7DTbDgRMGTKpzDKJBIQM9VbQmnQ233MpxZcKhMTLZuq/s84wOidg4O6bB83D8eP////8C6AMAAAAAAABk7xERERERERERERERERERERERERERERERERERERERERERYChaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpadqkUERERERERERERERERERERERERERGIrIuBAQAAAAAAGXapFFq8YGY3j2xzGqbxng0uRp6N7BwuiKwAAAAA";
  const auto nft_transaction = x402bch::parse_transaction(nft_encoded);
if (x402bch::bytes_to_hex(x402bch::serialize_transaction(nft_transaction)) != "02000000010101010101010101010101010101010101010101010101010101010101010101000000006a47304402206be1fbaf5ae88eb2d68e55b2eedbf7e51ea8a756ebfcc0e52e2d12ed2627da5a02206e499c612ce35742aee033aae7be41d123cf8e417b0d36c38113064caa730ca24121033d55b4269d0db7dcca7165c2a13132d9baafecf38c0e89d8383ba6c1f370fc78ffffffff02e80300000000000064ef111111111111111111111111111111111111111111111111111111111111111160285a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a76a914111111111111111111111111111111111111111188ac8b810100000000001976a9145abc6066378f6c731aa6f19e0d2e469e8dec1c2e88ac00000000") return 1;
  const auto nft_merchant_commitment = x402bch::hex_to_bytes("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
  const auto verified_nft = x402bch::verify_cash_token_payment(nft_transaction, {"100000"}, {{"1111111111111111111111111111111111111111111111111111111111111111", 0, "none", nft_merchant_commitment}}, "1000", "76a914111111111111111111111111111111111111111188ac", "1111111111111111111111111111111111111111111111111111111111111111", "0", "none", nft_merchant_commitment, 1, 1000);
  std::ifstream capability_input("spec/conformance/v1/cashtoken-capabilities.json");
  std::string capability_json((std::istreambuf_iterator<char>(capability_input)), {});
  capability_json.erase(std::remove(capability_json.begin(), capability_json.end(), '\n'), capability_json.end());
  capability_json.erase(std::remove(capability_json.begin(), capability_json.end(), '\r'), capability_json.end());
  const std::regex capability_pattern("\\\"capability\\\"\\s*:\\s*\\\"([^\\\"]+)\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"txid\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\".*?\\\"fee\\\"\\s*:\\s*\\\"([0-9]+)");
  const std::string base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const auto hex_to_base64 = [&](const std::string& hex) {
    const auto raw = x402bch::hex_to_bytes(hex);
    std::string encoded;
    for (size_t offset = 0; offset < raw.size(); offset += 3) {
      const uint32_t value = (static_cast<uint32_t>(raw[offset]) << 16) |
          (offset + 1 < raw.size() ? static_cast<uint32_t>(raw[offset + 1]) << 8 : 0) |
          (offset + 2 < raw.size() ? static_cast<uint32_t>(raw[offset + 2]) : 0);
      encoded.push_back(base64_alphabet[(value >> 18) & 63]);
      encoded.push_back(base64_alphabet[(value >> 12) & 63]);
      encoded.push_back(offset + 1 < raw.size() ? base64_alphabet[(value >> 6) & 63] : '=');
      encoded.push_back(offset + 2 < raw.size() ? base64_alphabet[value & 63] : '=');
    }
    return encoded;
  };
  size_t capability_count = 0;
  for (auto it = std::sregex_iterator(capability_json.begin(), capability_json.end(), capability_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto encoded = hex_to_base64((*it)[2].str());
    const auto transaction = x402bch::parse_transaction(encoded);
    const auto verified = x402bch::verify_cash_token_payment(
        transaction, {"100000"},
        {{"1111111111111111111111111111111111111111111111111111111111111111", 0,
          (*it)[1].str(), nft_merchant_commitment}},
        "1000", "76a914111111111111111111111111111111111111111188ac",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0", (*it)[1].str(), nft_merchant_commitment, 1, 1000);
    if (verified.txid != (*it)[3].str() || verified.fee != (*it)[4].str() ||
        verified.serialized_size != 300) return 1;
    capability_count++;
  }
  if (capability_count != 2) return 1;
  std::ifstream negative_input("spec/conformance/v1/cashtoken-negative.json");
  std::string negative_json((std::istreambuf_iterator<char>(negative_input)), {});
  negative_json.erase(std::remove(negative_json.begin(), negative_json.end(), '\n'), negative_json.end());
  negative_json.erase(std::remove(negative_json.begin(), negative_json.end(), '\r'), negative_json.end());
  const std::regex negative_parse_pattern("\\\"kind\\\"\\s*:\\s*\\\"parse\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"errorCode\\\"");
  size_t negative_parse_count = 0;
  for (auto it = std::sregex_iterator(negative_json.begin(), negative_json.end(), negative_parse_pattern);
       it != std::sregex_iterator(); ++it) {
    try {
      x402bch::parse_transaction(hex_to_base64((*it)[1].str()));
      return 1;
    } catch (const std::invalid_argument&) {}
    negative_parse_count++;
  }
  if (negative_parse_count != 3) { std::cerr << "negative parse count: " << negative_parse_count << "\n"; return 1; }
  const std::regex negative_verify_pattern("\\\"kind\\\"\\s*:\\s*\\\"verify\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"errorCode\\\"");
  auto negative_verify = std::sregex_iterator(negative_json.begin(), negative_json.end(), negative_verify_pattern);
  if (negative_verify == std::sregex_iterator()) { std::cerr << "negative verify case not found\n"; return 1; }
  try {
    const auto transaction = x402bch::parse_transaction(hex_to_base64((*negative_verify)[1].str()));
    x402bch::verify_cash_token_payment(transaction, {"100000"},
        {{"0000000000000000000000000000000000000000000000000000000000000001", 1499, "none", {}}},
        "1000", "aa20222222222222222222222222222222222222222222222222222222222222222287",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "1000", "", {}, 1, 1000);
    return 1;
  } catch (const std::invalid_argument&) {}
  std::ifstream signature_input("spec/conformance/v1/p2pkh-signature.json");
  std::string signature_json((std::istreambuf_iterator<char>(signature_input)), {});
  signature_json.erase(std::remove(signature_json.begin(), signature_json.end(), '\n'), signature_json.end());
  signature_json.erase(std::remove(signature_json.begin(), signature_json.end(), '\r'), signature_json.end());
  const std::regex signature_pattern("\\\"sourceValue\\\"\\s*:\\s*\\\"([0-9]+)\\\".*?\\\"sourceScriptPubKey\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"expectedSighash\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\".*?\\\"expectedPayerHash\\\"\\s*:\\s*\\\"([0-9a-f]{40})\\\".*?\\\"expected\\\"\\s*:\\s*\\\"(accept|reject)\\\"");
  size_t signature_count = 0;
  for (auto it = std::sregex_iterator(signature_json.begin(), signature_json.end(), signature_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto transaction = x402bch::parse_transaction(hex_to_base64((*it)[3].str()));
    const auto source_script = x402bch::hex_to_bytes((*it)[2].str());
    const auto digest = x402bch::signing_hash(transaction, 0, std::stoull((*it)[1].str()), source_script);
    if (x402bch::bytes_to_hex(digest) != (*it)[4].str()) return 1;
    try {
      const auto payer_hash = x402bch::verify_p2pkh_input(transaction, 0, std::stoull((*it)[1].str()), source_script);
      if ((*it)[6].str() != "accept" || x402bch::bytes_to_hex(payer_hash) != (*it)[5].str()) return 1;
    } catch (const std::invalid_argument&) {
      if ((*it)[6].str() == "accept") return 1;
    }
    signature_count++;
  }
  if (signature_count != 2) return 1;
  std::ifstream request_hash_input("spec/conformance/v1/request-hash.json");
  std::string request_hash_json((std::istreambuf_iterator<char>(request_hash_input)), {});
  request_hash_json.erase(std::remove(request_hash_json.begin(), request_hash_json.end(), '\n'), request_hash_json.end());
  request_hash_json.erase(std::remove(request_hash_json.begin(), request_hash_json.end(), '\r'), request_hash_json.end());
  const std::regex request_hash_pattern("\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"requestHash\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\".*?\\\"expected\\\"\\s*:\\s*\\\"(accept|reject)\\\"");
  size_t request_hash_count = 0;
  for (auto it = std::sregex_iterator(request_hash_json.begin(), request_hash_json.end(), request_hash_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto transaction = x402bch::parse_transaction(hex_to_base64((*it)[1].str()));
    try {
      x402bch::assert_request_hash_commitment(transaction, (*it)[2].str());
      if ((*it)[3].str() != "accept") return 1;
    } catch (const std::invalid_argument&) {
      if ((*it)[3].str() == "accept") return 1;
    }
    request_hash_count++;
  }
  if (request_hash_count != 3) return 1;
  std::ifstream p2sh_input("spec/conformance/v1/p2sh-commitment.json");
  std::string p2sh_json((std::istreambuf_iterator<char>(p2sh_input)), {});
  p2sh_json.erase(std::remove(p2sh_json.begin(), p2sh_json.end(), '\n'), p2sh_json.end());
  p2sh_json.erase(std::remove(p2sh_json.begin(), p2sh_json.end(), '\r'), p2sh_json.end());
  const std::regex p2sh_pattern("\\\"inputIndex\\\"\\s*:\\s*(\\d+).*?\\\"sourceScriptPubKey\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"expected\\\"\\s*:\\s*\\\"(accept|reject)\\\"");
  size_t p2sh_count = 0;
  for (auto it = std::sregex_iterator(p2sh_json.begin(), p2sh_json.end(), p2sh_pattern); it != std::sregex_iterator(); ++it) {
    const auto transaction = x402bch::parse_transaction(hex_to_base64((*it)[3].str()));
    try {
      x402bch::verify_p2sh_redeem_script(transaction, std::stoul((*it)[1].str()), x402bch::hex_to_bytes((*it)[2].str()));
      if ((*it)[4].str() != "accept") return 1;
    } catch (const std::invalid_argument&) {
      if ((*it)[4].str() == "accept") return 1;
    }
    p2sh_count++;
  }
  if (p2sh_count != 4) return 1;
  std::ifstream settlement_input("spec/conformance/v1/settlement-policy.json");
  std::string settlement_json((std::istreambuf_iterator<char>(settlement_input)), {});
  settlement_json.erase(std::remove(settlement_json.begin(), settlement_json.end(), '\n'), settlement_json.end());
  settlement_json.erase(std::remove(settlement_json.begin(), settlement_json.end(), '\r'), settlement_json.end());
  const std::regex settlement_block_pattern("\\{\\s*\\\"id\\\".*?\\}", std::regex::ECMAScript | std::regex::optimize);
  const auto field_string = [](const std::string& block, const std::string& name) {
    std::smatch match;
    if (!std::regex_search(block, match, std::regex("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"")))
      throw std::runtime_error("missing settlement string field: " + name);
    return match[1].str();
  };
  const auto field_optional_string = [](const std::string& block, const std::string& name) -> std::optional<std::string> {
    std::smatch match;
    if (!std::regex_search(block, match, std::regex("\\\"" + name + "\\\"\\s*:\\s*(?:\\\"([^\\\"]*)\\\"|null)")))
      throw std::runtime_error("missing optional settlement string field: " + name);
    if (match[1].matched) return match[1].str();
    return std::nullopt;
  };
  const auto field_uint = [](const std::string& block, const std::string& name) -> std::optional<uint64_t> {
    std::smatch match;
    if (!std::regex_search(block, match, std::regex("\"" + name + "\"\\s*:\\s*([0-9]+)"))) return std::nullopt;
    return std::stoull(match[1].str());
  };
  const auto field_bool = [](const std::string& block, const std::string& name, bool fallback) {
    std::smatch match;
    if (!std::regex_search(block, match, std::regex("\"" + name + "\"\\s*:\\s*(true|false)"))) return fallback;
    return match[1].str() == "true";
  };
  size_t settlement_count = 0;
  for (auto it = std::sregex_iterator(settlement_json.begin(), settlement_json.end(), settlement_block_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto block = it->str();
    const auto strategy = field_string(block, "strategy");
    const auto status = field_string(block, "status");
    const auto expected = field_bool(block, "expectedAccepted", false);
    if (x402bch::accepts_bch_settlement(strategy, status, field_uint(block, "confirmations").value_or(0),
                                        field_uint(block, "height"), field_uint(block, "tipHeight"),
                                        field_bool(block, "doubleSpendProof", false)) != expected)
      return 1;
    settlement_count++;
  }
  if (settlement_count != 13) return 1;
  std::ifstream observation_input("spec/conformance/v1/provider-observation.json");
  std::string observation_json((std::istreambuf_iterator<char>(observation_input)), {});
  observation_json.erase(std::remove(observation_json.begin(), observation_json.end(), '\n'), observation_json.end());
  observation_json.erase(std::remove(observation_json.begin(), observation_json.end(), '\r'), observation_json.end());
  const std::regex observation_block_pattern("\\{\\s*\\\"id\\\".*?\\}");
  const auto observation_string = [](const std::string& block, const std::string& name) {
    std::smatch match;
    if (!std::regex_search(block, match, std::regex("\"" + name + "\"\\s*:\\s*\"([^\"]*)\""))) return std::string();
    return match[1].str();
  };
  const auto observation_bool = [](const std::string& block, const std::string& name) {
    std::smatch match;
    if (!std::regex_search(block, match, std::regex("\"" + name + "\"\\s*:\\s*(true|false)"))) return false;
    return match[1].str() == "true";
  };
  std::map<std::string, std::optional<std::vector<uint8_t>>> provider_bytes;
  size_t observation_count = 0;
  for (auto it = std::sregex_iterator(observation_json.begin(), observation_json.end(), observation_block_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto block = it->str();
    const auto raw_hex = observation_string(block, "rawTransaction");
    const bool missing = std::regex_search(block, std::regex("\"rawTransaction\"\\s*:\\s*null"));
    const auto raw = raw_hex.empty() ? std::vector<uint8_t>{} : x402bch::hex_to_bytes(raw_hex);
    if (x402bch::provider_transaction_matches(observation_string(block, "candidateTxid"), raw) != observation_bool(block, "expected")) return 1;
    provider_bytes[observation_string(block, "id")] = missing ? std::nullopt : std::optional<std::vector<uint8_t>>(raw);
    observation_count++;
  }
  if (observation_count != 5) return 1;
  std::ifstream provider_settlement_input("spec/conformance/v1/settlement-provider.json");
  std::string provider_settlement_json((std::istreambuf_iterator<char>(provider_settlement_input)), {});
  provider_settlement_json.erase(std::remove(provider_settlement_json.begin(), provider_settlement_json.end(), '\n'), provider_settlement_json.end());
  provider_settlement_json.erase(std::remove(provider_settlement_json.begin(), provider_settlement_json.end(), '\r'), provider_settlement_json.end());
  size_t provider_settlement_count = 0;
  for (auto it = std::sregex_iterator(provider_settlement_json.begin(), provider_settlement_json.end(), settlement_block_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto block = it->str();
    const auto provider_case = field_string(block, "providerCase");
    const auto found = provider_bytes.find(provider_case);
    if (found == provider_bytes.end()) return 1;
    if (x402bch::observe_bch_provider_transaction(field_string(block, "candidateTxid"), found->second) != field_string(block, "expectedObservation")) return 1;
    const auto result = x402bch::resolve_bch_settlement_from_provider(
        field_string(block, "candidateTxid"), field_bool(block, "candidateValid", false),
        field_bool(block, "bindingMatches", false), field_string(block, "existingClaim"),
        field_string(block, "strategy"), field_string(block, "status"),
        field_uint(block, "confirmations").value_or(0), field_uint(block, "height"),
        field_uint(block, "tipHeight"), field_string(block, "broadcastAttempt"), found->second);
    if (result.state != field_string(block, "expectedState") ||
        result.transaction_id != field_string(block, "expectedTransactionId") ||
        result.next_action != field_string(block, "expectedAction")) return 1;
    provider_settlement_count++;
  }
  if (provider_settlement_count != 7) return 1;
  std::ifstream source_output_input("spec/conformance/v1/provider-source-output.json");
  std::string source_output_json((std::istreambuf_iterator<char>(source_output_input)), {});
  source_output_json.erase(std::remove(source_output_json.begin(), source_output_json.end(), '\n'), source_output_json.end());
  source_output_json.erase(std::remove(source_output_json.begin(), source_output_json.end(), '\r'), source_output_json.end());
  size_t source_output_count = 0;
  for (auto it = std::sregex_iterator(source_output_json.begin(), source_output_json.end(), settlement_block_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto block = it->str();
    const auto found = provider_bytes.find(field_string(block, "providerCase"));
    if (found == provider_bytes.end()) return 1;
    const auto result = x402bch::get_bch_provider_source_output(
        field_string(block, "sourceTxid"), static_cast<uint32_t>(field_uint(block, "vout").value_or(0)), found->second);
    if (result.observation != field_string(block, "expectedObservation")) return 1;
    const auto expected_value = field_optional_string(block, "expectedValue");
    const auto expected_script = field_optional_string(block, "expectedScriptPubKey");
    if (!expected_value.has_value() || !expected_script.has_value()) {
      if (result.source_output.has_value()) return 1;
    } else if (!result.source_output.has_value() || std::to_string(result.source_output->value) != *expected_value ||
               x402bch::bytes_to_hex(result.source_output->script_pubkey) != *expected_script) {
      return 1;
    }
    source_output_count++;
  }
  if (source_output_count != 6) return 1;
  std::ifstream outcome_input("spec/conformance/v1/settlement-outcome.json");
  std::string outcome_json((std::istreambuf_iterator<char>(outcome_input)), {});
  outcome_json.erase(std::remove(outcome_json.begin(), outcome_json.end(), '\n'), outcome_json.end());
  outcome_json.erase(std::remove(outcome_json.begin(), outcome_json.end(), '\r'), outcome_json.end());
  size_t outcome_count = 0;
  for (auto it = std::sregex_iterator(outcome_json.begin(), outcome_json.end(), settlement_block_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto block = it->str();
    const auto outcome = x402bch::resolve_bch_settlement_outcome(
        field_bool(block, "candidateValid", false), field_string(block, "providerObservation"),
        field_string(block, "strategy"), field_string(block, "status"),
        field_uint(block, "confirmations").value_or(0), field_uint(block, "height"),
        field_uint(block, "tipHeight"), field_bool(block, "doubleSpendProof", false));
    if (outcome != field_string(block, "expectedOutcome")) return 1;
    outcome_count++;
  }
  if (outcome_count != 8) return 1;
  std::ifstream integration_input("spec/conformance/v1/settlement-integration.json");
  std::string integration_json((std::istreambuf_iterator<char>(integration_input)), {});
  integration_json.erase(std::remove(integration_json.begin(), integration_json.end(), '\n'), integration_json.end());
  integration_json.erase(std::remove(integration_json.begin(), integration_json.end(), '\r'), integration_json.end());
  size_t integration_count = 0;
  for (auto it = std::sregex_iterator(integration_json.begin(), integration_json.end(), settlement_block_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto block = it->str();
    const auto result = x402bch::resolve_bch_settlement_integration(
        field_string(block, "candidateTxid"), field_bool(block, "candidateValid", false),
        field_bool(block, "bindingMatches", false), field_string(block, "existingClaim"),
        field_string(block, "providerObservation"), field_string(block, "strategy"),
        field_string(block, "status"), field_uint(block, "confirmations").value_or(0),
        field_uint(block, "height"), field_uint(block, "tipHeight"),
        field_string(block, "broadcastAttempt"));
    if (result.state != field_string(block, "expectedState") ||
        result.transaction_id != field_string(block, "expectedTransactionId") ||
        result.next_action != field_string(block, "expectedAction"))
      return 1;
    integration_count++;
  }
  if (integration_count != 11) return 1;
  std::ifstream vm_input("spec/conformance/v1/bch-vm.json");
  std::string vm_json((std::istreambuf_iterator<char>(vm_input)), {});
  vm_json.erase(std::remove(vm_json.begin(), vm_json.end(), '\n'), vm_json.end());
  vm_json.erase(std::remove(vm_json.begin(), vm_json.end(), '\r'), vm_json.end());
  if (vm_json.find("\"version\": 1") == std::string::npos ||
      vm_json.find("\"profile\": \"bch-bounded-v1\"") == std::string::npos)
    return 1;
  const auto optional_string = [](const std::string& block, const std::string& name) {
    std::smatch match;
    if (!std::regex_search(block, match, std::regex("\"" + name + "\"\\s*:\\s*(?:\"([^\"]+)\"|null)")))
      throw std::runtime_error("missing VM field: " + name);
    return match[1].str();
  };
  size_t vm_count = 0;
  for (auto it = std::sregex_iterator(vm_json.begin(), vm_json.end(), settlement_block_pattern);
       it != std::sregex_iterator(); ++it) {
    const auto block = it->str();
    const auto result = x402bch::evaluate_bch_vm(
        x402bch::hex_to_bytes(field_string(block, "unlockingScript")),
        x402bch::hex_to_bytes(field_string(block, "lockingScript")));
    if (result.accepted != field_bool(block, "expectedAccepted", false) ||
        result.error_code != optional_string(block, "expectedError"))
      return 1;
    vm_count++;
  }
  if (vm_count != 12) return 1;
  std::cout << "cpp conformance fixture: ok\n";
}
