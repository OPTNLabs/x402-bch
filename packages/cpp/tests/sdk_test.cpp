#include "x402_bch_sdk.hpp"
#include "x402_bch/diagnostics.hpp"

#include <fstream>
#include <iostream>
#include <regex>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

namespace {
using namespace x402bch;

const std::string kMnemonic =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const std::string kMerchantScript = "76a914333333333333333333333333333333333333333388ac";

std::vector<uint8_t> decode_base64(const std::string& value) {
  const std::string alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<uint8_t> result;
  uint32_t buffer = 0;
  int bits = 0;
  for (const char item : value) {
    if (item == '=') break;
    const auto position = alphabet.find(item);
    if (position == std::string::npos) continue;
    buffer = (buffer << 6) | static_cast<uint32_t>(position);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      result.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
    }
  }
  return result;
}

std::string fixture_string(const std::string& json, const std::string& key) {
  std::smatch match;
  if (!std::regex_search(json, match,
                         std::regex("\\\"" + key + "\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"")))
    throw std::runtime_error("missing fixture field: " + key);
  return match[1].str();
}

void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

class FakeWallet final : public Wallet {
 public:
  explicit FakeWallet(std::vector<uint8_t> raw) : raw_(std::move(raw)) {}
  std::vector<uint8_t> create_payment(const TransactionRequest&) override { return raw_; }

 private:
  std::vector<uint8_t> raw_;
};

class FakeProvider final : public Provider {
 public:
  explicit FakeProvider(std::string txid) : txid_(std::move(txid)) {}
  std::string network() const override { return "bch:bitcoincash"; }
  std::vector<Utxo> list_utxos(const std::string&) override { return utxos; }
  TransactionOutput source_output(const std::string&, uint32_t) override {
    return {100000, source_script, std::nullopt};
  }
  std::string outpoint_status(const std::string&, uint32_t) override { return "unspent"; }
  std::string broadcast(const std::vector<uint8_t>&) override { ++broadcasts; return txid_; }
  std::optional<std::vector<uint8_t>> transaction(const std::string&) override { return observed; }
  ProviderStatus transaction_status(const std::string&) override { return {"confirmed", 100}; }
  uint64_t tip_height() override { return 100; }
  bool has_double_spend_proof(const std::string&) override { return false; }

  std::string txid_;
  std::optional<std::vector<uint8_t>> observed;
  std::vector<Utxo> utxos;
  std::vector<uint8_t> source_script =
      hex_to_bytes("76a91479b000887626b294a914501a4cd226b58b23598388ac");
  int broadcasts = 0;
};

class TokenTransport final : public FulcrumTransport {
 public:
  std::string request(const std::string& method, const std::string&) override {
    if (method == "blockchain.scripthash.listunspent") {
      return "[{\"tx_hash\":\"" + std::string(64, '2') +
             "\",\"tx_pos\":\"0\",\"value\":\"10000\",\"height\":\"123\","
             "\"tokenData\":{\"category\":\"" + std::string(64, '3') +
             "\",\"amount\":\"1000\"}}]";
    }
    if (method == "blockchain.transaction.get_height") return "0";
    throw std::runtime_error("unexpected Fulcrum method: " + method);
  }
};

class FailTransport final : public FulcrumTransport {
 public:
  std::string request(const std::string&, const std::string&) override {
    throw std::runtime_error("offline");
  }
};
class OkTransport final : public FulcrumTransport {
 public:
  std::string request(const std::string&, const std::string&) override { return "ok"; }
};

void test_settlement_store() {
  InMemorySettlementStore store;
  const auto first = std::string(64, 'a');
  const auto second = std::string(64, 'b');
  require(store.claim(first, "request-a") == "acquired", "first claim");
  require(store.claim(first, "request-a") == "same", "same claim");
  require(store.claim(first, "request-b") == "conflict", "conflicting claim");
  store.release(first);
  require(store.claim(first, "request-b") == "acquired", "released claim");
  require(store.claim(second, "request-a") == "acquired", "second claim");
  store.mark_accepted(second);
  store.release(second);
  require(store.claim(second, "request-b") == "conflict", "accepted claim");
}

void test_observed_retry() {
  std::ifstream input("spec/conformance/v1/sdk-lifecycle.json");
  const std::string json((std::istreambuf_iterator<char>(input)), {});
  const auto raw = decode_base64(fixture_string(json, "base64"));
  const auto txid = fixture_string(json, "txid");
  const auto requirements = build_native_requirements(
      "bch:bitcoincash", "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf", "1000");
  FakeWallet wallet(raw);
  FakeProvider provider(txid);
  provider.observed = raw;
  const auto payload = ExactBchClient(wallet, provider).create_payment_payload(requirements);
  InMemorySettlementStore store;
  const auto settled = ExactBchFacilitator(provider, store).settle(payload, requirements);
  require(settled.success && provider.broadcasts == 0, "observed retry rebroadcast");
}

void test_request_hash_builder() {
  Secp256k1BchSigner signer(kMnemonic, "bch:bitcoincash");
  const auto payer = decode_cash_address(signer.address("bch:bitcoincash"), "bch:bitcoincash");
  const auto raw = build_and_sign_native_payment(
      {{std::string(64, 'c'), 0, 100000, payer.script_pubkey, std::nullopt, std::nullopt}},
      hex_to_bytes(kMerchantScript), 1000, signer, "bch:bitcoincash", 1, 546, std::string(64, 'a'));
  const auto transaction = parse_transaction(encode_base64(raw));
  assert_request_hash_commitment(transaction, std::string(64, 'a'));
}

void test_cash_token_fee_input() {
  Secp256k1BchSigner signer(kMnemonic, "bch:bitcoincash");
  const auto payer = decode_cash_address(signer.address("bch:bitcoincash"), "bch:bitcoincash");
  const auto category = std::string(64, '1');
  const std::vector<Utxo> selected{
      {std::string(64, 'd'), 0, 1258, payer.script_pubkey, CashToken{category, 5, "none", {}}, std::nullopt},
      {std::string(64, 'e'), 0, 10000, payer.script_pubkey, std::nullopt, std::nullopt}};
  const auto raw = build_and_sign_cash_token_payment(
      selected, hex_to_bytes(kMerchantScript), 1000, 2, category, "none", {}, signer,
      "bch:bitcoincash", 1, 1000);
  const auto transaction = parse_transaction(encode_base64(raw));
  require(transaction.inputs.size() == 2 && transaction.outputs.front().token.has_value() &&
              transaction.outputs.front().token->amount == 2,
          "CashToken fee input");
}

void test_fulcrum_token_utxo() {
  TokenTransport transport;
  FulcrumProvider provider("bch:bitcoincash", transport);
  const auto utxos = provider.list_utxos("bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf");
  require(utxos.size() == 1 && utxos.front().token.has_value() &&
              utxos.front().token->category == std::string(64, '3') &&
              utxos.front().token->amount == 1000 && utxos.front().height == 123,
          "Fulcrum CashToken UTXO");
  require(provider.transaction_status("ignored").kind == "mempool", "Fulcrum mempool height");
}

void test_failover() {
  FailTransport failing;
  OkTransport working;
  FailoverFulcrumTransport transport({&failing, &working});
  require(transport.request("server.version", "[]") == "ok", "Fulcrum failover");
}

void test_socket_transport() {
  const int listener = socket(AF_INET, SOCK_STREAM, 0);
  require(listener >= 0, "Fulcrum socket listener");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  require(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "Fulcrum socket bind");
  require(listen(listener, 1) == 0, "Fulcrum socket listen");
  socklen_t length = sizeof(address);
  require(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0, "Fulcrum socket port");
  std::thread server([listener]() {
    const int client = accept(listener, nullptr, nullptr);
    if (client >= 0) {
      char buffer[4096];
      recv(client, buffer, sizeof(buffer), 0);
      const std::string response = "{\"id\":1,\"result\":[\"fulcrum-test\",\"1.0\"]}\n";
      send(client, response.data(), response.size(), 0);
      close(client);
    }
    close(listener);
  });
  SocketFulcrumTransport transport("127.0.0.1", ntohs(address.sin_port), 1000);
  const auto response = transport.request("server.version", "[\"x402-bch\",\"1.0\"]");
  require(response.find("fulcrum-test") != std::string::npos, "Fulcrum socket response");
  server.join();
}

void test_bchn_transport() {
  const int listener = socket(AF_INET, SOCK_STREAM, 0);
  require(listener >= 0, "BCHN socket listener");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  require(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "BCHN socket bind");
  require(listen(listener, 1) == 0, "BCHN socket listen");
  socklen_t length = sizeof(address);
  require(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0, "BCHN socket port");
  std::thread server([listener]() {
    const int client = accept(listener, nullptr, nullptr);
    if (client >= 0) {
      char buffer[4096];
      recv(client, buffer, sizeof(buffer), 0);
      const std::string body = "{\"id\":1,\"result\":[{\"allowed\":true,\"txid\":\"" + std::string(64, 'a') + "\"}]}";
      const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
      send(client, response.data(), response.size(), 0);
      close(client);
    }
    close(listener);
  });
  BchnRpcTransport transport("http://127.0.0.1:" + std::to_string(ntohs(address.sin_port)) + "/", 1000);
  const auto response = transport.test_mempool_accept({1, 2, 3});
  require(response.allowed && response.txid == std::string(64, 'a'), "BCHN RPC response");
  server.join();
}

void test_mocknet_provider() {
  const auto script = hex_to_bytes("76a914111111111111111111111111111111111111111188ac");
  const auto merchant = hex_to_bytes("76a914333333333333333333333333333333333333333388ac");
  const Utxo input{std::string(64, '1'), 0, 5000, script, std::nullopt, std::nullopt};
  MocknetProvider provider("bch:bchtest", {input}, 200);
  provider.register_transaction({std::string(64, '3'), {1, 2, 3}, {{input.txid, 0}}, {{1000, merchant, std::nullopt}, {3700, script, std::nullopt}}});
  require(provider.list_utxos("bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyarjfagm9").size() == 1, "mocknet UTXO listing");
  provider.broadcast({1, 2, 3});
  require(provider.outpoint_status(input.txid, 0) == "spent", "mocknet spend state");
}

void test_diagnostics() {
  const auto diagnostic = create_bch_diagnostic("provider", "transaction_identity_mismatch", "provider mismatch", {{"txid", std::string(64, 'a')}, {"rawTransaction", "deadbeef"}});
  require(diagnostic.context.at("rawTransaction") == kDiagnosticRedacted, "diagnostic redaction");
}

void test_http_boundary() {
  const auto response = create_bch_payment_required_response("{\"x402Version\":2}");
  require(response.status == 402 && decode_bch_http_header(response.headers.at(kBchPaymentRequiredHeader)) == "{\"x402Version\":2}", "HTTP boundary");
}

void test_signer_client_selects_provider_utxo() {
  Secp256k1BchSigner signer(kMnemonic, "bch:bitcoincash");
  const auto payer = decode_cash_address(signer.address("bch:bitcoincash"), "bch:bitcoincash");
  const auto requirements = build_native_requirements(
      "bch:bitcoincash", "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue",
      "1000", std::string(64, 'a'));
  FakeProvider provider(std::string(64, 'f'));
  provider.source_script = payer.script_pubkey;
  provider.utxos.push_back({std::string(64, 'c'), 0, 100000, payer.script_pubkey, std::nullopt, std::nullopt});
  const auto payload = ExactBchSignerClient(signer, provider).create_payment_payload(requirements);
  const auto transaction = parse_transaction(payload.transaction);
  assert_request_hash_commitment(transaction, std::string(64, 'a'));
}

void test_registered_covenant_profile() {
  const CovenantSuccessorPolicy policy{"51", "100", 0, "epoch-plus-one", "preserve", "preserve-minus-fee"};
  const CovenantProfile profile{
      "x402-bch/recursive-ticket", "recursive-state", 1, "bch:bchtest", {{"domain", "x402-bch"}, {"version", "1"}}, policy,
      "fba46d05764137264160f0fdd5f2126de0609f00bceb7a7b996d4fe06f770f62",
      "4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260",
      "bd272f1e231a1c34eb2ee188e4a51e34860c9513ececb58e4176dbd5817cd132"};
  const CovenantState source{"51", "1000", "1", std::string(64, 'a'), std::nullopt};
  const CovenantState successor{"51", "950", "2", std::string(64, 'a'), std::nullopt};
  require(covenant_profile_hashes_match(profile), "covenant profile identity");
  require(validate_covenant_transition(profile, {std::string(64, 'a'), 0, "50", source, successor}).empty(), "covenant successor");
  const CovenantState wrong{"52", "950", "2", std::string(64, 'a'), std::nullopt};
  require(validate_covenant_transition(profile, {std::string(64, 'a'), 0, "50", source, wrong}) == "locking-bytecode-mismatch", "covenant rejection");
  const CovenantTokenState token{"1111111111111111111111111111111111111111111111111111111111111111", "7", std::nullopt};
  const CovenantState token_source{"51", "2000", "8", std::string(64, 'b'), token};
  const CovenantState token_successor{"51", "1999", "9", std::string(64, 'b'), token};
  require(validate_covenant_transition(profile, {std::string(64, 'b'), 0, "1", token_source, token_successor}).empty(), "covenant token case");
  require(validate_covenant_transition(profile, {std::string(64, 'a'), 0, "50", source, {"51", "950", "3", std::string(64, 'a'), std::nullopt}}) == "state-transition-invalid", "covenant epoch rejection");
  require(validate_covenant_transition(profile, {std::string(64, 'a'), 0, "101", source, {"51", "899", "2", std::string(64, 'a'), std::nullopt}}) == "fee-exceeds-limit", "covenant fee rejection");
  require(validate_covenant_transition(profile, {std::string(64, 'b'), 0, "1", token_source, {"51", "1999", "9", std::string(64, 'b'), CovenantTokenState{"2222222222222222222222222222222222222222222222222222222222222222", "7", std::nullopt}}}) == "token-state-mismatch", "covenant token rejection");
}
}

int main() {
  try {
    test_settlement_store();
    test_observed_retry();
    test_request_hash_builder();
    test_cash_token_fee_input();
    test_fulcrum_token_utxo();
    test_failover();
    test_socket_transport();
    test_bchn_transport();
    test_mocknet_provider();
    test_diagnostics();
    test_http_boundary();
    test_signer_client_selects_provider_utxo();
    test_registered_covenant_profile();
    std::cout << "cpp SDK adapter tests: 12 passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
