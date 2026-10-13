#pragma once

#include "x402_bch.hpp"

#include <mutex>
#include <unordered_map>

namespace x402bch {
class Provider;

struct TransactionRequest {
  std::string network;
  std::string pay_to;
  std::string value;
  std::string asset;
  std::string token_amount;
  std::optional<CashToken> token;
  std::string request_hash;
};

class Wallet {
 public:
  virtual ~Wallet() = default;
  virtual std::vector<uint8_t> create_payment(const TransactionRequest& request) = 0;
};

class Signer {
 public:
  virtual ~Signer() = default;
  virtual std::vector<uint8_t> public_key() const = 0;
  virtual std::vector<uint8_t> sign_digest(const std::vector<uint8_t>& digest) = 0;
  virtual std::string address(const std::string& network) const = 0;
};

struct Utxo {
  std::string txid;
  uint32_t vout = 0;
  uint64_t value = 0;
  std::vector<uint8_t> script_pubkey;
  std::optional<CashToken> token;
  std::optional<uint64_t> height;
};

struct WalletAddress {
  std::string address;
  std::string path;
  uint32_t change = 0;
  uint32_t index = 0;
  std::vector<uint8_t> public_key;
};
struct DiscoveredAddress { WalletAddress wallet; std::vector<Utxo> utxos; };

class Secp256k1BchSigner final : public Signer {
 public:
  Secp256k1BchSigner(const std::string& mnemonic, const std::string& network,
                     const std::string& passphrase = {}, uint32_t change = 0,
                     uint32_t index = 0, uint32_t account = 0);
  std::vector<uint8_t> public_key() const override;
  std::vector<uint8_t> sign_digest(const std::vector<uint8_t>& digest) override;
  std::string address(const std::string& network) const override;

 private:
  std::vector<uint8_t> private_key_;
  std::string default_network_;
};

WalletAddress derive_bch_wallet_address(
    const std::string& mnemonic, const std::string& network, uint32_t change,
    uint32_t index, uint32_t account = 0, const std::string& passphrase = {},
    std::optional<uint32_t> coin_type = std::nullopt);
std::vector<DiscoveredAddress> discover_bch_hd_wallet_addresses(
    const std::string& mnemonic, const std::string& network, Provider& provider,
    uint32_t gap_limit = 20, uint32_t max_addresses = 1000, uint32_t account = 0,
    const std::string& passphrase = {});

std::vector<uint8_t> build_and_sign_native_payment(
    const std::vector<Utxo>& selected, const std::vector<uint8_t>& merchant_script,
    uint64_t merchant_value, Signer& signer, const std::string& network,
    uint64_t fee_rate = 1, uint64_t dust_threshold = 546,
    const std::string& request_hash = {});

std::vector<uint8_t> build_and_sign_cash_token_payment(
    const std::vector<Utxo>& selected, const std::vector<uint8_t>& merchant_script,
    uint64_t merchant_value, uint64_t token_amount, const std::string& category,
    const std::string& merchant_capability, const std::vector<uint8_t>& merchant_commitment,
    Signer& signer, const std::string& network, uint64_t fee_rate = 1,
    uint64_t dust_threshold = 1000, const std::string& request_hash = {});

struct ProviderStatus {
  std::string kind;
  uint64_t height = 0;
};

class Provider {
 public:
  virtual ~Provider() = default;
  virtual std::string network() const = 0;
  virtual std::vector<Utxo> list_utxos(const std::string& address) = 0;
  virtual TransactionOutput source_output(const std::string& txid, uint32_t vout) = 0;
  virtual std::string outpoint_status(const std::string& txid, uint32_t vout) = 0;
  virtual std::string broadcast(const std::vector<uint8_t>& raw_transaction) = 0;
  virtual std::optional<std::vector<uint8_t>> transaction(const std::string& txid) = 0;
  virtual ProviderStatus transaction_status(const std::string& txid) = 0;
  virtual uint64_t tip_height() = 0;
  virtual bool has_double_spend_proof(const std::string& txid) = 0;
};

class FulcrumTransport {
 public:
  virtual ~FulcrumTransport() = default;
  virtual std::string request(const std::string& method, const std::string& params_json) = 0;
};

class FailoverFulcrumTransport final : public FulcrumTransport {
 public:
  explicit FailoverFulcrumTransport(std::vector<FulcrumTransport*> transports);
  std::string request(const std::string& method, const std::string& params_json) override;

 private:
  std::vector<FulcrumTransport*> transports_;
};

/** Concrete newline-delimited Fulcrum JSON-RPC transport over TCP. */
class SocketFulcrumTransport final : public FulcrumTransport {
 public:
  SocketFulcrumTransport(std::string host, uint16_t port, uint32_t timeout_ms = 10000);
  std::string request(const std::string& method, const std::string& params_json) override;

 private:
  std::string host_;
  uint16_t port_;
  uint32_t timeout_ms_;
};

struct BchnMempoolResult {
  bool allowed = false;
  std::string reason;
  std::string txid;
};

/** Direct BCHN JSON-RPC over HTTP. TLS should be supplied by a caller-owned proxy or transport. */
class BchnRpcTransport final {
 public:
  BchnRpcTransport(std::string url, uint32_t timeout_ms = 10000);
  std::string request(const std::string& method, const std::string& params_json);
  BchnMempoolResult test_mempool_accept(const std::vector<uint8_t>& raw_transaction);

 private:
  std::string host_;
  uint16_t port_ = 0;
  std::string path_;
  uint32_t timeout_ms_ = 0;
};

/** Concrete Fulcrum provider over an application-supplied JSON transport. */
class FulcrumProvider final : public Provider {
 public:
  FulcrumProvider(std::string network, FulcrumTransport& transport);
  std::string network() const override { return network_; }
  std::vector<Utxo> list_utxos(const std::string& address) override;
  TransactionOutput source_output(const std::string& txid, uint32_t vout) override;
  std::string outpoint_status(const std::string& txid, uint32_t vout) override;
  std::string broadcast(const std::vector<uint8_t>& raw_transaction) override;
  std::optional<std::vector<uint8_t>> transaction(const std::string& txid) override;
  ProviderStatus transaction_status(const std::string& txid) override;
  uint64_t tip_height() override;
  bool has_double_spend_proof(const std::string& txid) override;

 private:
  std::string request(const std::string& method, const std::string& params_json);
  std::string network_;
  FulcrumTransport& transport_;
};

struct MocknetInput {
  std::string txid;
  uint32_t vout = 0;
};

struct MocknetTransaction {
  std::string txid;
  std::vector<uint8_t> raw_transaction;
  std::vector<MocknetInput> inputs;
  std::vector<TransactionOutput> outputs;
};

/** Deterministic in-memory UTXO provider for SDK integration tests. */
class MocknetProvider final : public Provider {
 public:
  MocknetProvider(std::string network, std::vector<Utxo> initial_utxos, uint64_t tip_height);
  std::string network() const override { return network_; }
  void register_transaction(MocknetTransaction transaction);
  std::vector<Utxo> list_utxos(const std::string& address) override;
  TransactionOutput source_output(const std::string& txid, uint32_t vout) override;
  std::string outpoint_status(const std::string& txid, uint32_t vout) override;
  std::string broadcast(const std::vector<uint8_t>& raw_transaction) override;
  std::optional<std::vector<uint8_t>> transaction(const std::string& txid) override;
  ProviderStatus transaction_status(const std::string& txid) override;
  uint64_t tip_height() override { return tip_height_; }
  bool has_double_spend_proof(const std::string&) override { return false; }

 private:
  static std::string key(const std::string& txid, uint32_t vout);
  std::string network_;
  uint64_t tip_height_;
  std::mutex mutex_;
  std::unordered_map<std::string, Utxo> unspent_;
  std::unordered_map<std::string, TransactionOutput> outputs_;
  std::unordered_map<std::string, MocknetTransaction> registered_;
  std::unordered_map<std::string, std::vector<uint8_t>> transactions_;
  std::unordered_map<std::string, ProviderStatus> statuses_;
};

class SettlementStore {
 public:
  virtual ~SettlementStore() = default;
  virtual std::string claim(const std::string& txid, const std::string& binding) = 0;
  virtual void mark_accepted(const std::string& txid) = 0;
  virtual void release(const std::string& txid) = 0;
};

class InMemorySettlementStore final : public SettlementStore {
 public:
  std::string claim(const std::string& txid, const std::string& binding) override;
  void mark_accepted(const std::string& txid) override;
  void release(const std::string& txid) override;

 private:
  struct Record { std::string binding; bool accepted = false; };
  std::mutex mutex_;
  std::unordered_map<std::string, Record> records_;
};

TransactionRequest to_transaction_request(const Requirements& requirements);

class ExactBchClient {
 public:
  ExactBchClient(Wallet& wallet, Provider& provider) : wallet_(wallet), provider_(provider) {}
  PaymentPayload create_payment_payload(const Requirements& requirements) const;

 private:
  Wallet& wallet_;
  Provider& provider_;
};

/** Low-level signer-backed client with provider-owned UTXO selection. */
class ExactBchSignerClient {
 public:
  ExactBchSignerClient(Signer& signer, Provider& provider, uint64_t fee_rate = 1,
                       uint64_t dust_threshold = 546)
      : signer_(signer), provider_(provider), fee_rate_(fee_rate), dust_threshold_(dust_threshold) {}
  PaymentPayload create_payment_payload(const Requirements& requirements) const;

 private:
  Signer& signer_;
  Provider& provider_;
  uint64_t fee_rate_;
  uint64_t dust_threshold_;
};

struct VerifyResponse {
  bool is_valid = false;
  std::string transaction_id;
  std::string invalid_reason;
};

struct SettleResponse {
  bool success = false;
  std::string transaction_id;
  std::string error_reason;
};

class ExactBchFacilitator {
 public:
  ExactBchFacilitator(Provider& provider, SettlementStore& store)
      : provider_(provider), store_(store) {}
  VerifyResponse verify(const PaymentPayload& payload, const Requirements& requirements) const;
  SettleResponse settle(const PaymentPayload& payload, const Requirements& requirements,
                        const std::string& strategy = "confirmations",
                        uint64_t confirmations = 1);

 private:
  PaymentVerification verify_payment(const PaymentPayload& payload,
                                     const Requirements& requirements,
                                     bool require_unspent) const;
  bool accepted(const std::string& txid, const std::string& strategy,
                uint64_t confirmations) const;
  Provider& provider_;
  SettlementStore& store_;
};

}  // namespace x402bch
