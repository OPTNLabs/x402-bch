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
  int max_timeout_seconds = 300;
  std::string asset_transfer_method = "native";
  std::string token_value;
  std::string token_category;
  std::string token_amount;
  std::string token_capability;
  std::vector<uint8_t> token_commitment;
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

}
