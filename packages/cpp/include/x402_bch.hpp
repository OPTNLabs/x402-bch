#pragma once
#include <regex>
#include <stdexcept>
#include <string>
namespace x402bch {
struct Requirements {
  int version;
  std::string scheme;
  std::string network;
  std::string amount;
  std::string pay_to;
  std::string payment_flow;
};

struct PaymentPayload {
  int version;
  std::string scheme;
  std::string network;
  std::string transaction;
  Requirements accepted;
};

inline void validate_requirements(int version, const std::string& scheme, const std::string& amount, const std::string& flow) {
  if (version != 2 || scheme != "exact" || !std::regex_match(amount, std::regex("[0-9]+")) || flow != "upfront") throw std::invalid_argument("unsupported x402 requirements");
}

inline bool valid_base64(const std::string& value) {
  if (value.empty() || value.size() % 4 != 0) return false;
  return value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos;
}

inline void validate_payment_payload(const PaymentPayload& payload, const Requirements& expected) {
  validate_requirements(expected.version, expected.scheme, expected.amount, expected.payment_flow);
  if (payload.version != 2 || payload.scheme != expected.scheme || payload.network != expected.network)
    throw std::invalid_argument("payment payload does not bind to requirements");
  if (payload.accepted.network != expected.network || payload.accepted.amount != expected.amount || payload.accepted.pay_to != expected.pay_to)
    throw std::invalid_argument("accepted requirements mismatch");
  if (!valid_base64(payload.transaction)) throw std::invalid_argument("transaction must be non-empty base64");
}
}
