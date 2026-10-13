#include "x402_bch.hpp"

namespace x402bch {
namespace {

void validate_server_inputs(const std::string& network, const std::string& pay_to,
                            const std::string& amount) {
  if (network != "bch:bitcoincash" && network != "bch:bchtest")
    throw std::invalid_argument("unsupported BCH network");
  if (pay_to.empty()) throw std::invalid_argument("payTo is required");
  if (!std::regex_match(amount, std::regex("(0|[1-9][0-9]*)")))
    throw std::invalid_argument("amount must be a canonical decimal string");
}

void validate_server_request_hash(const std::string& request_hash) {
  if (!request_hash.empty() && !std::regex_match(request_hash, std::regex("[0-9a-fA-F]{64}")))
    throw std::invalid_argument("requestHash must be 32-byte hexadecimal");
}

}  // namespace

Requirements build_native_requirements(const std::string& network, const std::string& pay_to,
                                       const std::string& amount,
                                       const std::string& request_hash) {
  validate_server_inputs(network, pay_to, amount);
  validate_server_request_hash(request_hash);
  Requirements result{2, "exact", network, amount, "BCH", pay_to, "upfront", request_hash};
  result.asset_transfer_method = "native";
  return result;
}

Requirements build_cash_token_requirements(
    const std::string& network, const std::string& pay_to, const std::string& category,
    const std::string& amount, std::string value, const std::string& request_hash,
    const std::string& capability, const std::vector<uint8_t>& commitment) {
  validate_server_inputs(network, pay_to, amount);
  if (!std::regex_match(category, std::regex("[0-9a-fA-F]{64}")))
    throw std::invalid_argument("CashToken category must be 32-byte hexadecimal");
  if (value.empty()) value = "1000";
  if (!std::regex_match(value, std::regex("(0|[1-9][0-9]*)")))
    throw std::invalid_argument("CashToken value must be canonical satoshis");
  if (!capability.empty() && capability != "none" && capability != "mutable" &&
      capability != "minting")
    throw std::invalid_argument("CashToken NFT capability is invalid");
  if (commitment.size() > 40) throw std::invalid_argument("CashToken commitment is too large");
  validate_server_request_hash(request_hash);
  Requirements result{2, "exact", network, amount, category, pay_to, "upfront", request_hash};
  result.asset_transfer_method = "cashtoken";
  result.token_value = value;
  result.token_category = category;
  result.token_amount = amount;
  result.token_capability = capability;
  result.token_commitment = commitment;
  return result;
}

}  // namespace x402bch
