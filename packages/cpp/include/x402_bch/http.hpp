#pragma once

#include "protocol.hpp"

#include <map>

namespace x402bch {

inline constexpr const char* kBchPaymentRequiredHeader = "PAYMENT-REQUIRED";
inline constexpr const char* kBchPaymentSignatureHeader = "PAYMENT-SIGNATURE";
inline constexpr const char* kBchPaymentResponseHeader = "PAYMENT-RESPONSE";

struct BchHttpResponse {
  int status = 0;
  std::map<std::string, std::string> headers;
  std::string body;
};

inline std::string encode_bch_http_header(const std::string& json) {
  if (json.empty()) throw std::invalid_argument("HTTP x402 header JSON must not be empty");
  return encode_base64(std::vector<uint8_t>(json.begin(), json.end()));
}

inline std::string decode_bch_http_header(const std::string& header) {
  const auto bytes = decode_base64(header);
  if (bytes.empty()) throw std::invalid_argument("HTTP x402 header JSON must not be empty");
  return std::string(bytes.begin(), bytes.end());
}

inline BchHttpResponse create_bch_payment_required_response(const std::string& requirements_json) {
  return {402, {{kBchPaymentRequiredHeader, encode_bch_http_header(requirements_json)}}, "Payment required"};
}

inline std::map<std::string, std::string> create_bch_payment_signature_header(const std::string& payload_json) { return {{kBchPaymentSignatureHeader, encode_bch_http_header(payload_json)}}; }
inline std::map<std::string, std::string> create_bch_payment_response(const std::string& result_json) { return {{kBchPaymentResponseHeader, encode_bch_http_header(result_json)}}; }

}  // namespace x402bch
