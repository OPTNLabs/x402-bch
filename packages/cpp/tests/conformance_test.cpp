#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include "x402_bch.hpp"

int main() {
  std::ifstream input("spec/conformance/v1/payment-requirements.json");
  const std::string json((std::istreambuf_iterator<char>(input)), {});
  if (json.find("\"version\": 1") == std::string::npos ||
      json.find("\"scheme\": \"exact\"") == std::string::npos) return 1;
  if (!std::regex_match("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        std::regex("[0-9a-f]{64}"))) return 1;
  x402bch::validate_requirements(2, "exact", "1000", "upfront");
  if (x402bch::request_hash("{\"url\":\"https://example.test/resource\"}") != "1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675") return 1;
  x402bch::Requirements requirements{2, "exact", "bch:bchtest", "1000", "bchtest:merchant", "upfront"};
  x402bch::PaymentPayload payload{2, "exact", "bch:bchtest", "AQID", requirements};
  x402bch::validate_payment_payload(payload, requirements);
  payload.transaction = "bad";
  try { x402bch::validate_payment_payload(payload, requirements); return 1; }
  catch (const std::invalid_argument&) {}
  std::cout << "cpp conformance fixture: ok\n";
}
