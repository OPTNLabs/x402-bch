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
  std::cout << "cpp conformance fixture: ok\n";
}
