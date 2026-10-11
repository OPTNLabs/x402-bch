#pragma once
#include <regex>
#include <stdexcept>
#include <string>
namespace x402bch {
inline void validate_requirements(int version, const std::string& scheme, const std::string& amount, const std::string& flow) {
  if (version != 2 || scheme != "exact" || !std::regex_match(amount, std::regex("[0-9]+")) || flow != "upfront") throw std::invalid_argument("unsupported x402 requirements");
}
}
