#include "x402_bch/covenant.hpp"

#include "x402_bch/address.hpp"
#include "x402_bch/crypto.hpp"
#include "x402_bch/protocol.hpp"

namespace x402bch {
namespace {
BigInt uint_value(const std::string& value) {
  BigInt result = 0;
  for (const auto character : value) {
    if (character < '0' || character > '9') return BigInt(0);
    result *= 10;
    result += character - '0';
  }
  return result;
}

std::string quote(const std::string& value) {
  std::string result = "\"";
  for (const auto character : value) {
    if (character == '\\' || character == '\"') result.push_back('\\');
    result.push_back(character);
  }
  result.push_back('\"');
  return result;
}

std::string canonical_policy(const CovenantSuccessorPolicy& policy) {
  return "{\"lockingBytecode\":" + quote(policy.locking_bytecode) +
         ",\"maxFee\":" + quote(policy.max_fee) +
         ",\"outputIndex\":" + std::to_string(policy.output_index) +
         ",\"stateTransition\":" + quote(policy.state_transition) +
         ",\"token\":" + quote(policy.token) +
         ",\"value\":" + quote(policy.value) + "}";
}

std::string canonical_parameters(const std::map<std::string, std::string>& parameters) {
  std::string result = "{";
  bool first = true;
  for (const auto& [key, value] : parameters) {
    if (!first) result.push_back(',');
    first = false;
    result += quote(key) + ":" + quote(value);
  }
  return result + "}";
}

std::string sha256_hex(const std::vector<uint8_t>& bytes) {
  return request_hash(std::string(bytes.begin(), bytes.end()));
}

}

bool covenant_profile_hashes_match(const CovenantProfile& profile) {
  const auto descriptor = "{\"constructorParameters\":" + canonical_parameters(profile.constructor_parameters) +
                          ",\"family\":" + quote(profile.family) +
                          ",\"id\":" + quote(profile.id) +
                          ",\"network\":" + quote(profile.network) +
                          ",\"profileVersion\":" + std::to_string(profile.profile_version) +
                          ",\"successorPolicy\":" + canonical_policy(profile.successor_policy) + "}";
  const auto locking = hex_to_bytes(profile.successor_policy.locking_bytecode);
  return request_hash(descriptor) == profile.descriptor_hash &&
         sha256_hex(locking) == profile.locking_bytecode_hash &&
         request_hash(canonical_policy(profile.successor_policy)) == profile.successor_policy_hash;
}

std::string validate_covenant_transition(const CovenantProfile& profile, const CovenantTransition& transition) {
  if (!covenant_profile_hashes_match(profile)) return "profile-identity-mismatch";
  if (transition.source.locking_bytecode != profile.successor_policy.locking_bytecode ||
      transition.successor.locking_bytecode != profile.successor_policy.locking_bytecode)
    return "locking-bytecode-mismatch";
  if (transition.successor_output_index != profile.successor_policy.output_index)
    return "successor-output-index-mismatch";
  if (transition.request_hash != transition.source.request_hash ||
      transition.request_hash != transition.successor.request_hash)
    return "request-hash-mismatch";
  if (profile.successor_policy.state_transition == "epoch-plus-one" &&
      uint_value(transition.successor.epoch) != uint_value(transition.source.epoch) + 1)
    return "state-transition-invalid";
  const auto fee = uint_value(transition.fee);
  if (fee > uint_value(profile.successor_policy.max_fee)) return "fee-exceeds-limit";
  if (profile.successor_policy.value == "preserve-minus-fee" &&
      uint_value(transition.source.value) - uint_value(transition.successor.value) != fee)
    return "state-transition-invalid";
  if (profile.successor_policy.token == "preserve" && !(transition.source.token == transition.successor.token))
    return "token-state-mismatch";
  return {};
}

}
