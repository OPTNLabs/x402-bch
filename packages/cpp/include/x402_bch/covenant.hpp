#pragma once

#include <map>
#include <optional>
#include <cstdint>
#include <string>
#include <vector>

namespace x402bch {

struct CovenantSuccessorPolicy {
  std::string locking_bytecode;
  std::string max_fee;
  uint32_t output_index;
  std::string state_transition;
  std::string token;
  std::string value;
};

struct CovenantProfile {
  std::string id;
  std::string family;
  uint64_t profile_version;
  std::string network;
  std::map<std::string, std::string> constructor_parameters;
  CovenantSuccessorPolicy successor_policy;
  std::string descriptor_hash;
  std::string locking_bytecode_hash;
  std::string successor_policy_hash;
};

struct CovenantNftState {
  std::string capability;
  std::string commitment;
  bool operator==(const CovenantNftState& other) const {
    return capability == other.capability && commitment == other.commitment;
  }
};

struct CovenantTokenState {
  std::string category;
  std::string amount;
  std::optional<CovenantNftState> nft;
  bool operator==(const CovenantTokenState& other) const {
    return category == other.category && amount == other.amount && nft == other.nft;
  }
};

struct CovenantState {
  std::string locking_bytecode;
  std::string value;
  std::string epoch;
  std::string request_hash;
  std::optional<CovenantTokenState> token;
};

struct CovenantTransition {
  std::string request_hash;
  uint32_t successor_output_index;
  std::string fee;
  CovenantState source;
  CovenantState successor;
};

bool covenant_profile_hashes_match(const CovenantProfile& profile);
std::string validate_covenant_transition(const CovenantProfile& profile, const CovenantTransition& transition);

}
