#pragma once
#include "transaction.hpp"
namespace x402bch {
struct BchVmResult {
  bool accepted = false;
  std::string error_code;
};

inline bool bch_vm_truthy(const std::vector<uint8_t>& value) {
  for (size_t index = 0; index < value.size(); index++) {
    if (value[index] != 0) return !(index == value.size() - 1 && value[index] == 0x80);
  }
  return false;
}

inline std::string execute_bch_script(const std::vector<uint8_t>& script,
                                      std::vector<std::vector<uint8_t>>& stack) {
  size_t offset = 0;
  while (offset < script.size()) {
    const uint8_t opcode = script[offset++];
    if (opcode == 0) { stack.emplace_back(); continue; }
    if (opcode >= 1 && opcode <= 75) {
      const size_t length = opcode;
      if (offset + length > script.size()) return "TRUNCATED_PUSH";
      stack.emplace_back(script.begin() + static_cast<std::ptrdiff_t>(offset),
                         script.begin() + static_cast<std::ptrdiff_t>(offset + length));
      offset += length;
      continue;
    }
    if (opcode == 0x4c || opcode == 0x4d || opcode == 0x4e) {
      const size_t width = opcode == 0x4c ? 1 : (opcode == 0x4d ? 2 : 4);
      if (offset + width > script.size()) return "TRUNCATED_PUSH";
      size_t length = 0;
      for (size_t index = 0; index < width; index++) length |= static_cast<size_t>(script[offset + index]) << (8 * index);
      offset += width;
      if (length > 520) return "PUSH_SIZE";
      if (offset + length > script.size()) return "TRUNCATED_PUSH";
      stack.emplace_back(script.begin() + static_cast<std::ptrdiff_t>(offset),
                         script.begin() + static_cast<std::ptrdiff_t>(offset + length));
      offset += length;
      continue;
    }
    if (opcode >= 0x51 && opcode <= 0x60) { stack.push_back({static_cast<uint8_t>(opcode - 0x50)}); continue; }
    switch (opcode) {
      case 0x69:
        if (stack.empty()) return "INVALID_STACK_OPERATION";
        if (!bch_vm_truthy(stack.back())) return "VERIFY";
        stack.pop_back();
        break;
      case 0x76:
        if (stack.empty()) return "INVALID_STACK_OPERATION";
        stack.push_back(stack.back());
        break;
      case 0x87: {
        if (stack.size() < 2) return "INVALID_STACK_OPERATION";
        const auto right = stack.back(); stack.pop_back();
        const auto left = stack.back(); stack.pop_back();
        stack.push_back(left == right ? std::vector<uint8_t>{1} : std::vector<uint8_t>{});
        break;
      }
      case 0x88: {
        if (stack.size() < 2) return "INVALID_STACK_OPERATION";
        const auto right = stack.back(); stack.pop_back();
        const auto left = stack.back(); stack.pop_back();
        if (left != right) return "EQUALVERIFY";
        break;
      }
      case 0xa9:
        if (stack.empty()) return "INVALID_STACK_OPERATION";
        { const auto value = stack.back(); stack.pop_back(); stack.push_back(hash160(value)); }
        break;
      case 0x6a: return "OP_RETURN";
      default: return "BAD_OPCODE";
    }
  }
  return {};
}

inline BchVmResult evaluate_bch_vm(const std::vector<uint8_t>& unlocking_script,
                                   const std::vector<uint8_t>& locking_script) {
  std::vector<std::vector<uint8_t>> stack;
  auto error = execute_bch_script(unlocking_script, stack);
  if (error.empty()) error = execute_bch_script(locking_script, stack);
  if (error.empty() && stack.size() != 1) error = "CLEANSTACK";
  if (error.empty() && !bch_vm_truthy(stack.back())) error = "FALSE";
  return {error.empty(), error};
}

// Check push-only unlocking and the committed P2SH20/P2SH32 redeem script.
// This validates the hash boundary only; it does not execute arbitrary BCH VM.
inline void verify_p2sh_redeem_script(const Transaction& transaction, size_t input_index, const std::vector<uint8_t>& source_script) {
  const bool p2sh20 = source_script.size() == 23 && source_script[0] == 0xa9 && source_script[1] == 0x14 && source_script[22] == 0x87;
  const bool p2sh32 = source_script.size() == 35 && source_script[0] == 0xaa && source_script[1] == 0x20 && source_script[34] == 0x87;
  if (!p2sh20 && !p2sh32) throw std::invalid_argument("source output is not P2SH20 or P2SH32");
  if (input_index >= transaction.inputs.size()) throw std::invalid_argument("invalid input index");
  const auto& script = transaction.inputs[input_index].script_sig;
  std::vector<std::vector<uint8_t>> pushes;
  size_t offset = 0;
  while (offset < script.size()) {
    const auto opcode = script[offset++];
    if (opcode == 0) { pushes.emplace_back(); continue; }
    uint64_t length = 0;
    if (opcode >= 1 && opcode <= 75) length = opcode;
    else if (opcode == 0x4c) length = read_little_endian(script, offset, 1);
    else if (opcode == 0x4d) length = read_little_endian(script, offset, 2);
    else if (opcode == 0x4e) length = read_little_endian(script, offset, 4);
    else throw std::invalid_argument("P2SH unlocking script is not push-only");
    if (length > script.size() - offset) throw std::invalid_argument("P2SH unlocking script push is truncated");
    pushes.emplace_back(script.begin() + static_cast<std::ptrdiff_t>(offset), script.begin() + static_cast<std::ptrdiff_t>(offset + length));
    offset += static_cast<size_t>(length);
  }
  if (pushes.empty()) throw std::invalid_argument("P2SH unlocking script does not push a redeem script");
  const auto& redeem_script = pushes.back();
  const auto committed = p2sh20 ? hash160(redeem_script) : double_sha256_bytes(redeem_script);
  if (!std::equal(committed.begin(), committed.end(), source_script.begin() + 2)) throw std::invalid_argument("P2SH redeem script commitment mismatch");
}

}
