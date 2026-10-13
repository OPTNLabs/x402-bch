#include "x402_bch_sdk.hpp"

#include <algorithm>

namespace x402bch {

MocknetProvider::MocknetProvider(std::string network, std::vector<Utxo> initial_utxos, uint64_t tip_height)
    : network_(std::move(network)), tip_height_(tip_height) {
  if (network_ != "bch:bitcoincash" && network_ != "bch:bchtest") throw std::invalid_argument("unsupported BCH network");
  for (const auto& utxo : initial_utxos) {
    const auto outpoint = key(utxo.txid, utxo.vout);
    if (!unspent_.emplace(outpoint, utxo).second) throw std::invalid_argument("duplicate mocknet outpoint");
    outputs_[outpoint] = {utxo.value, utxo.script_pubkey, utxo.token};
  }
}

void MocknetProvider::register_transaction(MocknetTransaction transaction) {
  if (!std::regex_match(transaction.txid, std::regex("[0-9a-fA-F]{64}"))) throw std::invalid_argument("mocknet txid must be 32-byte hexadecimal");
  registered_[bytes_to_hex(transaction.raw_transaction)] = std::move(transaction);
}

std::vector<Utxo> MocknetProvider::list_utxos(const std::string& address) {
  const auto script = decode_cash_address(address, network_).script_pubkey;
  std::lock_guard lock(mutex_);
  std::vector<Utxo> result;
  for (const auto& [_, utxo] : unspent_) if (utxo.script_pubkey == script) result.push_back(utxo);
  return result;
}

TransactionOutput MocknetProvider::source_output(const std::string& txid, uint32_t vout) {
  std::lock_guard lock(mutex_);
  const auto found = outputs_.find(key(txid, vout));
  if (found == outputs_.end()) throw std::invalid_argument("mocknet source output was not found");
  return found->second;
}

std::string MocknetProvider::outpoint_status(const std::string& txid, uint32_t vout) {
  std::lock_guard lock(mutex_);
  const auto outpoint = key(txid, vout);
  if (unspent_.find(outpoint) != unspent_.end()) return "unspent";
  return outputs_.find(outpoint) != outputs_.end() ? "spent" : "unknown";
}

std::string MocknetProvider::broadcast(const std::vector<uint8_t>& raw_transaction) {
  std::lock_guard lock(mutex_);
  const auto found = registered_.find(bytes_to_hex(raw_transaction));
  if (found == registered_.end()) throw std::invalid_argument("mocknet transaction is not registered");
  const auto& transaction = found->second;
  const auto known = statuses_.find(transaction.txid);
  if (known != statuses_.end() && known->second.kind != "conflicted") return transaction.txid;
  for (const auto& input : transaction.inputs) if (unspent_.find(key(input.txid, input.vout)) == unspent_.end()) throw std::invalid_argument("mocknet input is already spent");
  for (const auto& input : transaction.inputs) unspent_.erase(key(input.txid, input.vout));
  for (uint32_t vout = 0; vout < transaction.outputs.size(); ++vout) {
    const auto outpoint = key(transaction.txid, vout);
    outputs_[outpoint] = transaction.outputs[vout];
    const auto& output = transaction.outputs[vout];
    unspent_[outpoint] = {transaction.txid, vout, output.value, output.script_pubkey, output.token, std::nullopt};
  }
  transactions_[transaction.txid] = raw_transaction;
  statuses_[transaction.txid] = {"mempool", 0};
  return transaction.txid;
}

std::optional<std::vector<uint8_t>> MocknetProvider::transaction(const std::string& txid) {
  std::lock_guard lock(mutex_);
  const auto found = transactions_.find(txid);
  return found == transactions_.end() ? std::nullopt : std::optional<std::vector<uint8_t>>(found->second);
}

ProviderStatus MocknetProvider::transaction_status(const std::string& txid) {
  std::lock_guard lock(mutex_);
  const auto found = statuses_.find(txid);
  return found == statuses_.end() ? ProviderStatus{"notFound", 0} : found->second;
}

std::string MocknetProvider::key(const std::string& txid, uint32_t vout) { return txid + ":" + std::to_string(vout); }

}
