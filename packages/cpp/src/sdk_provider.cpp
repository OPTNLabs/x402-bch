#include "sdk_support.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <regex>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
namespace x402bch {
using namespace detail;
std::string FulcrumProvider::request(const std::string& method, const std::string& params_json) {
  return transport_.request(method, params_json);
}

std::vector<Utxo> FulcrumProvider::list_utxos(const std::string& address) {
  const auto decoded = decode_cash_address(address, network_);
  const auto script_hash = reverse_hex_bytes(request_hash(
      std::string(decoded.script_pubkey.begin(), decoded.script_pubkey.end())));
  const auto response = request("blockchain.scripthash.listunspent",
                                "[\"" + script_hash + "\",\"include_tokens\"]");
  std::vector<Utxo> result;
  const std::regex objects("\\{(?:[^{}]|\\{[^{}]*\\})*\\}");
  for (auto begin = std::sregex_iterator(response.begin(), response.end(), objects);
       begin != std::sregex_iterator(); ++begin) {
    const auto object = begin->str();
    if (object.find("tx_hash") == std::string::npos && object.find("txid") == std::string::npos) continue;
    const auto txid = object.find("tx_hash") != std::string::npos ? json_string(object, "tx_hash") : json_string(object, "txid");
    const auto vout = object.find("tx_pos") != std::string::npos ? json_number(object, "tx_pos") : json_number(object, "vout");
    const auto value = std::to_string(json_number(object, "value"));
    std::optional<uint64_t> height;
    if (object.find("height") != std::string::npos) {
      const auto candidate = json_number(object, "height");
      if (candidate > 0) height = candidate;
    }
    result.push_back({txid, static_cast<uint32_t>(vout), json_number(object, "value"), decoded.script_pubkey, json_token(object), height});
    result.back().value = json_number(object, "value");
  }
  return result;
}

TransactionOutput FulcrumProvider::source_output(const std::string& txid, uint32_t vout) {
  const auto response = request("blockchain.transaction.get", "[\"" + txid + "\",true]");
  std::smatch match;
  const std::regex pattern("\\\"n\\\"\\s*:\\s*" + std::to_string(vout) +
                           "[^}]*\\\"value\\\"\\s*:\\s*([0-9]+(?:\\.[0-9]+)?)" +
                           "[^}]*\\\"hex\\\"\\s*:\\s*\\\"([0-9a-fA-F]+)\\\"");
  if (!std::regex_search(response, match, pattern))
    throw std::invalid_argument("source output was not found or has no script hex");
  const auto value_text = match[1].str();
  const auto decimal = value_text.find('.');
  if (decimal != std::string::npos) {
    const auto fraction = value_text.substr(decimal + 1);
    if (fraction.size() > 8 || fraction.find_first_not_of('0') != std::string::npos)
      throw std::invalid_argument("source output BCH value has more than 8 decimals");
  }
  const auto whole = decimal == std::string::npos ? value_text : value_text.substr(0, decimal);
  uint64_t value = std::stoull(whole) * 100000000ULL;
  if (decimal != std::string::npos) value += std::stoull(value_text.substr(decimal + 1) + std::string(8 - (value_text.size() - decimal - 1), '0'));
  return {value, hex_to_bytes(match[2].str()), json_token(response)};
}

std::string FulcrumProvider::outpoint_status(const std::string&, uint32_t) {
  return "unknown";
}

std::string FulcrumProvider::broadcast(const std::vector<uint8_t>& raw_transaction) {
  const auto response = quoted_or_raw(request("blockchain.transaction.broadcast",
                                               "[\"" + bytes_to_hex(raw_transaction) + "\"]"));
  if (!std::regex_match(response, std::regex("[0-9a-fA-F]{64}")))
    throw std::invalid_argument("Fulcrum broadcast did not return a transaction ID");
  std::string result = response;
  std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return result;
}

std::optional<std::vector<uint8_t>> FulcrumProvider::transaction(const std::string& txid) {
  const auto response = quoted_or_raw(request("blockchain.transaction.get", "[\"" + txid + "\"]"));
  if (response.empty() || !std::regex_match(response, std::regex("[0-9a-fA-F]+")))
    throw std::invalid_argument("Fulcrum transaction response is not raw hexadecimal data");
  return hex_to_bytes(response);
}

ProviderStatus FulcrumProvider::transaction_status(const std::string& txid) {
  const auto response = quoted_or_raw(request("blockchain.transaction.get_height", "[\"" + txid + "\"]"));
  const auto height = std::stoll(response);
  if (height > 0) return {"confirmed", static_cast<uint64_t>(height)};
  if (height == 0 || height == -1) return {"mempool", 0};
  return {"notFound", 0};
}

uint64_t FulcrumProvider::tip_height() {
  return json_number(request("blockchain.headers.subscribe", "[]"), "height");
}

bool FulcrumProvider::has_double_spend_proof(const std::string& txid) {
  const auto response = quoted_or_raw(request("blockchain.transaction.dsproof.get", "[\"" + txid + "\"]"));
  return !response.empty() && response != "null";
}

std::string FailoverFulcrumTransport::request(const std::string& method,
                                              const std::string& params_json) {
  std::string errors;
  for (auto* transport : transports_) {
    try {
      return transport->request(method, params_json);
    } catch (const std::exception& error) {
      if (!errors.empty()) errors += "; ";
      errors += error.what();
    }
  }
  throw std::runtime_error("all Fulcrum transports failed: " + errors);
}

SocketFulcrumTransport::SocketFulcrumTransport(std::string host, uint16_t port, uint32_t timeout_ms)
    : host_(std::move(host)), port_(port), timeout_ms_(timeout_ms) {
  if (host_.empty() || port_ == 0 || timeout_ms_ == 0)
    throw std::invalid_argument("Fulcrum host, port, and timeout are required");
}

std::string SocketFulcrumTransport::request(const std::string& method, const std::string& params_json) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo* addresses = nullptr;
  const auto service = std::to_string(port_);
  if (getaddrinfo(host_.c_str(), service.c_str(), &hints, &addresses) != 0)
    throw std::runtime_error("Fulcrum endpoint could not be resolved");
  int descriptor = -1;
  for (auto* address = addresses; address != nullptr; address = address->ai_next) {
    descriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (descriptor < 0) continue;
    timeval timeout{static_cast<long>(timeout_ms_ / 1000), static_cast<long>((timeout_ms_ % 1000) * 1000)};
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(descriptor, address->ai_addr, address->ai_addrlen) == 0) break;
    close(descriptor);
    descriptor = -1;
  }
  freeaddrinfo(addresses);
  if (descriptor < 0) throw std::runtime_error("Fulcrum connection failed");
  const auto request_json = "{\"id\":1,\"method\":\"" + method + "\",\"params\":" + params_json + "}\n";
  const auto sent = send(descriptor, request_json.data(), request_json.size(), 0);
  if (sent != static_cast<ssize_t>(request_json.size())) {
    close(descriptor);
    throw std::runtime_error("Fulcrum request failed");
  }
  std::string response;
  char buffer[4096];
  while (response.find('\n') == std::string::npos) {
    const auto received = recv(descriptor, buffer, sizeof(buffer), 0);
    if (received <= 0) {
      close(descriptor);
      throw std::runtime_error("Fulcrum response failed");
    }
    response.append(buffer, static_cast<size_t>(received));
    if (response.size() > 4 * 1024 * 1024) {
      close(descriptor);
      throw std::runtime_error("Fulcrum response is too large");
    }
  }
  close(descriptor);
  response.resize(response.find('\n'));
  if (response.find("\"error\"") != std::string::npos)
    throw std::runtime_error("Fulcrum RPC error: " + response);
  return response;
}

BchnRpcTransport::BchnRpcTransport(std::string url, uint32_t timeout_ms)
    : timeout_ms_(timeout_ms) {
  if (url.rfind("http://", 0) != 0 || timeout_ms_ == 0)
    throw std::invalid_argument("BCHN RPC requires a plain http:// URL and timeout");
  const auto authority_start = std::string("http://").size();
  const auto path_position = url.find('/', authority_start);
  const auto authority = url.substr(authority_start, path_position == std::string::npos ? std::string::npos : path_position - authority_start);
  const auto separator = authority.rfind(':');
  if (separator == std::string::npos) throw std::invalid_argument("BCHN RPC URL must include a port");
  host_ = authority.substr(0, separator);
  path_ = path_position == std::string::npos ? "/" : url.substr(path_position);
  const auto parsed_port = std::stoul(authority.substr(separator + 1));
  if (host_.empty() || parsed_port == 0 || parsed_port > 65535) throw std::invalid_argument("invalid BCHN RPC host or port");
  port_ = static_cast<uint16_t>(parsed_port);
}

std::string BchnRpcTransport::request(const std::string& method, const std::string& params_json) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo* addresses = nullptr;
  const auto service = std::to_string(port_);
  if (getaddrinfo(host_.c_str(), service.c_str(), &hints, &addresses) != 0)
    throw std::runtime_error("BCHN RPC endpoint could not be resolved");
  int descriptor = -1;
  for (auto* address = addresses; address != nullptr; address = address->ai_next) {
    descriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (descriptor < 0) continue;
    timeval timeout{static_cast<long>(timeout_ms_ / 1000), static_cast<long>((timeout_ms_ % 1000) * 1000)};
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(descriptor, address->ai_addr, address->ai_addrlen) == 0) break;
    close(descriptor);
    descriptor = -1;
  }
  freeaddrinfo(addresses);
  if (descriptor < 0) throw std::runtime_error("BCHN RPC connection failed");
  const auto body = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":" + params_json + "}";
  const auto request_text = "POST " + path_ + " HTTP/1.1\r\nHost: " + host_ + "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
  if (send(descriptor, request_text.data(), request_text.size(), 0) != static_cast<ssize_t>(request_text.size())) {
    close(descriptor);
    throw std::runtime_error("BCHN RPC request failed");
  }
  std::string response;
  char buffer[4096];
  while (true) {
    const auto received = recv(descriptor, buffer, sizeof(buffer), 0);
    if (received <= 0) break;
    response.append(buffer, static_cast<size_t>(received));
    if (response.size() > 8 * 1024 * 1024) { close(descriptor); throw std::runtime_error("BCHN RPC response is too large"); }
  }
  close(descriptor);
  const auto separator = response.find("\r\n\r\n");
  if (separator == std::string::npos) throw std::runtime_error("BCHN RPC response has no body");
  const auto status_end = response.find(' ');
  if (status_end == std::string::npos || response.substr(status_end + 1, 3) != "200")
    throw std::runtime_error("BCHN RPC returned a non-200 HTTP status");
  return response.substr(separator + 4);
}

BchnMempoolResult BchnRpcTransport::test_mempool_accept(const std::vector<uint8_t>& raw_transaction) {
  const auto response = request("testmempoolaccept", "[[\"" + bytes_to_hex(raw_transaction) + "\"]]");
  const auto allowed_position = response.find("\"allowed\"");
  if (allowed_position == std::string::npos) throw std::invalid_argument("BCHN testmempoolaccept result has no allowed flag");
  BchnMempoolResult result;
  result.allowed = response.find("true", allowed_position) < response.find(',', allowed_position);
  const auto txid_position = response.find("\"txid\"");
  if (txid_position != std::string::npos) result.txid = json_string(response, "txid");
  const auto reason_position = response.find("\"reject-reason\"");
  if (reason_position != std::string::npos) result.reason = json_string(response, "reject-reason");
  return result;
}

}
