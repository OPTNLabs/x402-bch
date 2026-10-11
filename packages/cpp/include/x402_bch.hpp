#pragma once
#include <regex>
#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace x402bch {
struct Requirements {
  int version;
  std::string scheme;
  std::string network;
  std::string amount;
  std::string pay_to;
  std::string payment_flow;
};

struct PaymentPayload {
  int version;
  std::string scheme;
  std::string network;
  std::string transaction;
  Requirements accepted;
};

inline void validate_requirements(int version, const std::string& scheme, const std::string& amount, const std::string& flow) {
  if (version != 2 || scheme != "exact" || !std::regex_match(amount, std::regex("[0-9]+")) || flow != "upfront") throw std::invalid_argument("unsupported x402 requirements");
}

inline bool valid_base64(const std::string& value) {
  if (value.empty() || value.size() % 4 != 0) return false;
  return value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos;
}

inline std::string request_hash(const std::string& canonical_json) {
  constexpr std::array<uint32_t, 64> k = {
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  auto rotr = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };
  std::vector<uint8_t> data(canonical_json.begin(), canonical_json.end());
  const uint64_t bit_length = static_cast<uint64_t>(data.size()) * 8;
  data.push_back(0x80);
  while (data.size() % 64 != 56) data.push_back(0);
  for (int shift = 56; shift >= 0; shift -= 8) data.push_back(static_cast<uint8_t>(bit_length >> shift));
  std::array<uint32_t, 8> h = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  for (size_t offset = 0; offset < data.size(); offset += 64) {
    std::array<uint32_t, 64> w{};
    for (size_t i = 0; i < 16; ++i) w[i] = (static_cast<uint32_t>(data[offset+i*4]) << 24) | (static_cast<uint32_t>(data[offset+i*4+1]) << 16) | (static_cast<uint32_t>(data[offset+i*4+2]) << 8) | data[offset+i*4+3];
    for (size_t i = 16; i < 64; ++i) { const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3); const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10); w[i] = w[i-16] + s0 + w[i-7] + s1; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],x=h[7];
    for (size_t i = 0; i < 64; ++i) { const uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25); const uint32_t ch=(e&f)^((~e)&g); const uint32_t temp1=x+S1+ch+k[i]+w[i]; const uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22); const uint32_t maj=(a&b)^(a&c)^(b&c); const uint32_t temp2=S0+maj; x=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2; }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=x;
  }
  std::ostringstream out; out << std::hex << std::setfill('0'); for (uint32_t word : h) out << std::setw(8) << word; return out.str();
}

inline void validate_payment_payload(const PaymentPayload& payload, const Requirements& expected) {
  validate_requirements(expected.version, expected.scheme, expected.amount, expected.payment_flow);
  if (payload.version != 2 || payload.scheme != expected.scheme || payload.network != expected.network)
    throw std::invalid_argument("payment payload does not bind to requirements");
  if (payload.accepted.network != expected.network || payload.accepted.amount != expected.amount || payload.accepted.pay_to != expected.pay_to)
    throw std::invalid_argument("accepted requirements mismatch");
  if (!valid_base64(payload.transaction)) throw std::invalid_argument("transaction must be non-empty base64");
}
}
