#pragma once
#include "vm.hpp"
namespace x402bch {
using BigInt = mpz_class;
struct SecpPoint { BigInt x; BigInt y; bool infinity = false; };
inline BigInt secp_mod(BigInt value, const BigInt& modulus) { value %= modulus; if (value < 0) value += modulus; return value; }
inline BigInt secp_pow(BigInt base, BigInt exponent, const BigInt& modulus) { BigInt result = 1; base = secp_mod(base, modulus); while (exponent > 0) { if ((exponent & 1) != 0) result = secp_mod(result * base, modulus); base = secp_mod(base * base, modulus); exponent >>= 1; } return result; }
inline const BigInt& secp_p() { static const BigInt value("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16); return value; }
inline const BigInt& secp_n() { static const BigInt value("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16); return value; }
inline SecpPoint secp_g() { return {BigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16), BigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16), false}; }
inline SecpPoint secp_add(const SecpPoint& left, const SecpPoint& right) {
  if (left.infinity) return right; if (right.infinity) return left;
  const auto& modulus = secp_p(); if (left.x == right.x && secp_mod(left.y + right.y, modulus) == 0) return {{}, {}, true};
  BigInt lambda; if (left.x == right.x && left.y == right.y) lambda = secp_mod(BigInt(3) * left.x * left.x * secp_pow(BigInt(2) * left.y, modulus - 2, modulus), modulus); else lambda = secp_mod((right.y - left.y) * secp_pow(right.x - left.x, modulus - 2, modulus), modulus);
  const auto x = secp_mod(lambda * lambda - left.x - right.x, modulus); return {x, secp_mod(lambda * (left.x - x) - left.y, modulus), false};
}
inline SecpPoint secp_mul(BigInt scalar, SecpPoint point) { SecpPoint result{{}, {}, true}; while (scalar > 0) { const BigInt bit = scalar & 1; if (bit.get_ui() != 0) result = secp_add(result, point); point = secp_add(point, point); scalar >>= 1; } return result; }
inline SecpPoint decode_secp_public_key(const std::vector<uint8_t>& encoded) {
  if (encoded.size() != 33 || (encoded[0] != 2 && encoded[0] != 3)) throw std::invalid_argument("invalid compressed public key");
  BigInt x = 0; for (size_t index = 1; index < encoded.size(); index++) x = (x << 8) + encoded[index]; if (x >= secp_p()) throw std::invalid_argument("invalid compressed public key");
  const auto rhs = secp_mod(x * x * x + 7, secp_p()); auto y = secp_pow(rhs, (secp_p() + 1) / 4, secp_p()); if (secp_mod(y * y, secp_p()) != rhs) throw std::invalid_argument("invalid compressed public key"); const BigInt parity = y & 1; if (parity.get_ui() != (encoded[0] & 1)) y = secp_p() - y; return {x, y, false};
}
inline BigInt big_int_from_bytes(const std::vector<uint8_t>& value) { BigInt result = 0; for (auto item : value) result = (result << 8) + item; return result; }
inline std::pair<BigInt, BigInt> parse_der_signature(const std::vector<uint8_t>& value) {
  if (value.size() < 8 || value[0] != 0x30 || static_cast<size_t>(value[1]) + 2 != value.size()) throw std::invalid_argument("malformed DER signature"); size_t offset = 2; if (value[offset++] != 2) throw std::invalid_argument("malformed DER r"); const size_t r_length = value[offset++]; if (r_length == 0 || offset + r_length + 2 > value.size()) throw std::invalid_argument("malformed DER r"); std::vector<uint8_t> r(value.begin() + static_cast<std::ptrdiff_t>(offset), value.begin() + static_cast<std::ptrdiff_t>(offset + r_length)); offset += r_length; if (value[offset++] != 2) throw std::invalid_argument("malformed DER s"); const size_t s_length = value[offset++]; if (s_length == 0 || offset + s_length != value.size()) throw std::invalid_argument("malformed DER s"); std::vector<uint8_t> s(value.begin() + static_cast<std::ptrdiff_t>(offset), value.end()); if ((r[0] & 0x80) != 0 || (r.size() > 1 && r[0] == 0 && (r[1] & 0x80) == 0) || (s[0] & 0x80) != 0 || (s.size() > 1 && s[0] == 0 && (s[1] & 0x80) == 0)) throw std::invalid_argument("non-canonical DER integer"); return {big_int_from_bytes(r), big_int_from_bytes(s)};
}
inline bool verify_secp_ecdsa(const std::vector<uint8_t>& digest, const BigInt& r, const BigInt& s, const SecpPoint& public_key) {
  if (r <= 0 || r >= secp_n() || s <= 0 || s >= secp_n()) return false; const auto inverse = secp_pow(s, secp_n() - 2, secp_n()); const auto e = big_int_from_bytes(digest); const auto point = secp_add(secp_mul(secp_mod(e * inverse, secp_n()), secp_g()), secp_mul(secp_mod(r * inverse, secp_n()), public_key)); return !point.infinity && secp_mod(point.x, secp_n()) == r;
}

}
