"""BCH hashing and secp256k1 primitives."""

import hashlib
from typing import Optional

def _double_sha256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def _parse_der_signature(encoded: bytes) -> tuple[int, int]:
    if len(encoded) < 8 or encoded[0] != 0x30 or encoded[1] + 2 != len(encoded):
        raise ValueError("malformed DER signature")
    offset = 2
    if encoded[offset] != 0x02:
        raise ValueError("malformed DER r")
    r_length = encoded[offset + 1]
    offset += 2
    if r_length == 0 or offset + r_length + 2 > len(encoded):
        raise ValueError("malformed DER r")
    r_bytes = encoded[offset : offset + r_length]
    offset += r_length
    if encoded[offset] != 0x02:
        raise ValueError("malformed DER s")
    s_length = encoded[offset + 1]
    offset += 2
    if s_length == 0 or offset + s_length != len(encoded):
        raise ValueError("malformed DER s")
    s_bytes = encoded[offset : offset + s_length]
    for item in (r_bytes, s_bytes):
        if item[0] & 0x80 or (len(item) > 1 and item[0] == 0 and item[1] < 0x80):
            raise ValueError("non-canonical DER integer")
    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


def _secp_point_add(left: tuple[int, int] | None, right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % _SECP256K1_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, _SECP256K1_P) % _SECP256K1_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _SECP256K1_P) % _SECP256K1_P
    x3 = (slope * slope - x1 - x2) % _SECP256K1_P
    return x3, (slope * (x1 - x3) - y1) % _SECP256K1_P


def _secp_point_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result = None
    base = point
    while scalar:
        if scalar & 1:
            result = _secp_point_add(result, base)
        base = _secp_point_add(base, base)
        scalar >>= 1
    return result


def _decode_compressed_public_key(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid compressed public key")
    x = int.from_bytes(encoded[1:], "big")
    if x >= _SECP256K1_P:
        raise ValueError("invalid compressed public key")
    y = pow((x * x * x + 7) % _SECP256K1_P, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if y * y % _SECP256K1_P != (x * x * x + 7) % _SECP256K1_P:
        raise ValueError("invalid compressed public key")
    if y & 1 != encoded[0] & 1:
        y = _SECP256K1_P - y
    return x, y


def _verify_secp256k1_ecdsa(digest: bytes, r: int, s: int, encoded_public_key: bytes) -> bool:
    if not 0 < r < _SECP256K1_N or not 0 < s < _SECP256K1_N:
        return False
    public_key = _decode_compressed_public_key(encoded_public_key)
    inverse = pow(s, -1, _SECP256K1_N)
    e = int.from_bytes(digest, "big")
    point = _secp_point_add(
        _secp_point_mul(e * inverse % _SECP256K1_N, _SECP256K1_G),
        _secp_point_mul(r * inverse % _SECP256K1_N, public_key),
    )
    return point is not None and point[0] % _SECP256K1_N == r


def _hash160(value: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(value).digest())


def _ripemd160(message: bytes) -> bytes:
    data = bytearray(message)
    bit_length = len(data) * 8
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data.extend(bit_length.to_bytes(8, "little"))
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    r_left = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    r_right = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    s_left = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    s_right = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    k_left = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k_right = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]
    def rol(value: int, shift: int) -> int:
        return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF
    def function(index: int, x: int, y: int, z: int) -> int:
        if index < 16: return x ^ y ^ z
        if index < 32: return (x & y) | (~x & z)
        if index < 48: return (x | ~y) ^ z
        if index < 64: return (x & z) | (y & ~z)
        return x ^ (y | ~z)
    for offset in range(0, len(data), 64):
        words = [int.from_bytes(data[offset + index * 4 : offset + index * 4 + 4], "little") for index in range(16)]
        left = h[:]
        right = h[:]
        for index in range(80):
            value = (rol((left[0] + function(index, left[1], left[2], left[3]) + words[r_left[index]] + k_left[index // 16]) & 0xFFFFFFFF, s_left[index]) + left[4]) & 0xFFFFFFFF
            left = [left[4], value, left[1], rol(left[2], 10), left[3]]
            value = (rol((right[0] + function(79 - index, right[1], right[2], right[3]) + words[r_right[index]] + k_right[index // 16]) & 0xFFFFFFFF, s_right[index]) + right[4]) & 0xFFFFFFFF
            right = [right[4], value, right[1], rol(right[2], 10), right[3]]
        h = [(h[1] + left[2] + right[3]) & 0xFFFFFFFF, (h[2] + left[3] + right[4]) & 0xFFFFFFFF, (h[3] + left[4] + right[0]) & 0xFFFFFFFF, (h[4] + left[0] + right[1]) & 0xFFFFFFFF, (h[0] + left[1] + right[2]) & 0xFFFFFFFF]
    return b"".join(value.to_bytes(4, "little") for value in h)
