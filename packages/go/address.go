package x402bch

import (
	"bytes"
	"fmt"
	"strings"
)

const cashAddrCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func cashAddrPrefix(network string) (string, error) {
	switch network {
	case "bch:bitcoincash":
		return "bitcoincash", nil
	case "bch:bchtest":
		return "bchtest", nil
	default:
		return "", fmt.Errorf("unsupported BCH network")
	}
}

func cashAddrPolymod(values []byte) uint64 {
	generator := [...]uint64{0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470}
	checksum := uint64(1)
	for _, value := range values {
		top := checksum >> 35
		checksum = ((checksum & 0x07ffffffff) << 5) ^ uint64(value)
		for index, item := range generator {
			if (top>>index)&1 != 0 {
				checksum ^= item
			}
		}
	}
	return checksum
}

func cashAddrPrefixExpand(prefix string) []byte {
	result := make([]byte, 0, len(prefix)+1)
	for _, value := range prefix {
		result = append(result, byte(value&0x1f))
	}
	return append(result, 0)
}

func cashAddrConvertBits(values []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	accumulator, bits := uint32(0), uint(0)
	maximum := uint32((1 << toBits) - 1)
	result := make([]byte, 0)
	for _, value := range values {
		if uint32(value)>>fromBits != 0 {
			return nil, fmt.Errorf("CashAddr data contains an invalid value")
		}
		accumulator = (accumulator << fromBits) | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((accumulator>>bits)&maximum))
		}
	}
	if pad {
		if bits != 0 {
			result = append(result, byte((accumulator<<(toBits-bits))&maximum))
		}
	} else if bits >= fromBits || ((accumulator<<(toBits-bits))&maximum) != 0 {
		return nil, fmt.Errorf("CashAddr has non-zero padding")
	}
	return result, nil
}

// DecodeCashAddress returns standard locking bytecode and CashToken support.
func DecodeCashAddress(address, network string) ([]byte, bool, error) {
	prefix, err := cashAddrPrefix(network)
	if err != nil {
		return nil, false, err
	}
	if address != strings.ToLower(address) {
		return nil, false, fmt.Errorf("CashAddr must be lowercase")
	}
	parts := strings.Split(address, ":")
	if len(parts) != 2 || parts[0] != prefix || parts[1] == "" {
		return nil, false, fmt.Errorf("CashAddr network mismatch")
	}
	encoded := parts[1]
	values := make([]byte, len(encoded))
	for index, value := range encoded {
		position := strings.IndexRune(cashAddrCharset, value)
		if position < 0 {
			return nil, false, fmt.Errorf("invalid CashAddr characters")
		}
		values[index] = byte(position)
	}
	if len(values) < 9 || cashAddrPolymod(append(cashAddrPrefixExpand(prefix), values...)) != 1 {
		return nil, false, fmt.Errorf("invalid CashAddr checksum")
	}
	payload, err := cashAddrConvertBits(values[:len(values)-8], 5, 8, false)
	if err != nil || len(payload) < 1 {
		return nil, false, fmt.Errorf("invalid CashAddr payload")
	}
	version := payload[0]
	tokenSupport := version&0x10 != 0
	baseVersion := version & 0x0f
	kind := baseVersion >> 3
	sizeCode := baseVersion & 0x07
	lengths := [...]int{20, 24, 28, 32, 40, 48, 56, 64}
	if (kind != 0 && kind != 1) || int(sizeCode) >= len(lengths) || len(payload[1:]) != lengths[sizeCode] {
		return nil, false, fmt.Errorf("unsupported CashAddr type")
	}
	hash := payload[1:]
	if kind == 0 {
		return append(append([]byte{0x76, 0xa9, 0x14}, hash...), 0x88, 0xac), tokenSupport, nil
	}
	if len(hash) == 20 {
		return append(append([]byte{0xa9, 0x14}, hash...), 0x87), tokenSupport, nil
	}
	if len(hash) == 32 {
		return append(append([]byte{0xaa, 0x20}, hash...), 0x87), tokenSupport, nil
	}
	return nil, false, fmt.Errorf("unsupported CashAddr payload")
}

// EncodeCashAddress encodes a standard P2PKH, P2SH20, or P2SH32 script.
func EncodeCashAddress(script []byte, network string, tokenSupport bool) (string, error) {
	prefix, err := cashAddrPrefix(network)
	if err != nil {
		return "", err
	}
	var version byte
	var payload []byte
	switch {
	case len(script) == 25 && bytes.Equal(script[:3], []byte{0x76, 0xa9, 0x14}) && bytes.Equal(script[23:], []byte{0x88, 0xac}):
		version, payload = 0, script[3:23]
	case len(script) == 23 && bytes.Equal(script[:2], []byte{0xa9, 0x14}) && script[22] == 0x87:
		version, payload = 8, script[2:22]
	case len(script) == 35 && bytes.Equal(script[:2], []byte{0xaa, 0x20}) && script[34] == 0x87:
		version, payload = 11, script[2:34]
	default:
		return "", fmt.Errorf("unsupported locking script for CashAddr")
	}
	if tokenSupport {
		version |= 0x10
	}
	data, err := cashAddrConvertBits(append([]byte{version}, payload...), 8, 5, true)
	if err != nil {
		return "", err
	}
	checksumInput := append(append(cashAddrPrefixExpand(prefix), data...), make([]byte, 8)...)
	checksum := cashAddrPolymod(checksumInput) ^ 1
	for index := uint(0); index < 8; index++ {
		data = append(data, byte((checksum>>(5*(7-index)))&0x1f))
	}
	var encoded strings.Builder
	for _, value := range data {
		encoded.WriteByte(cashAddrCharset[value])
	}
	return prefix + ":" + encoded.String(), nil
}
