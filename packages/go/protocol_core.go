package x402bch

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
)

func ValidateRequirements(r Requirements) error {
	if (r.X402Version != 0 && r.X402Version != 2) || r.Scheme != "exact" || (r.Network != "bch:bitcoincash" && r.Network != "bch:bchtest") || r.Asset == "" || r.PayTo == "" || !regexp.MustCompile(`^[0-9]+$`).MatchString(r.Amount) {
		return fmt.Errorf("unsupported x402 requirements")
	}
	if r.Extra["paymentFlow"] != "upfront" {
		return fmt.Errorf("BCH exact requires upfront payment")
	}
	if hash, ok := r.Extra["requestHash"].(string); ok && !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(hash) {
		return fmt.Errorf("requestHash must be 32-byte hexadecimal")
	}
	return nil
}

func ValidatePaymentPayload(p PaymentPayload, expected Requirements) error {
	if err := ValidateRequirements(expected); err != nil {
		return err
	}
	if p.X402Version != 2 || p.Accepted.Scheme != expected.Scheme || p.Accepted.Network != expected.Network || p.Accepted.Asset != expected.Asset || p.Accepted.Amount != expected.Amount || p.Accepted.PayTo != expected.PayTo || !reflect.DeepEqual(p.Accepted.Extra, expected.Extra) {
		return fmt.Errorf("accepted requirements mismatch")
	}
	decoded, err := base64.StdEncoding.DecodeString(p.Payload.Transaction)
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("transaction must be non-empty base64")
	}
	return nil
}

func RequestHash(canonicalRequest string) string {
	h := sha256.Sum256([]byte(canonicalRequest))
	return hex.EncodeToString(h[:])
}

// ValidateTransactionEnvelope checks the portable BCH transaction boundary.
// It deliberately does not claim to validate scripts, signatures, or tokens.
func ValidateTransactionEnvelope(encoded string) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < 10 {
		return fmt.Errorf("transaction envelope must be valid non-empty base64")
	}
	version := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24
	if version != 1 && version != 2 {
		return fmt.Errorf("unsupported transaction version")
	}
	if raw[4] == 0 {
		return fmt.Errorf("transaction must contain an input")
	}
	// This lightweight gate leaves full varint/script/token validation to the SDK.
	return nil
}

// TransactionID returns the conventional BCH txid for a base64 raw transaction.
func TransactionID(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("transaction must be non-empty base64")
	}
	return transactionIDFromRaw(raw), nil
}

func transactionIDFromRaw(raw []byte) string {
	first := sha256.Sum256(raw)
	second := sha256.Sum256(first[:])
	result := make([]byte, len(second))
	for i := range second {
		result[i] = second[len(second)-1-i]
	}
	return hex.EncodeToString(result)
}
