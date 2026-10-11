package x402bch

import (
	"encoding/base64"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

type Requirements struct {
	X402Version int `json:"x402Version"`
	Scheme string `json:"scheme"`
	Network string `json:"network"`
	Amount string `json:"amount"`
	Asset string `json:"asset"`
	PayTo string `json:"payTo"`
	Extra map[string]interface{} `json:"extra"`
}

type PaymentPayload struct {
	X402Version int `json:"x402Version"`
	Payload struct { Transaction string `json:"transaction"` } `json:"payload"`
	Accepted Requirements `json:"accepted"`
}

func ValidateRequirements(r Requirements) error {
	if (r.X402Version != 0 && r.X402Version != 2) || r.Scheme != "exact" || (r.Network != "bch:bitcoincash" && r.Network != "bch:bchtest") || r.Asset == "" || r.PayTo == "" || !regexp.MustCompile(`^[0-9]+$`).MatchString(r.Amount) { return fmt.Errorf("unsupported x402 requirements") }
	if r.Extra["paymentFlow"] != "upfront" { return fmt.Errorf("BCH exact requires upfront payment") }
	if hash, ok := r.Extra["requestHash"].(string); ok && !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(hash) { return fmt.Errorf("requestHash must be 32-byte hexadecimal") }
	return nil
}

func ValidatePaymentPayload(p PaymentPayload, expected Requirements) error {
	if err := ValidateRequirements(expected); err != nil { return err }
	if p.X402Version != 2 || p.Accepted.Scheme != expected.Scheme || p.Accepted.Network != expected.Network || p.Accepted.Asset != expected.Asset || p.Accepted.Amount != expected.Amount || p.Accepted.PayTo != expected.PayTo { return fmt.Errorf("accepted requirements mismatch") }
	decoded, err := base64.StdEncoding.DecodeString(p.Payload.Transaction)
	if err != nil || len(decoded) == 0 { return fmt.Errorf("transaction must be non-empty base64") }
	return nil
}

func RequestHash(canonicalRequest string) string { h := sha256.Sum256([]byte(canonicalRequest)); return hex.EncodeToString(h[:]) }
