package x402bch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

type Requirements struct { X402Version int `json:"x402Version"`; Scheme string `json:"scheme"`; Amount string `json:"amount"`; Extra map[string]interface{} `json:"extra"` }

func ValidateRequirements(r Requirements) error {
	if r.X402Version != 2 || r.Scheme != "exact" || !regexp.MustCompile(`^[0-9]+$`).MatchString(r.Amount) { return fmt.Errorf("unsupported x402 requirements") }
	if r.Extra["paymentFlow"] != "upfront" { return fmt.Errorf("BCH exact requires upfront payment") }
	if hash, ok := r.Extra["requestHash"].(string); ok && !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(hash) { return fmt.Errorf("requestHash must be 32-byte hexadecimal") }
	return nil
}

func RequestHash(resource interface{}) (string, error) { b, err := json.Marshal(resource); if err != nil { return "", err }; h := sha256.Sum256(b); return hex.EncodeToString(h[:]), nil }
