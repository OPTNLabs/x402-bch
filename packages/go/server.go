package x402bch

import (
	"encoding/hex"
	"fmt"
	"regexp"
)

const defaultServerTimeoutSeconds = 300

// BuildNativeRequirements creates the server-side x402 exact BCH offer.
// requestHash may be empty when the resource does not require URL binding.
func BuildNativeRequirements(network, payTo, amount, requestHash string) (Requirements, error) {
	if err := validateServerInputs(network, payTo, amount); err != nil {
		return Requirements{}, err
	}
	extra := map[string]interface{}{
		"assetTransferMethod": "native",
		"paymentFlow":         "upfront",
	}
	if requestHash != "" {
		if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(requestHash) {
			return Requirements{}, fmt.Errorf("requestHash must be 32-byte hexadecimal")
		}
		extra["requestHash"] = requestHash
	}
	return Requirements{
		X402Version:       2,
		Scheme:            "exact",
		Network:           network,
		Amount:            amount,
		Asset:             "BCH",
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultServerTimeoutSeconds,
		Extra:             extra,
	}, nil
}

// BuildCashTokenRequirements creates a fungible or NFT CashToken offer.
// value is the BCH satoshi value assigned to the token-bearing merchant output.
func BuildCashTokenRequirements(network, payTo, category, amount, value, requestHash string, nft *NftState) (Requirements, error) {
	if err := validateServerInputs(network, payTo, amount); err != nil {
		return Requirements{}, err
	}
	if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(category) {
		return Requirements{}, fmt.Errorf("CashToken category must be 32-byte hexadecimal")
	}
	if value == "" {
		value = "1000"
	}
	if !regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(value) {
		return Requirements{}, fmt.Errorf("CashToken value must be canonical satoshis")
	}
	extra := map[string]interface{}{
		"assetTransferMethod": "cashtoken",
		"paymentFlow":         "upfront",
		"value":               value,
		"token": map[string]interface{}{
			"category": category,
			"amount":   amount,
		},
	}
	if nft != nil {
		extra["token"].(map[string]interface{})["nft"] = map[string]interface{}{
			"capability": nft.Capability,
			"commitment": hex.EncodeToString(nft.Commitment),
		}
	}
	if requestHash != "" {
		if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(requestHash) {
			return Requirements{}, fmt.Errorf("requestHash must be 32-byte hexadecimal")
		}
		extra["requestHash"] = requestHash
	}
	return Requirements{
		X402Version:       2,
		Scheme:            "exact",
		Network:           network,
		Amount:            amount,
		Asset:             category,
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultServerTimeoutSeconds,
		Extra:             extra,
	}, nil
}

func validateServerInputs(network, payTo, amount string) error {
	if network != "bch:bitcoincash" && network != "bch:bchtest" {
		return fmt.Errorf("unsupported BCH network")
	}
	if payTo == "" {
		return fmt.Errorf("payTo is required")
	}
	if !regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(amount) {
		return fmt.Errorf("amount must be a canonical decimal string")
	}
	return nil
}
