package x402bch

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ExactBchSignerClient is the low-level signer counterpart to ExactBchClient.
// It owns no wallet state: the caller supplies the signer and the provider
// supplies UTXOs and source-output facts.
type ExactBchSignerClient struct {
	Signer        BchSigner
	Provider      BchProvider
	FeeRate       uint64
	DustThreshold uint64
}

// CreatePaymentPayload selects provider UTXOs, builds a BCH ForkID payment,
// verifies the result against provider source outputs, and returns the x402
// exact payload. The wallet-backed client remains available when selection is
// intentionally delegated to an external wallet.
func (c ExactBchSignerClient) CreatePaymentPayload(requirements Requirements) (PaymentPayload, error) {
	if c.Signer == nil || c.Provider == nil {
		return PaymentPayload{}, fmt.Errorf("signer and provider are required")
	}
	if err := ValidateRequirements(requirements); err != nil {
		return PaymentPayload{}, err
	}
	merchantScript, tokenSupport, err := DecodeCashAddress(requirements.PayTo, requirements.Network)
	if err != nil {
		return PaymentPayload{}, err
	}
	if requirements.Asset != "BCH" && !tokenSupport {
		return PaymentPayload{}, fmt.Errorf("CashToken payments require a token-support merchant CashAddr")
	}
	address, err := c.Signer.Address(requirements.Network)
	if err != nil {
		return PaymentPayload{}, err
	}
	publicKey := c.Signer.PublicKey()
	payerScript := append([]byte{0x76, 0xa9, 0x14}, hash160(publicKey)...)
	payerScript = append(payerScript, 0x88, 0xac)
	utxos, err := c.Provider.ListUtxos(address)
	if err != nil {
		return PaymentPayload{}, err
	}
	utxos = filterSignerUtxos(utxos, payerScript, requirements)
	sort.SliceStable(utxos, func(left, right int) bool {
		l, _ := canonicalUint(utxos[left].Value)
		r, _ := canonicalUint(utxos[right].Value)
		return l > r
	})
	if len(utxos) == 0 {
		return PaymentPayload{}, fmt.Errorf("no compatible BCH UTXOs available")
	}
	feeRate := c.FeeRate
	if feeRate == 0 {
		feeRate = 1
	}
	dust := c.DustThreshold
	if dust == 0 {
		dust = 546
	}
	selected := make([]BchUtxo, 0, len(utxos))
	var selectedValue, selectedTokens uint64
	targetTokens := uint64(0)
	if requirements.Asset != "BCH" {
		targetTokens, err = canonicalUint(requirements.Amount)
		if err != nil {
			return PaymentPayload{}, err
		}
	}
	merchantValue := requirements.Amount
	if requirements.Asset != "BCH" {
		merchantValue = stringValueOr(requirements.Extra["value"], "1000")
	}
	merchantValueUint, err := canonicalUint(merchantValue)
	if err != nil {
		return PaymentPayload{}, err
	}
	for _, utxo := range utxos {
		value, valueErr := canonicalUint(utxo.Value)
		if valueErr != nil {
			return PaymentPayload{}, valueErr
		}
		selected = append(selected, utxo)
		selectedValue += value
		if utxo.Token != nil {
			selectedTokens += utxo.Token.Amount
		}
		if selectedValue >= merchantValueUint && (requirements.Asset == "BCH" || selectedTokens >= targetTokens) {
			break
		}
	}
	if selectedValue < merchantValueUint || (requirements.Asset != "BCH" && selectedTokens < targetTokens) {
		return PaymentPayload{}, fmt.Errorf("insufficient BCH/CashToken UTXOs for payment and fee")
	}
	var raw []byte
	if requirements.Asset == "BCH" {
		raw, err = BuildAndSignNativePayment(selected, merchantScript, merchantValueUint, c.Signer, requirements.Network, feeRate, dust, stringValue(requirements.Extra["requestHash"]))
	} else {
		nft := requestedNftState(requirements.Extra)
		raw, err = BuildAndSignCashTokenPayment(selected, merchantScript, merchantValueUint, targetTokens, requirements.Asset, nft, c.Signer, requirements.Network, feeRate, 1000, stringValue(requirements.Extra["requestHash"]))
	}
	if err != nil {
		return PaymentPayload{}, err
	}
	payload := PaymentPayload{X402Version: 2, Accepted: requirements}
	payload.Payload.Transaction = base64.StdEncoding.EncodeToString(raw)
	if err := (ExactBchClient{Provider: c.Provider}).verifyWalletPayment(raw, requirements); err != nil {
		return PaymentPayload{}, err
	}
	return payload, nil
}

func filterSignerUtxos(utxos []BchUtxo, payerScript []byte, requirements Requirements) []BchUtxo {
	result := make([]BchUtxo, 0, len(utxos))
	for _, utxo := range utxos {
		script, err := hex.DecodeString(utxo.ScriptPubKey)
		if err != nil || !bytes.Equal(script, payerScript) {
			continue
		}
		if requirements.Asset == "BCH" && utxo.Token != nil {
			continue
		}
		if requirements.Asset != "BCH" && utxo.Token != nil && !strings.EqualFold(utxo.Token.Category, requirements.Asset) {
			continue
		}
		result = append(result, utxo)
	}
	return result
}

func requestedNftState(extra map[string]interface{}) *NftState {
	token, _ := extra["token"].(map[string]interface{})
	nft, _ := token["nft"].(map[string]interface{})
	if nft == nil {
		return nil
	}
	return &NftState{Capability: stringValue(nft["capability"]), Commitment: decodeHexString(stringValue(nft["commitment"]))}
}
