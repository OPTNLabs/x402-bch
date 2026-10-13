package x402bch

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

type BchWallet interface {
	CreatePayment(BchTransactionRequest) ([]byte, error)
}

// BchSigner is the low-level signing boundary for applications that own UTXO
// selection and transaction construction. It never exposes private key bytes.
type BchSigner interface {
	PublicKey() []byte
	SignDigest(digest []byte) ([]byte, error)
	Address(network string) (string, error)
}

type BchUtxo struct {
	Txid         string
	Vout         uint32
	Value        string
	ScriptPubKey string
	Token        *CashToken
	Height       *uint64
}

// BchTransactionStatus is provider-observed chain state.
type BchTransactionStatus struct {
	Kind   string
	Height *uint64
}

// BchProvider is the chain-truth boundary for client validation and settlement.
type BchProvider interface {
	Network() string
	ListUtxos(address string) ([]BchUtxo, error)
	GetSourceOutput(txid string, vout uint32) (SourceOutput, error)
	GetOutpointStatus(txid string, vout uint32) (string, error)
	Broadcast(raw []byte) (string, error)
	GetTransaction(txid string) ([]byte, bool, error)
	GetTransactionStatus(txid string) (BchTransactionStatus, error)
	GetTipHeight() (uint64, error)
	HasDoubleSpendProof(txid string) (bool, error)
}

// BuildAndSignNativePayment constructs a deterministic native-BCH payment from
// explicit UTXOs. Key custody, UTXO selection, and signer policy remain with
// the caller; this function only builds, signs, and validates the transition.
func BuildAndSignNativePayment(selected []BchUtxo, merchantScript []byte, merchantValue uint64, signer BchSigner, network string, feeRate, dustThreshold uint64, requestHash ...string) ([]byte, error) {
	if len(selected) == 0 || len(selected) > 100 {
		return nil, fmt.Errorf("invalid BCH input count")
	}
	if merchantValue < dustThreshold {
		return nil, fmt.Errorf("merchant output is dust")
	}
	var inputValue uint64
	sources := make([]SourceOutput, len(selected))
	inputs := make([]TransactionInput, len(selected))
	for i, utxo := range selected {
		value, err := canonicalUint(utxo.Value)
		if err != nil {
			return nil, err
		}
		if ^uint64(0)-inputValue < value {
			return nil, fmt.Errorf("input value exceeds u64")
		}
		inputValue += value
		sources[i] = SourceOutput{Value: utxo.Value, ScriptPubKey: utxo.ScriptPubKey, Token: utxo.Token}
		inputs[i] = TransactionInput{Txid: utxo.Txid, Vout: utxo.Vout, Sequence: 0xffffffff}
	}
	if inputValue < merchantValue {
		return nil, fmt.Errorf("selected BCH UTXOs do not cover payment")
	}
	address, err := signer.Address(network)
	if err != nil {
		return nil, err
	}
	changeScript, _, err := DecodeCashAddress(address, networkToChain(network))
	if err != nil {
		return nil, err
	}
	change := inputValue - merchantValue
	commitment := []byte(nil)
	if len(requestHash) > 1 {
		return nil, fmt.Errorf("at most one request hash is supported")
	} else if len(requestHash) == 1 && requestHash[0] != "" {
		commitment, err = RequestHashScript(requestHash[0])
		if err != nil {
			return nil, err
		}
	}
	push := func(value []byte) ([]byte, error) {
		if len(value) > 75 {
			return nil, fmt.Errorf("push value is too large")
		}
		return append([]byte{byte(len(value))}, value...), nil
	}
	for attempt := 0; attempt < 32; attempt++ {
		includeChange := change >= dustThreshold
		outputs := []TransactionOutput{{Value: merchantValue, ScriptPubKey: merchantScript}}
		if includeChange {
			outputs = append(outputs, TransactionOutput{Value: change, ScriptPubKey: changeScript})
		}
		if commitment != nil {
			outputs = append(outputs, TransactionOutput{Value: 0, ScriptPubKey: commitment})
		}
		tx := Transaction{Version: 2, Inputs: append([]TransactionInput(nil), inputs...), Outputs: outputs}
		publicKey := signer.PublicKey()
		for index, utxo := range selected {
			digest, err := SigningHash(tx, index, sources[index])
			if err != nil {
				return nil, err
			}
			signature, err := signer.SignDigest(digest)
			if err != nil {
				return nil, err
			}
			signature = append(signature, 0x41)
			sigPush, err := push(signature)
			if err != nil {
				return nil, err
			}
			keyPush, err := push(publicKey)
			if err != nil {
				return nil, err
			}
			tx.Inputs[index].ScriptSig = append(sigPush, keyPush...)
			_ = utxo
		}
		raw, err := SerializeTransaction(tx)
		if err != nil {
			return nil, err
		}
		requiredFee := uint64(len(raw)) * feeRate
		available := inputValue - merchantValue
		if !includeChange {
			if available < requiredFee {
				return nil, fmt.Errorf("selected BCH UTXOs do not cover fee")
			}
			if _, err := VerifyNativePayment(tx, sources, fmt.Sprint(merchantValue), hex.EncodeToString(merchantScript), feeRate, dustThreshold); err != nil {
				return nil, err
			}
			return raw, nil
		}
		if available < requiredFee {
			return nil, fmt.Errorf("selected BCH UTXOs do not cover fee")
		}
		desiredChange := available - requiredFee
		if desiredChange < dustThreshold {
			change = 0
			continue
		}
		if change > desiredChange {
			change = desiredChange
			continue
		}
		if _, err := VerifyNativePayment(tx, sources, fmt.Sprint(merchantValue), hex.EncodeToString(merchantScript), feeRate, dustThreshold); err != nil {
			return nil, err
		}
		return raw, nil
	}
	return nil, fmt.Errorf("BCH fee/change calculation did not converge")
}

// BuildAndSignCashTokenPayment constructs a fungible/NFT CashToken payment
// while preserving token conservation and BCH fee/change invariants.
func BuildAndSignCashTokenPayment(selected []BchUtxo, merchantScript []byte, merchantValue, tokenAmount uint64, category string, merchantNFT *NftState, signer BchSigner, network string, feeRate, dustThreshold uint64, requestHash ...string) ([]byte, error) {
	if len(selected) == 0 || len(category) != 64 {
		return nil, fmt.Errorf("invalid CashToken payment")
	}
	var inputValue, sourceAmount uint64
	sources := make([]CashTokenSource, len(selected))
	inputs := make([]TransactionInput, len(selected))
	nftCount := 0
	for i, utxo := range selected {
		if utxo.Token != nil && !strings.EqualFold(utxo.Token.Category, category) {
			return nil, fmt.Errorf("selected UTXOs do not contain the requested CashToken")
		}
		value, valueErr := canonicalUint(utxo.Value)
		if valueErr != nil {
			return nil, valueErr
		}
		if ^uint64(0)-inputValue < value {
			return nil, fmt.Errorf("input value exceeds u64")
		}
		inputValue += value
		sourceToken := CashToken{Category: strings.ToLower(category)}
		if utxo.Token != nil {
			sourceToken = *utxo.Token
		}
		if ^uint64(0)-sourceAmount < sourceToken.Amount {
			return nil, fmt.Errorf("CashToken amount exceeds u64")
		}
		sourceAmount += sourceToken.Amount
		if utxo.Token != nil && utxo.Token.Nft != nil {
			nftCount++
			if merchantNFT == nil || utxo.Token.Nft.Capability != merchantNFT.Capability || !bytes.Equal(utxo.Token.Nft.Commitment, merchantNFT.Commitment) {
				return nil, fmt.Errorf("selected NFT state does not match merchant output")
			}
		}
		sources[i] = CashTokenSource{Value: utxo.Value, Token: sourceToken}
		inputs[i] = TransactionInput{Txid: utxo.Txid, Vout: utxo.Vout, Sequence: 0xffffffff}
	}
	if sourceAmount < tokenAmount || inputValue < merchantValue || (merchantNFT == nil && nftCount != 0) {
		return nil, fmt.Errorf("selected UTXOs do not cover CashToken payment")
	}
	address, err := signer.Address(network)
	if err != nil {
		return nil, err
	}
	changeScript, _, err := DecodeCashAddress(address, networkToChain(network))
	if err != nil {
		return nil, err
	}
	changeValue, tokenChange := inputValue-merchantValue, sourceAmount-tokenAmount
	commitment := []byte(nil)
	if len(requestHash) > 1 {
		return nil, fmt.Errorf("at most one request hash is supported")
	} else if len(requestHash) == 1 && requestHash[0] != "" {
		commitment, err = RequestHashScript(requestHash[0])
		if err != nil {
			return nil, err
		}
	}
	push := func(value []byte) ([]byte, error) {
		if len(value) > 75 {
			return nil, fmt.Errorf("push value is too large")
		}
		return append([]byte{byte(len(value))}, value...), nil
	}
	for attempt := 0; attempt < 32; attempt++ {
		if tokenChange > 0 && changeValue < dustThreshold {
			return nil, fmt.Errorf("CashToken change requires dust-valued BCH output")
		}
		outputs := []TransactionOutput{{Value: merchantValue, ScriptPubKey: merchantScript, Token: &CashToken{Category: strings.ToLower(category), Amount: tokenAmount, Nft: merchantNFT}}}
		if tokenChange > 0 {
			outputs = append(outputs, TransactionOutput{Value: changeValue, ScriptPubKey: changeScript, Token: &CashToken{Category: strings.ToLower(category), Amount: tokenChange}})
		}
		if commitment != nil {
			outputs = append(outputs, TransactionOutput{Value: 0, ScriptPubKey: commitment})
		}
		tx := Transaction{Version: 2, Inputs: append([]TransactionInput(nil), inputs...), Outputs: outputs}
		publicKey := signer.PublicKey()
		for index, utxo := range selected {
			digest, err := SigningHash(tx, index, SourceOutput{Value: sources[index].Value, ScriptPubKey: selected[index].ScriptPubKey, Token: selected[index].Token})
			if err != nil {
				return nil, err
			}
			signature, err := signer.SignDigest(digest)
			if err != nil {
				return nil, err
			}
			signature = append(signature, 0x41)
			sigPush, err := push(signature)
			if err != nil {
				return nil, err
			}
			keyPush, err := push(publicKey)
			if err != nil {
				return nil, err
			}
			tx.Inputs[index].ScriptSig = append(sigPush, keyPush...)
			_ = utxo
		}
		raw, err := SerializeTransaction(tx)
		if err != nil {
			return nil, err
		}
		requiredFee := uint64(len(raw)) * feeRate
		available := inputValue - merchantValue
		if available < requiredFee {
			return nil, fmt.Errorf("selected BCH UTXOs do not cover fee")
		}
		desired := available - requiredFee
		if tokenChange == 0 && desired < 546 {
			desired = 0
		}
		if tokenChange > 0 && desired < dustThreshold {
			return nil, fmt.Errorf("selected BCH UTXOs do not cover token change dust")
		}
		if changeValue > desired {
			changeValue = desired
			continue
		}
		if _, err := VerifyCashTokenPaymentWithNFT(tx, sources, fmt.Sprint(merchantValue), hex.EncodeToString(merchantScript), category, fmt.Sprint(tokenAmount), merchantNFT, feeRate, dustThreshold); err != nil {
			return nil, err
		}
		return raw, nil
	}
	return nil, fmt.Errorf("BCH fee/change calculation did not converge")
}

func networkToChain(network string) string {
	if network == "mainnet" || network == "bch:bitcoincash" {
		return "bch:bitcoincash"
	}
	return "bch:bchtest"
}

// FulcrumTransport is the injected Electrum Cash JSON-RPC boundary.
