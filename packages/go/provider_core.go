package x402bch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type FulcrumTransport interface {
	Request(method string, params []interface{}) (interface{}, error)
}

// FailoverFulcrumTransport retries one request across caller-supplied transports.
type FailoverFulcrumTransport struct{ transports []FulcrumTransport }

func NewFailoverFulcrumTransport(transports ...FulcrumTransport) (*FailoverFulcrumTransport, error) {
	if len(transports) == 0 {
		return nil, fmt.Errorf("at least one Fulcrum transport is required")
	}
	return &FailoverFulcrumTransport{transports: transports}, nil
}

// FulcrumProvider maps an injected Electrum Cash transport to BchProvider.
// It deliberately does not create endpoints or assume a public provider.
type FulcrumProvider struct {
	network   string
	transport FulcrumTransport
}

func NewFulcrumProvider(network string, transport FulcrumTransport) (*FulcrumProvider, error) {
	if network != "bch:bitcoincash" && network != "bch:bchtest" {
		return nil, fmt.Errorf("unsupported BCH network")
	}
	if transport == nil {
		return nil, fmt.Errorf("Fulcrum transport is required")
	}
	return &FulcrumProvider{network: network, transport: transport}, nil
}

func (p *FulcrumProvider) Network() string { return p.network }

func (p *FulcrumProvider) scriptHash(address string) (string, error) {
	script, _, err := DecodeCashAddress(address, p.network)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(script)
	for i, j := 0, len(hash)-1; i < j; i, j = i+1, j-1 {
		hash[i], hash[j] = hash[j], hash[i]
	}
	return hex.EncodeToString(hash[:]), nil
}

func (p *FulcrumProvider) ListUtxos(address string) ([]BchUtxo, error) {
	scriptHash, err := p.scriptHash(address)
	if err != nil {
		return nil, err
	}
	result, err := p.transport.Request("blockchain.scripthash.listunspent", []interface{}{scriptHash, "include_tokens"})
	if err != nil {
		return nil, err
	}
	items, ok := result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Fulcrum listunspent response is not an array")
	}
	script, _, err := DecodeCashAddress(address, p.network)
	if err != nil {
		return nil, err
	}
	utxos := make([]BchUtxo, 0, len(items))
	for _, raw := range items {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid Fulcrum UTXO entry")
		}
		txid := stringValue(entry["tx_hash"])
		if txid == "" {
			txid = stringValue(entry["txid"])
		}
		vout, ok := uint32Value(entry["tx_pos"])
		if !ok {
			vout, ok = uint32Value(entry["vout"])
		}
		if len(txid) != 64 || !ok {
			return nil, fmt.Errorf("invalid Fulcrum UTXO outpoint")
		}
		height, heightOK := uint64Value(entry["height"])
		token, tokenErr := cashTokenFromFulcrumEntry(entry)
		if tokenErr != nil {
			return nil, tokenErr
		}
		utxo := BchUtxo{Txid: txid, Vout: vout, Value: stringValue(entry["value"]), ScriptPubKey: hex.EncodeToString(script), Token: token}
		if heightOK && height > 0 {
			utxo.Height = &height
		}
		utxos = append(utxos, utxo)
	}
	return utxos, nil
}

func cashTokenFromFulcrumEntry(entry map[string]interface{}) (*CashToken, error) {
	raw, ok := entry["tokenData"]
	if !ok {
		raw, ok = entry["token_data"]
	}
	if !ok || raw == nil {
		return nil, nil
	}
	data, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid Fulcrum CashToken data")
	}
	category := stringValue(data["category"])
	if len(category) != 64 {
		return nil, fmt.Errorf("invalid Fulcrum CashToken category")
	}
	amount := stringValue(data["amount"])
	if amount == "" && data["amount"] != nil {
		amount = fmt.Sprintf("%v", data["amount"])
	}
	if amount == "" {
		amount = "0"
	}
	parsedAmount, err := canonicalUint(amount)
	if err != nil {
		return nil, fmt.Errorf("invalid Fulcrum CashToken amount: %w", err)
	}
	var nft *NftState
	if rawNft, exists := data["nft"]; exists && rawNft != nil {
		nftData, nftOK := rawNft.(map[string]interface{})
		if !nftOK {
			return nil, fmt.Errorf("invalid Fulcrum CashToken NFT data")
		}
		commitment, decodeErr := hex.DecodeString(stringValue(nftData["commitment"]))
		if decodeErr != nil {
			return nil, fmt.Errorf("invalid Fulcrum CashToken NFT commitment: %w", decodeErr)
		}
		nft = &NftState{Capability: stringValue(nftData["capability"]), Commitment: commitment}
	}
	return &CashToken{Category: strings.ToLower(category), Amount: parsedAmount, Nft: nft}, nil
}

func (p *FulcrumProvider) GetSourceOutput(txid string, vout uint32) (SourceOutput, error) {
	result, err := p.transport.Request("blockchain.transaction.get", []interface{}{txid, true})
	if err != nil {
		return SourceOutput{}, err
	}
	object, ok := result.(map[string]interface{})
	if !ok {
		return SourceOutput{}, fmt.Errorf("invalid Fulcrum transaction response")
	}
	outputs, ok := object["vout"].([]interface{})
	if !ok {
		return SourceOutput{}, fmt.Errorf("Fulcrum transaction response has no vout array")
	}
	for _, raw := range outputs {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		n, nOK := uint32Value(entry["n"])
		script, sOK := entry["scriptPubKey"].(map[string]interface{})
		scriptHex, hOK := script["hex"].(string)
		if nOK && n == vout && sOK && hOK {
			return SourceOutput{Value: stringValue(entry["value"]), ScriptPubKey: scriptHex}, nil
		}
	}
	return SourceOutput{}, fmt.Errorf("source output was not found")
}

func (p *FulcrumProvider) GetOutpointStatus(txid string, vout uint32) (string, error) {
	// A transaction lookup alone cannot prove whether one output is spent.
	// Do not infer spend state from confirmation height.
	_ = txid
	_ = vout
	return "unknown", nil
}

func (p *FulcrumProvider) Broadcast(raw []byte) (string, error) {
	result, err := p.transport.Request("blockchain.transaction.broadcast", []interface{}{hex.EncodeToString(raw)})
	if err != nil {
		return "", err
	}
	txid, ok := result.(string)
	if !ok || len(txid) != 64 {
		return "", fmt.Errorf("Fulcrum broadcast did not return a transaction ID")
	}
	return strings.ToLower(txid), nil
}

func (p *FulcrumProvider) GetTransaction(txid string) ([]byte, bool, error) {
	result, err := p.transport.Request("blockchain.transaction.get", []interface{}{txid})
	if err != nil {
		return nil, false, err
	}
	text, ok := result.(string)
	if !ok {
		return nil, false, fmt.Errorf("Fulcrum transaction response is not raw hexadecimal data")
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func (p *FulcrumProvider) GetTransactionStatus(txid string) (BchTransactionStatus, error) {
	result, err := p.transport.Request("blockchain.transaction.get_height", []interface{}{txid})
	if err != nil {
		return BchTransactionStatus{}, err
	}
	height, ok := uint64Value(result)
	if ok && height > 0 {
		return BchTransactionStatus{Kind: "confirmed", Height: &height}, nil
	}
	if result == float64(0) || result == float64(-1) || result == int(0) || result == int(-1) {
		return BchTransactionStatus{Kind: "mempool"}, nil
	}
	return BchTransactionStatus{Kind: "notFound"}, nil
}

func (p *FulcrumProvider) GetTipHeight() (uint64, error) {
	result, err := p.transport.Request("blockchain.headers.subscribe", []interface{}{})
	if err != nil {
		return 0, err
	}
	object, ok := result.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid Fulcrum chain tip")
	}
	height, ok := uint64Value(object["height"])
	if !ok {
		return 0, fmt.Errorf("invalid Fulcrum chain tip")
	}
	return height, nil
}

func (p *FulcrumProvider) HasDoubleSpendProof(txid string) (bool, error) {
	result, err := p.transport.Request("blockchain.transaction.dsproof.get", []interface{}{txid})
	if err != nil {
		return false, err
	}
	return result != nil && result != "", nil
}

func uint64Value(value interface{}) (uint64, bool) {
	switch number := value.(type) {
	case uint64:
		return number, true
	case uint32:
		return uint64(number), true
	case int:
		if number >= 0 {
			return uint64(number), true
		}
	case int64:
		if number >= 0 {
			return uint64(number), true
		}
	case float64:
		if number >= 0 && number == float64(uint64(number)) {
			return uint64(number), true
		}
	}
	return 0, false
}

func uint32Value(value interface{}) (uint32, bool) {
	number, ok := uint64Value(value)
	if !ok || number > uint64(^uint32(0)) {
		return 0, false
	}
	return uint32(number), true
}

func (t *FailoverFulcrumTransport) Request(method string, params []interface{}) (interface{}, error) {
	var last error
	for _, transport := range t.transports {
		result, err := transport.Request(method, params)
		if err == nil {
			return result, nil
		}
		last = err
	}
	return nil, fmt.Errorf("all Fulcrum transports failed: %w", last)
}

// BchSettlementStore is the replay/idempotency boundary, not settlement truth.
