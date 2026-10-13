package x402bch

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

type MocknetInput struct {
	Txid string
	Vout uint32
}

type MocknetTransaction struct {
	Txid           string
	RawTransaction []byte
	Inputs         []MocknetInput
	Outputs        []SourceOutput
}

// MocknetProvider is a deterministic UTXO provider. It never contacts BCHN,
// Fulcrum, or a wallet and only accepts transactions registered by the test.
type MocknetProvider struct {
	network      string
	tipHeight    uint64
	mu           sync.Mutex
	unspent      map[string]BchUtxo
	outputs      map[string]SourceOutput
	registered   map[string]MocknetTransaction
	transactions map[string][]byte
	statuses     map[string]BchTransactionStatus
}

func NewMocknetProvider(network string, initial []BchUtxo, tipHeight uint64) (*MocknetProvider, error) {
	if network != "bch:bitcoincash" && network != "bch:bchtest" {
		return nil, fmt.Errorf("unsupported BCH network")
	}
	provider := &MocknetProvider{network: network, tipHeight: tipHeight, unspent: map[string]BchUtxo{}, outputs: map[string]SourceOutput{}, registered: map[string]MocknetTransaction{}, transactions: map[string][]byte{}, statuses: map[string]BchTransactionStatus{}}
	for _, utxo := range initial {
		key := mocknetOutpoint(utxo.Txid, utxo.Vout)
		if _, exists := provider.unspent[key]; exists {
			return nil, fmt.Errorf("duplicate mocknet outpoint %s", key)
		}
		provider.unspent[key] = utxo
		provider.outputs[key] = SourceOutput{Value: utxo.Value, ScriptPubKey: utxo.ScriptPubKey, Token: utxo.Token}
	}
	return provider, nil
}

func (p *MocknetProvider) Network() string { return p.network }

func (p *MocknetProvider) RegisterTransaction(transaction MocknetTransaction) error {
	if len(transaction.Txid) != 64 {
		return fmt.Errorf("mocknet txid must be 32-byte hexadecimal")
	}
	if _, err := hex.DecodeString(transaction.Txid); err != nil {
		return fmt.Errorf("mocknet txid must be hexadecimal: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.registered[hex.EncodeToString(transaction.RawTransaction)] = transaction
	return nil
}

func (p *MocknetProvider) ListUtxos(address string) ([]BchUtxo, error) {
	script, _, err := DecodeCashAddress(address, p.network)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]BchUtxo, 0)
	for _, utxo := range p.unspent {
		if strings.EqualFold(utxo.ScriptPubKey, hex.EncodeToString(script)) {
			result = append(result, utxo)
		}
	}
	return result, nil
}

func (p *MocknetProvider) GetSourceOutput(txid string, vout uint32) (SourceOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	output, ok := p.outputs[mocknetOutpoint(txid, vout)]
	if !ok {
		return SourceOutput{}, fmt.Errorf("mocknet source output was not found")
	}
	return output, nil
}

func (p *MocknetProvider) GetOutpointStatus(txid string, vout uint32) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := mocknetOutpoint(txid, vout)
	if _, ok := p.unspent[key]; ok {
		return "unspent", nil
	}
	if _, ok := p.outputs[key]; ok {
		return "spent", nil
	}
	return "unknown", nil
}

func (p *MocknetProvider) Broadcast(raw []byte) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	transaction, ok := p.registered[hex.EncodeToString(raw)]
	if !ok {
		return "", fmt.Errorf("mocknet transaction is not registered")
	}
	if status, exists := p.statuses[transaction.Txid]; exists && status.Kind != "conflicted" {
		return transaction.Txid, nil
	}
	for _, input := range transaction.Inputs {
		if _, exists := p.unspent[mocknetOutpoint(input.Txid, input.Vout)]; !exists {
			return "", fmt.Errorf("mocknet input is already spent")
		}
	}
	for _, input := range transaction.Inputs {
		delete(p.unspent, mocknetOutpoint(input.Txid, input.Vout))
	}
	for vout, output := range transaction.Outputs {
		outpoint := mocknetOutpoint(transaction.Txid, uint32(vout))
		p.outputs[outpoint] = output
		p.unspent[outpoint] = BchUtxo{Txid: transaction.Txid, Vout: uint32(vout), Value: output.Value, ScriptPubKey: output.ScriptPubKey, Token: output.Token}
	}
	p.transactions[transaction.Txid] = append([]byte(nil), raw...)
	p.statuses[transaction.Txid] = BchTransactionStatus{Kind: "mempool"}
	return transaction.Txid, nil
}

func (p *MocknetProvider) GetTransaction(txid string) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, ok := p.transactions[txid]
	return append([]byte(nil), raw...), ok, nil
}

func (p *MocknetProvider) GetTransactionStatus(txid string) (BchTransactionStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if status, ok := p.statuses[txid]; ok {
		return status, nil
	}
	return BchTransactionStatus{Kind: "notFound"}, nil
}

func (p *MocknetProvider) GetTipHeight() (uint64, error)            { return p.tipHeight, nil }
func (p *MocknetProvider) HasDoubleSpendProof(string) (bool, error) { return false, nil }

func (p *MocknetProvider) Confirm(txid string, height uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.transactions[txid]; !ok {
		return fmt.Errorf("mocknet transaction is not known")
	}
	p.statuses[txid] = BchTransactionStatus{Kind: "confirmed", Height: &height}
	for key, utxo := range p.unspent {
		if utxo.Txid == txid {
			utxo.Height = &height
			p.unspent[key] = utxo
		}
	}
	return nil
}

func mocknetOutpoint(txid string, vout uint32) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(txid), vout)
}
