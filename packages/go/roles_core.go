package x402bch

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

type BchSettlementStore interface {
	Claim(txid, binding string) (string, error)
	MarkAccepted(txid string) error
	Release(txid string) error
}

type InMemoryBchSettlementStore struct {
	mu      sync.Mutex
	records map[string]settlementRecord
}

type settlementRecord struct {
	binding  string
	accepted bool
}

func NewInMemoryBchSettlementStore() *InMemoryBchSettlementStore {
	return &InMemoryBchSettlementStore{records: make(map[string]settlementRecord)}
}

func (s *InMemoryBchSettlementStore) Claim(txid, binding string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[txid]
	if !ok {
		s.records[txid] = settlementRecord{binding: binding}
		return "acquired", nil
	}
	if record.binding == binding {
		return "same", nil
	}
	return "conflict", nil
}

func (s *InMemoryBchSettlementStore) MarkAccepted(txid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[txid]
	if ok {
		record.accepted = true
		s.records[txid] = record
	}
	return nil
}

func (s *InMemoryBchSettlementStore) Release(txid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.records[txid]; ok && !record.accepted {
		delete(s.records, txid)
	}
	return nil
}

// ToBchTransactionRequest converts a server offer into a wallet request.
func ToBchTransactionRequest(requirements Requirements) (BchTransactionRequest, error) {
	if err := ValidateRequirements(requirements); err != nil {
		return BchTransactionRequest{}, err
	}
	extra := requirements.Extra
	isToken, _ := extra["assetTransferMethod"].(string)
	request := BchTransactionRequest{
		Network:     map[string]string{"bch:bitcoincash": "mainnet", "bch:bchtest": "chipnet"}[requirements.Network],
		PayTo:       requirements.PayTo,
		Value:       requirements.Amount,
		Asset:       requirements.Asset,
		RequestHash: stringValue(extra["requestHash"]),
	}
	if isToken == "cashtoken" {
		request.Value = stringValueOr(extra["value"], "1000")
		request.TokenAmount = requirements.Amount
		if token, ok := extra["token"].(map[string]interface{}); ok {
			if nft, ok := token["nft"].(map[string]interface{}); ok {
				request.TokenNFT = &NftState{Capability: stringValue(nft["capability"]), Commitment: decodeHexString(stringValue(nft["commitment"]))}
			}
		}
	}
	return request, nil
}

// ExactBchClient turns one wallet-signed transaction into an x402 payload.
type ExactBchClient struct {
	Wallet   BchWallet
	Provider BchProvider
}

func (c ExactBchClient) CreatePaymentPayload(requirements Requirements) (PaymentPayload, error) {
	request, err := ToBchTransactionRequest(requirements)
	if err != nil {
		return PaymentPayload{}, err
	}
	raw, err := c.Wallet.CreatePayment(request)
	if err != nil || len(raw) == 0 {
		if err == nil {
			err = fmt.Errorf("wallet returned empty transaction")
		}
		return PaymentPayload{}, err
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	if _, err := ParseTransaction(encoded); err != nil {
		return PaymentPayload{}, err
	}
	if err := c.verifyWalletPayment(raw, requirements); err != nil {
		return PaymentPayload{}, err
	}
	var payload PaymentPayload
	payload.X402Version = 2
	payload.Payload.Transaction = encoded
	payload.Accepted = requirements
	return payload, nil
}

// verifyWalletPayment performs the same provider-backed validation as the
// facilitator, but without requiring the wallet inputs to remain unspent.
// A wallet adapter owns construction; x402 still verifies the returned
// transaction before handing it to the protocol.
func (c ExactBchClient) verifyWalletPayment(raw []byte, requirements Requirements) error {
	tx, err := ParseTransaction(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return err
	}
	merchantScript, _, err := DecodeCashAddress(requirements.PayTo, requirements.Network)
	if err != nil {
		return err
	}
	sources := make([]SourceOutput, 0, len(tx.Inputs))
	for _, input := range tx.Inputs {
		source, sourceErr := c.Provider.GetSourceOutput(input.Txid, input.Vout)
		if sourceErr != nil {
			return sourceErr
		}
		sources = append(sources, source)
	}
	if requestHash := stringValue(requirements.Extra["requestHash"]); requestHash != "" {
		if err := AssertRequestHashCommitment(tx, requestHash); err != nil {
			return err
		}
	}
	if stringValue(requirements.Extra["assetTransferMethod"]) == "cashtoken" {
		extraToken, _ := requirements.Extra["token"].(map[string]interface{})
		var nft *NftState
		if tokenNft, ok := extraToken["nft"].(map[string]interface{}); ok {
			nft = &NftState{Capability: stringValue(tokenNft["capability"]), Commitment: decodeHexString(stringValue(tokenNft["commitment"]))}
		}
		tokenSources := make([]CashTokenSource, 0, len(sources))
		for _, source := range sources {
			token := CashToken{Category: requirements.Asset}
			if source.Token != nil {
				token = *source.Token
			}
			tokenSources = append(tokenSources, CashTokenSource{Value: source.Value, Token: token})
		}
		_, err = VerifyCashTokenPaymentWithNFT(tx, tokenSources, stringValueOr(requirements.Extra["value"], "1000"), fmt.Sprintf("%x", merchantScript), requirements.Asset, requirements.Amount, nft, 1, 1000)
		return err
	}
	_, err = VerifyNativePayment(tx, sources, requirements.Amount, fmt.Sprintf("%x", merchantScript), 1, 546)
	return err
}

// ExactBchFacilitator exposes the provider-backed role without taking custody.
// The full transaction validator remains the same VerifyNativePayment or
// VerifyCashTokenPaymentWithNFT function used by the protocol core.
type ExactBchFacilitator struct {
	Provider        BchProvider
	SettlementStore BchSettlementStore
	Strategy        string
	Confirmations   uint64
}

type VerifyResponse struct {
	IsValid       bool
	Payer         string
	TransactionID string
	InvalidReason string
}

type SettleResponse struct {
	Success       bool
	TransactionID string
	ErrorReason   string
	Payer         string
}

func (f ExactBchFacilitator) Verify(payload PaymentPayload, requirements Requirements) VerifyResponse {
	verification, err := f.verifyPayment(payload, requirements, true)
	if err != nil {
		return VerifyResponse{InvalidReason: "invalid_exact_bch_payment:" + err.Error()}
	}
	return VerifyResponse{IsValid: true, TransactionID: verification.Txid}
}

func (f ExactBchFacilitator) Settle(payload PaymentPayload, requirements Requirements) SettleResponse {
	if err := ValidatePaymentPayload(payload, requirements); err != nil {
		return SettleResponse{ErrorReason: "invalid_exact_bch_payment:" + err.Error()}
	}
	txid, err := TransactionID(payload.Payload.Transaction)
	if err != nil {
		return SettleResponse{ErrorReason: "invalid_exact_bch_payment:" + err.Error()}
	}
	store := f.SettlementStore
	if store == nil {
		store = NewInMemoryBchSettlementStore()
	}
	// Provider-returned bytes are authoritative on retries. If the original
	// transaction is already observed, validate those bytes and do not attempt
	// a second broadcast merely because local settlement state is absent.
	if observed, found, observeErr := f.Provider.GetTransaction(txid); observeErr == nil && found && ProviderTransactionMatches(txid, observed) {
		observedPayload := payload
		observedPayload.Payload.Transaction = base64.StdEncoding.EncodeToString(observed)
		if _, verifyErr := f.verifyPayment(observedPayload, requirements, false); verifyErr == nil && f.accepted(txid) {
			_ = store.MarkAccepted(txid)
			return SettleResponse{Success: true, TransactionID: txid}
		}
	}
	bindingBytes, _ := json.Marshal(requirements)
	claim, err := store.Claim(txid, string(bindingBytes))
	if err != nil || claim == "conflict" {
		return SettleResponse{TransactionID: txid, ErrorReason: "transaction_already_claimed_for_another_request"}
	}
	if claim == "same" {
		if !f.accepted(txid) {
			return SettleResponse{TransactionID: txid, ErrorReason: "settlement_pending"}
		}
		return SettleResponse{Success: true, TransactionID: txid}
	}
	verification, err := f.verifyPayment(payload, requirements, true)
	if err != nil {
		_ = store.Release(txid)
		return SettleResponse{TransactionID: txid, ErrorReason: "invalid_exact_bch_payment:" + err.Error()}
	}
	raw, _ := base64.StdEncoding.DecodeString(payload.Payload.Transaction)
	broadcastTxid, broadcastErr := f.Provider.Broadcast(raw)
	if broadcastErr != nil {
		status, statusErr := f.Provider.GetTransactionStatus(txid)
		if statusErr == nil && status.Kind != "notFound" {
			return SettleResponse{TransactionID: txid, ErrorReason: "settlement_pending"}
		}
		_ = store.Release(txid)
		return SettleResponse{TransactionID: txid, ErrorReason: "broadcast_failed:" + broadcastErr.Error()}
	}
	if !strings.EqualFold(broadcastTxid, txid) {
		_ = store.Release(txid)
		return SettleResponse{TransactionID: broadcastTxid, ErrorReason: "broadcast_returned_mismatched_txid"}
	}
	if !f.accepted(txid) {
		return SettleResponse{TransactionID: txid, ErrorReason: "settlement_pending"}
	}
	_ = store.MarkAccepted(txid)
	return SettleResponse{Success: true, TransactionID: verification.Txid}
}

func (f ExactBchFacilitator) verifyPayment(payload PaymentPayload, requirements Requirements, requireUnspent bool) (PaymentVerification, error) {
	if err := ValidatePaymentPayload(payload, requirements); err != nil {
		return PaymentVerification{}, err
	}
	tx, err := ParseTransaction(payload.Payload.Transaction)
	if err != nil {
		return PaymentVerification{}, err
	}
	if requestHash := stringValue(requirements.Extra["requestHash"]); requestHash != "" {
		if err := AssertRequestHashCommitment(tx, requestHash); err != nil {
			return PaymentVerification{}, err
		}
	}
	merchantScript, _, err := DecodeCashAddress(requirements.PayTo, requirements.Network)
	if err != nil {
		return PaymentVerification{}, err
	}
	extra := requirements.Extra
	if stringValue(extra["assetTransferMethod"]) == "cashtoken" {
		sources := make([]CashTokenSource, 0, len(tx.Inputs))
		for _, input := range tx.Inputs {
			source, sourceErr := f.Provider.GetSourceOutput(input.Txid, input.Vout)
			if sourceErr != nil || (requireUnspent && !f.isUnspent(input.Txid, input.Vout)) {
				return PaymentVerification{}, fmt.Errorf("source output is not available")
			}
			if source.Token == nil {
				source.Token = &CashToken{Category: requirements.Asset}
			}
			sources = append(sources, CashTokenSource{Value: source.Value, Token: *source.Token})
		}
		var nft *NftState
		if token, ok := extra["token"].(map[string]interface{}); ok {
			if value, ok := token["nft"].(map[string]interface{}); ok {
				nft = &NftState{Capability: stringValue(value["capability"]), Commitment: decodeHexString(stringValue(value["commitment"]))}
			}
		}
		return VerifyCashTokenPaymentWithNFT(tx, sources, stringValueOr(extra["value"], "1000"), fmt.Sprintf("%x", merchantScript), requirements.Asset, requirements.Amount, nft, 1, 1000)
	}
	sources := make([]SourceOutput, 0, len(tx.Inputs))
	for _, input := range tx.Inputs {
		source, sourceErr := f.Provider.GetSourceOutput(input.Txid, input.Vout)
		if sourceErr != nil || (requireUnspent && !f.isUnspent(input.Txid, input.Vout)) {
			return PaymentVerification{}, fmt.Errorf("source output is not available")
		}
		sources = append(sources, source)
	}
	return VerifyNativePayment(tx, sources, requirements.Amount, fmt.Sprintf("%x", merchantScript), 1, 546)
}

func (f ExactBchFacilitator) isUnspent(txid string, vout uint32) bool {
	status, err := f.Provider.GetOutpointStatus(txid, vout)
	return err == nil && status == "unspent"
}

func (f ExactBchFacilitator) accepted(txid string) bool {
	status, err := f.Provider.GetTransactionStatus(txid)
	if err != nil {
		return false
	}
	strategy := f.Strategy
	if strategy == "" {
		strategy = "confirmations"
	}
	if strategy == "confirmations" {
		tip, tipErr := f.Provider.GetTipHeight()
		if tipErr != nil {
			return false
		}
		return AcceptsBchSettlement(strategy, status.Kind, f.ConfirmationsOrOne(), status.Height, &tip, false)
	}
	proof, _ := f.Provider.HasDoubleSpendProof(txid)
	return AcceptsBchSettlement(strategy, status.Kind, 0, nil, nil, proof)
}

func (f ExactBchFacilitator) ConfirmationsOrOne() uint64 {
	if f.Confirmations == 0 {
		return 1
	}
	return f.Confirmations
}

func stringValue(value interface{}) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func stringValueOr(value interface{}, fallback string) string {
	if text := stringValue(value); text != "" {
		return text
	}
	return fallback
}

func decodeHexString(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}
