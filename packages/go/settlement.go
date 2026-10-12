package x402bch

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// AcceptsBchSettlement applies the pure BCH settlement policy to provider
// facts. A nil height is an unknown height, not an implicit confirmation.
func AcceptsBchSettlement(strategy string, status string, confirmations uint64, height *uint64, tipHeight *uint64, doubleSpendProof bool) bool {
	switch strategy {
	case "mempool":
		return status == "mempool" || status == "confirmed"
	case "noDoubleSpendProof":
		return status == "confirmed" || (status == "mempool" && !doubleSpendProof)
	case "confirmations":
		if confirmations < 1 || status != "confirmed" || height == nil || tipHeight == nil || *tipHeight < *height {
			return false
		}
		return *tipHeight-*height+1 >= confirmations
	default:
		return false
	}
}

// ProviderTransactionMatches verifies provider bytes against the candidate txid.
// A missing or malformed observation is not chain evidence.
func ProviderTransactionMatches(candidateTxid string, rawTransaction []byte) bool {
	if len(rawTransaction) == 0 || len(candidateTxid) != 64 {
		return false
	}
	if _, err := hex.DecodeString(candidateTxid); err != nil {
		return false
	}
	encoded := base64.StdEncoding.EncodeToString(rawTransaction)
	if _, err := ParseTransaction(encoded); err != nil {
		return false
	}
	return strings.EqualFold(transactionIDFromRaw(rawTransaction), candidateTxid)
}

// ResolveBchSettlementOutcome normalizes provider and policy facts for retries.
func ResolveBchSettlementOutcome(candidateValid bool, providerObservation string, strategy string, status string, confirmations uint64, height *uint64, tipHeight *uint64, doubleSpendProof bool) string {
	if !candidateValid || providerObservation == "mismatch" || (providerObservation != "missing" && providerObservation != "match") || status == "conflicted" {
		return "rejected"
	}
	if providerObservation == "missing" {
		return "pending"
	}
	if AcceptsBchSettlement(strategy, status, confirmations, height, tipHeight, doubleSpendProof) {
		return "accepted"
	}
	return "pending"
}

type BchSettlementIntegrationResult struct {
	State         string
	TransactionID string
	NextAction    string
}

// ObserveBchProviderTransaction derives chain evidence from provider bytes.
// A nil slice means the provider has not observed the transaction; a present
// but malformed or mismatched slice is explicit mismatch evidence.
func ObserveBchProviderTransaction(candidateTxid string, rawTransaction []byte) string {
	if rawTransaction == nil {
		return "missing"
	}
	if ProviderTransactionMatches(candidateTxid, rawTransaction) {
		return "match"
	}
	return "mismatch"
}

type BchProviderSourceOutputResult struct {
	Observation  string
	SourceOutput *SourceOutput
}

// GetBchProviderSourceOutput projects an authoritative source output only
// after the provider bytes match the requested transaction ID.
func GetBchProviderSourceOutput(sourceTxid string, vout uint32, rawTransaction []byte) BchProviderSourceOutputResult {
	observation := ObserveBchProviderTransaction(sourceTxid, rawTransaction)
	if observation == "missing" || observation == "mismatch" {
		return BchProviderSourceOutputResult{Observation: observation}
	}
	encoded := base64.StdEncoding.EncodeToString(rawTransaction)
	transaction, err := ParseTransaction(encoded)
	if err != nil || uint64(vout) >= uint64(len(transaction.Outputs)) {
		return BchProviderSourceOutputResult{Observation: "notFound"}
	}
	output := transaction.Outputs[vout]
	return BchProviderSourceOutputResult{
		Observation: "match",
		SourceOutput: &SourceOutput{
			Value:        strconv.FormatUint(output.Value, 10),
			ScriptPubKey: hex.EncodeToString(output.ScriptPubKey),
		},
	}
}

// ResolveBchSettlementIntegration models facilitator retries without
// broadcasting or persisting state. Retry always refers to the same txid.
func ResolveBchSettlementIntegration(candidateTxid string, candidateValid bool, bindingMatches bool, existingClaim string, providerObservation string, strategy string, status string, confirmations uint64, height *uint64, tipHeight *uint64, broadcastAttempt string) BchSettlementIntegrationResult {
	transactionID := ""
	if candidateValid {
		transactionID = candidateTxid
	}
	if !candidateValid || !bindingMatches || providerObservation == "mismatch" {
		return BchSettlementIntegrationResult{State: "rejected", TransactionID: transactionID, NextAction: "reject"}
	}
	if existingClaim == "different" {
		return BchSettlementIntegrationResult{State: "rejected", TransactionID: transactionID, NextAction: "conflict"}
	}
	state := ResolveBchSettlementOutcome(true, providerObservation, strategy, status, confirmations, height, tipHeight, false)
	if state != "pending" {
		action := "reject"
		if state == "accepted" {
			action = "skip"
		}
		return BchSettlementIntegrationResult{State: state, TransactionID: transactionID, NextAction: action}
	}
	if providerObservation == "missing" && existingClaim == "none" && broadcastAttempt == "none" {
		return BchSettlementIntegrationResult{State: state, TransactionID: transactionID, NextAction: "broadcast"}
	}
	if providerObservation == "missing" && broadcastAttempt == "lost" {
		return BchSettlementIntegrationResult{State: state, TransactionID: transactionID, NextAction: "retry"}
	}
	return BchSettlementIntegrationResult{State: state, TransactionID: transactionID, NextAction: "retain"}
}

// ResolveBchSettlementFromProvider derives the observation from provider
// bytes, then applies the common retry-safe settlement state machine.
func ResolveBchSettlementFromProvider(candidateTxid string, candidateValid bool, bindingMatches bool, existingClaim string, strategy string, status string, confirmations uint64, height *uint64, tipHeight *uint64, broadcastAttempt string, rawTransaction []byte) BchSettlementIntegrationResult {
	return ResolveBchSettlementIntegration(
		candidateTxid,
		candidateValid,
		bindingMatches,
		existingClaim,
		ObserveBchProviderTransaction(candidateTxid, rawTransaction),
		strategy,
		status,
		confirmations,
		height,
		tipHeight,
		broadcastAttempt,
	)
}
