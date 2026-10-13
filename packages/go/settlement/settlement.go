// Package settlement exposes deterministic provider-fact settlement decisions.
package settlement

import core "github.com/OPTNLabs/x402-bch/packages/go"

type BchSettlementIntegrationResult = core.BchSettlementIntegrationResult
type BchProviderSourceOutputResult = core.BchProviderSourceOutputResult

var AcceptsBchSettlement = core.AcceptsBchSettlement
var ProviderTransactionMatches = core.ProviderTransactionMatches
var ObserveBchProviderTransaction = core.ObserveBchProviderTransaction
var GetBchProviderSourceOutput = core.GetBchProviderSourceOutput
var ResolveBchSettlementOutcome = core.ResolveBchSettlementOutcome
var ResolveBchSettlementIntegration = core.ResolveBchSettlementIntegration
var ResolveBchSettlementFromProvider = core.ResolveBchSettlementFromProvider
