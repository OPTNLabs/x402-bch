// Package sdk exposes client, facilitator, and settlement-store roles.
package sdk

import core "github.com/OPTNLabs/x402-bch/packages/go"

type BchTransactionRequest = core.BchTransactionRequest
type ExactBchClient = core.ExactBchClient
type ExactBchSignerClient = core.ExactBchSignerClient
type ExactBchFacilitator = core.ExactBchFacilitator
type VerifyResponse = core.VerifyResponse
type SettleResponse = core.SettleResponse
type BchSettlementStore = core.BchSettlementStore
type InMemoryBchSettlementStore = core.InMemoryBchSettlementStore

var NewInMemoryBchSettlementStore = core.NewInMemoryBchSettlementStore
var ToBchTransactionRequest = core.ToBchTransactionRequest
