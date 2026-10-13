// Package facilitator exposes provider-backed verification and settlement.
package facilitator

import core "github.com/OPTNLabs/x402-bch/packages/go"

type ExactBchFacilitator = core.ExactBchFacilitator
type VerifyResponse = core.VerifyResponse
type SettleResponse = core.SettleResponse
type BchSettlementStore = core.BchSettlementStore
type InMemoryBchSettlementStore = core.InMemoryBchSettlementStore

var NewInMemoryBchSettlementStore = core.NewInMemoryBchSettlementStore
