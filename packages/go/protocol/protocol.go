// Package protocol exposes the x402 wire and requirement boundary.
package protocol

import core "github.com/OPTNLabs/x402-bch/packages/go"

type Requirements = core.Requirements
type PaymentPayload = core.PaymentPayload

var ValidateRequirements = core.ValidateRequirements
var ValidatePaymentPayload = core.ValidatePaymentPayload
var RequestHash = core.RequestHash
var ValidateTransactionEnvelope = core.ValidateTransactionEnvelope
