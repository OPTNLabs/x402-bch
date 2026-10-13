// Package transaction exposes BCH transaction and payment validation helpers.
package transaction

import core "github.com/OPTNLabs/x402-bch/packages/go"

type Transaction = core.Transaction
type TransactionInput = core.TransactionInput
type TransactionOutput = core.TransactionOutput
type CashToken = core.CashToken
type CashTokenSource = core.CashTokenSource
type SourceOutput = core.SourceOutput
type PaymentVerification = core.PaymentVerification

var ParseTransaction = core.ParseTransaction
var SerializeTransaction = core.SerializeTransaction
var TransactionID = core.TransactionID
var RequestHashScript = core.RequestHashScript
var VerifyNativePayment = core.VerifyNativePayment
var VerifyCashTokenPayment = core.VerifyCashTokenPayment
var VerifyCashTokenPaymentWithNFT = core.VerifyCashTokenPaymentWithNFT
