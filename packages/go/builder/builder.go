// Package builder exposes explicit-UTXO BCH payment builders.
package builder

import core "github.com/OPTNLabs/x402-bch/packages/go"

type BchUtxo = core.BchUtxo
type BchSigner = core.BchSigner

var BuildAndSignNativePayment = core.BuildAndSignNativePayment
var BuildAndSignCashTokenPayment = core.BuildAndSignCashTokenPayment
