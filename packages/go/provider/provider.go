// Package provider exposes caller-injected BCH provider and Fulcrum roles.
package provider

import core "github.com/OPTNLabs/x402-bch/packages/go"

type BchProvider = core.BchProvider
type BchUtxo = core.BchUtxo
type SourceOutput = core.SourceOutput
type BchTransactionStatus = core.BchTransactionStatus
type FulcrumTransport = core.FulcrumTransport
type FailoverFulcrumTransport = core.FailoverFulcrumTransport
type FulcrumProvider = core.FulcrumProvider
type FulcrumSocketTransport = core.FulcrumSocketTransport
type BchnRpc = core.BchnRpc
type BchnRpcTransport = core.BchnRpcTransport
type BchnMempoolResult = core.BchnMempoolResult

var NewFailoverFulcrumTransport = core.NewFailoverFulcrumTransport
var NewFulcrumProvider = core.NewFulcrumProvider
var NewFulcrumSocketTransport = core.NewFulcrumSocketTransport
var NewBchnRpcTransport = core.NewBchnRpcTransport
var TestMempoolAccept = core.TestMempoolAccept
