// Package wallet exposes BCH wallet, signer, and HD discovery roles.
package wallet

import core "github.com/OPTNLabs/x402-bch/packages/go"

type BchWallet = core.BchWallet
type BchSigner = core.BchSigner
type BchWalletAddress = core.BchWalletAddress
type BchDiscoveredAddress = core.BchDiscoveredAddress
type Secp256k1BchSigner = core.Secp256k1BchSigner

var NewSecp256k1BchSignerFromMnemonic = core.NewSecp256k1BchSignerFromMnemonic
var DeriveBchWalletAddress = core.DeriveBchWalletAddress
var DiscoverBchHdWalletAddresses = core.DiscoverBchHdWalletAddresses
