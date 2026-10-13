package x402bch

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type sdkLifecycleFixture struct {
	Requirements Requirements `json:"requirements"`
	Wallet       struct {
		Network string `json:"network"`
		Value   string `json:"value"`
	} `json:"walletRequest"`
	Transaction struct {
		Base64 string `json:"base64"`
		Txid   string `json:"txid"`
	} `json:"transaction"`
}

type sdkTestWallet struct {
	request BchTransactionRequest
	raw     []byte
}

type sdkTestSigner struct{}

func (sdkTestSigner) PublicKey() []byte { return append([]byte{2}, bytes.Repeat([]byte{0x11}, 32)...) }
func (sdkTestSigner) SignDigest([]byte) ([]byte, error) {
	return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, nil
}
func (sdkTestSigner) Address(string) (string, error) {
	return "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf", nil
}

func (w *sdkTestWallet) CreatePayment(request BchTransactionRequest) ([]byte, error) {
	w.request = request
	return w.raw, nil
}

type sdkTestProvider struct {
	broadcasts int
	txid       string
	observed   []byte
}

type sdkTransport struct {
	result interface{}
	err    error
}

func (t sdkTransport) Request(string, []interface{}) (interface{}, error) { return t.result, t.err }

type fulcrumSdkTransport struct{ token bool }

func (t fulcrumSdkTransport) Request(method string, _ []interface{}) (interface{}, error) {
	switch method {
	case "blockchain.scripthash.listunspent":
		entry := map[string]interface{}{"tx_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "tx_pos": float64(0), "value": "5000", "height": float64(100)}
		if t.token {
			entry["tokenData"] = map[string]interface{}{"category": strings.Repeat("c", 64), "amount": "7"}
		}
		return []interface{}{entry}, nil
	case "blockchain.transaction.broadcast":
		return "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
	case "blockchain.transaction.get_height":
		return float64(100), nil
	case "blockchain.headers.subscribe":
		return map[string]interface{}{"height": float64(100)}, nil
	case "blockchain.transaction.dsproof.get":
		return nil, nil
	default:
		return nil, os.ErrNotExist
	}
}

func TestFailoverFulcrumTransport(t *testing.T) {
	transport, err := NewFailoverFulcrumTransport(
		sdkTransport{err: os.ErrNotExist}, sdkTransport{result: "ok"},
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.Request("server.version", nil)
	if err != nil || result != "ok" {
		t.Fatalf("failover result=%v err=%v", result, err)
	}
}

func TestBuildAndSignNativePayment(t *testing.T) {
	raw, err := BuildAndSignNativePayment(
		[]BchUtxo{{Txid: strings.Repeat("a", 64), Value: "5000", ScriptPubKey: "76a914111111111111111111111111111111111111111188ac"}},
		merchantScript(), 1000,
		sdkTestSigner{}, "mainnet", 1, 546)
	if err != nil || len(raw) == 0 {
		t.Fatalf("builder raw=%x err=%v", raw, err)
	}
}

func TestDeriveBchWalletAddressVectors(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	cases := []struct {
		network            string
		coin, change       uint32
		address, publicKey string
	}{
		{"bch:bchtest", 1, 0, "bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4", "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6"},
		{"bch:bchtest", 1, 1, "bchtest:qqwtwwfqkkkr3arquwx7k6ztn39yprlncq2gq6et74", "0320282ac6b3782721b1742c294530a9f250413361abbff659acc8352bc4c1f3f1"},
		{"bch:bitcoincash", 145, 0, "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6", "02bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217"},
		{"bch:bitcoincash", 145, 1, "bitcoincash:qr8aeharupyrmhfu0d4tdmsnc5y8cfk47y6qrsjsrx", "02f178b9410d11e47e10bef8a8e4bc53e48d9ae15864a024a54f87a802dad5f514"},
	}
	for _, tc := range cases {
		result, err := DeriveBchWalletAddress(mnemonic, tc.network, tc.change, 0, 0, "", &tc.coin)
		if err != nil || result.Address != tc.address || hex.EncodeToString(result.PublicKey) != tc.publicKey {
			t.Fatalf("HD vector mismatch: %+v err=%v", result, err)
		}
	}
}

func TestMnemonicSignerMatchesHdVector(t *testing.T) {
	signer, err := NewSecp256k1BchSignerFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "bch:bchtest", "", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	address, err := signer.Address("bch:bchtest")
	if err != nil || address != "bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4" {
		t.Fatalf("address=%s err=%v", address, err)
	}
	signature, err := signer.SignDigest(make([]byte, 32))
	if err != nil || len(signature) < 8 || signature[0] != 0x30 {
		t.Fatalf("signature=%x err=%v", signature, err)
	}
}

func TestRejectsInvalidBip39Checksum(t *testing.T) {
	_, err := DeriveBchWalletAddress("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo", "bch:bchtest", 0, 0, 0, "", nil)
	if err == nil {
		t.Fatal("expected invalid BIP39 checksum to be rejected")
	}
}

func merchantScript() []byte {
	value, err := hex.DecodeString("76a914333333333333333333333333333333333333333388ac")
	if err != nil {
		panic(err)
	}
	return value
}

func TestFulcrumProviderMapsTransportContract(t *testing.T) {
	provider, err := NewFulcrumProvider("bch:bitcoincash", fulcrumSdkTransport{})
	if err != nil {
		t.Fatal(err)
	}
	address := "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf"
	utxos, err := provider.ListUtxos(address)
	if err != nil || len(utxos) != 1 || utxos[0].Txid[0] != 'a' {
		t.Fatalf("utxos=%+v err=%v", utxos, err)
	}
	if txid, err := provider.Broadcast([]byte{0}); err != nil || len(txid) != 64 {
		t.Fatalf("broadcast txid=%s err=%v", txid, err)
	}
	status, err := provider.GetTransactionStatus(utxos[0].Txid)
	if err != nil || status.Kind != "confirmed" || status.Height == nil || *status.Height != 100 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func (p *sdkTestProvider) Network() string                     { return "bch:bitcoincash" }
func (p *sdkTestProvider) ListUtxos(string) ([]BchUtxo, error) { return nil, nil }
func (p *sdkTestProvider) GetSourceOutput(string, uint32) (SourceOutput, error) {
	return SourceOutput{Value: "100000"}, nil
}
func (p *sdkTestProvider) GetOutpointStatus(string, uint32) (string, error) { return "unspent", nil }
func (p *sdkTestProvider) Broadcast([]byte) (string, error)                 { p.broadcasts++; return p.txid, nil }
func (p *sdkTestProvider) GetTransaction(string) ([]byte, bool, error) {
	if len(p.observed) == 0 {
		return nil, false, nil
	}
	return p.observed, true, nil
}
func (p *sdkTestProvider) GetTransactionStatus(string) (BchTransactionStatus, error) {
	height := uint64(100)
	return BchTransactionStatus{Kind: "confirmed", Height: &height}, nil
}
func (p *sdkTestProvider) GetTipHeight() (uint64, error)            { return 100, nil }
func (p *sdkTestProvider) HasDoubleSpendProof(string) (bool, error) { return false, nil }

func TestSdkLifecycleFixture(t *testing.T) {
	rawFixture, err := os.ReadFile("spec/conformance/v1/sdk-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture sdkLifecycleFixture
	if err := json.Unmarshal(rawFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(fixture.Transaction.Base64)
	if err != nil {
		t.Fatal(err)
	}
	wallet := &sdkTestWallet{raw: raw}
	provider := &sdkTestProvider{txid: fixture.Transaction.Txid}
	payload, err := (ExactBchClient{Wallet: wallet, Provider: provider}).CreatePaymentPayload(fixture.Requirements)
	if err != nil {
		t.Fatal(err)
	}
	if wallet.request.Network != fixture.Wallet.Network || wallet.request.Value != fixture.Wallet.Value {
		t.Fatalf("wallet request mismatch: %+v", wallet.request)
	}
	result := (ExactBchFacilitator{Provider: provider}).Verify(payload, fixture.Requirements)
	if !result.IsValid {
		t.Fatalf("verification failed: %+v", result)
	}
	settled := (ExactBchFacilitator{Provider: provider}).Settle(payload, fixture.Requirements)
	if !settled.Success || provider.broadcasts != 1 {
		t.Fatalf("settlement failed: %+v broadcasts=%d", settled, provider.broadcasts)
	}
}

func TestSettlementStoreClaimLifecycle(t *testing.T) {
	store := NewInMemoryBchSettlementStore()
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	if claim, _ := store.Claim(first, "request-a"); claim != "acquired" {
		t.Fatalf("first claim=%s", claim)
	}
	if claim, _ := store.Claim(first, "request-a"); claim != "same" {
		t.Fatalf("same claim=%s", claim)
	}
	if claim, _ := store.Claim(first, "request-b"); claim != "conflict" {
		t.Fatalf("conflicting claim=%s", claim)
	}
	_ = store.Release(first)
	if claim, _ := store.Claim(first, "request-b"); claim != "acquired" {
		t.Fatalf("released claim=%s", claim)
	}
	if claim, _ := store.Claim(second, "request-a"); claim != "acquired" {
		t.Fatalf("second claim=%s", claim)
	}
	_ = store.MarkAccepted(second)
	_ = store.Release(second)
	if claim, _ := store.Claim(second, "request-b"); claim != "conflict" {
		t.Fatalf("accepted claim=%s", claim)
	}
}

func TestObservedRetryDoesNotBroadcastAgain(t *testing.T) {
	fixtureRaw, err := os.ReadFile("spec/conformance/v1/sdk-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture sdkLifecycleFixture
	if err := json.Unmarshal(fixtureRaw, &fixture); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(fixture.Transaction.Base64)
	if err != nil {
		t.Fatal(err)
	}
	provider := &sdkTestProvider{txid: fixture.Transaction.Txid, observed: raw}
	wallet := &sdkTestWallet{raw: raw}
	payload, err := (ExactBchClient{Wallet: wallet, Provider: provider}).CreatePaymentPayload(fixture.Requirements)
	if err != nil {
		t.Fatal(err)
	}
	settled := (ExactBchFacilitator{Provider: provider, SettlementStore: NewInMemoryBchSettlementStore()}).Settle(payload, fixture.Requirements)
	if !settled.Success || provider.broadcasts != 0 {
		t.Fatalf("observed retry settled=%+v broadcasts=%d", settled, provider.broadcasts)
	}
}

func TestNativeBuilderCommitsRequestHash(t *testing.T) {
	raw, err := BuildAndSignNativePayment(
		[]BchUtxo{{Txid: strings.Repeat("c", 64), Value: "100000", ScriptPubKey: "76a914111111111111111111111111111111111111111188ac"}},
		merchantScript(), 1000, sdkTestSigner{}, "mainnet", 1, 546, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := ParseTransaction(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertRequestHashCommitment(transaction, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestCashTokenBuilderAcceptsPureBchFeeInput(t *testing.T) {
	category := strings.Repeat("1", 64)
	selected := []BchUtxo{
		{Txid: strings.Repeat("d", 64), Value: "1258", ScriptPubKey: "76a914111111111111111111111111111111111111111188ac", Token: &CashToken{Category: category, Amount: 5}},
		{Txid: strings.Repeat("e", 64), Value: "10000", ScriptPubKey: "76a914111111111111111111111111111111111111111188ac"},
	}
	raw, err := BuildAndSignCashTokenPayment(selected, merchantScript(), 1000, 2, category, nil, sdkTestSigner{}, "mainnet", 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := ParseTransaction(base64.StdEncoding.EncodeToString(raw))
	if err != nil || len(transaction.Inputs) != 2 || transaction.Outputs[0].Token == nil || transaction.Outputs[0].Token.Amount != 2 {
		t.Fatalf("CashToken builder result inputs=%d output=%+v err=%v", len(transaction.Inputs), transaction.Outputs[0], err)
	}
}

func TestFulcrumProviderPreservesCashTokenUtxoState(t *testing.T) {
	provider, err := NewFulcrumProvider("bch:bitcoincash", fulcrumSdkTransport{token: true})
	if err != nil {
		t.Fatal(err)
	}
	address := "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf"
	utxos, err := provider.ListUtxos(address)
	if err != nil || len(utxos) != 1 || utxos[0].Token == nil || utxos[0].Token.Category != strings.Repeat("c", 64) || utxos[0].Token.Amount != 7 {
		t.Fatalf("token UTXO=%+v err=%v", utxos, err)
	}
}

type signerSdkProvider struct {
	*sdkTestProvider
	utxos []BchUtxo
}

func (p *signerSdkProvider) ListUtxos(string) ([]BchUtxo, error) { return p.utxos, nil }

func (p *signerSdkProvider) GetSourceOutput(txid string, vout uint32) (SourceOutput, error) {
	for _, utxo := range p.utxos {
		if utxo.Txid == txid && utxo.Vout == vout {
			return SourceOutput{Value: utxo.Value, ScriptPubKey: utxo.ScriptPubKey, Token: utxo.Token}, nil
		}
	}
	return SourceOutput{}, os.ErrNotExist
}

func TestSignerClientSelectsProviderUtxos(t *testing.T) {
	signer, err := NewSecp256k1BchSignerFromMnemonic(
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"bch:bitcoincash", "", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	payerScript := append([]byte{0x76, 0xa9, 0x14}, hash160(signer.PublicKey())...)
	payerScript = append(payerScript, 0x88, 0xac)
	requirements := Requirements{
		X402Version: 2, Scheme: "exact", Network: "bch:bitcoincash", Amount: "1000",
		Asset: "BCH", PayTo: "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue",
		MaxTimeoutSeconds: 300,
		Extra:             map[string]interface{}{"assetTransferMethod": "native", "paymentFlow": "upfront", "requestHash": strings.Repeat("a", 64)},
	}
	provider := &signerSdkProvider{
		sdkTestProvider: &sdkTestProvider{txid: strings.Repeat("f", 64)},
		utxos:           []BchUtxo{{Txid: strings.Repeat("c", 64), Vout: 0, Value: "100000", ScriptPubKey: hex.EncodeToString(payerScript)}},
	}
	payload, err := (ExactBchSignerClient{Signer: signer, Provider: provider}).CreatePaymentPayload(requirements)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := ParseTransaction(payload.Payload.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertRequestHashCommitment(transaction, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}
