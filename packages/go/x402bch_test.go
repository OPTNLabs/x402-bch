package x402bch

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestWireCore(t *testing.T) {
	r := Requirements{X402Version: 2, Scheme: "exact", Network: "bch:bchtest", Asset: "BCH", PayTo: "bchtest:merchant", Amount: "1000", Extra: map[string]interface{}{"paymentFlow": "upfront"}}
	if err := ValidateRequirements(r); err != nil {
		t.Fatal(err)
	}
	if RequestHash("{\"url\":\"https://example.test/resource\"}") != "1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675" {
		t.Fatal("request hash mismatch")
	}
}

func TestPaymentPayloadBindsAndValidatesTransaction(t *testing.T) {
	r := Requirements{X402Version: 2, Scheme: "exact", Network: "bch:bchtest", Asset: "BCH", Amount: "1000", PayTo: "bchtest:merchant", Extra: map[string]interface{}{"paymentFlow": "upfront", "requestHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	p := PaymentPayload{X402Version: 2, Accepted: r}
	p.Payload.Transaction = "AQID"
	if err := ValidatePaymentPayload(p, r); err != nil {
		t.Fatal(err)
	}
	mismatched := p
	mismatched.Accepted.Extra = map[string]interface{}{"paymentFlow": "upfront", "requestHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if err := ValidatePaymentPayload(mismatched, r); err == nil {
		t.Fatal("mismatched request hash accepted")
	}
	p.Payload.Transaction = "not base64"
	if err := ValidatePaymentPayload(p, r); err == nil {
		t.Fatal("expected invalid transaction")
	}
}

func TestTransactionEnvelopeBoundary(t *testing.T) {
	valid := "AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiATJrlQh+1HHiXNlhiWdL97/QnR0aAE//NQGIuj0NB4AAIgO7sholeiC2XV4xGiBYgm8x/lzDrqhumDiMjzVjDE+oZBIQMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0Hj/////8C6AMAAAAAAAAZdqkUIiIiIiIiIiIiIiIiIiIiIiIiIiKIrNaBAQAAAAAAGXapFHmwAIh2JrKUqRRQGkzSJrWLI1mDiKwAAAAA"
	if err := ValidateTransactionEnvelope(valid); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTransactionEnvelope("AQID"); err == nil {
		t.Fatal("expected incomplete envelope rejection")
	}
}

func TestTransactionID(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/transaction.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RawTransaction       string `json:"rawTransaction"`
		Txid                 string `json:"txid"`
		SourceValue          string `json:"sourceValue"`
		SourceScriptPubKey   string `json:"sourceScriptPubKey"`
		MerchantValue        string `json:"merchantValue"`
		MerchantScriptPubKey string `json:"merchantScriptPubKey"`
		Fee                  string `json:"fee"`
		SerializedSize       int    `json:"serializedSize"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	txid, err := TransactionID(fixtureRawBase64(fixture.RawTransaction))
	if err != nil || txid != fixture.Txid {
		t.Fatalf("txid mismatch: %s %v", txid, err)
	}
	if _, err := TransactionID("AQID"); err != nil {
		t.Fatal(err)
	}
	tx, err := ParseTransaction(fixtureRawBase64(fixture.RawTransaction))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SerializeTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != fixture.RawTransaction {
		t.Fatal("transaction serialization mismatch")
	}
	verified, err := VerifyNativePayment(tx, []SourceOutput{{Value: fixture.SourceValue, ScriptPubKey: fixture.SourceScriptPubKey}}, fixture.MerchantValue, fixture.MerchantScriptPubKey, 1, 546)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Txid != fixture.Txid || verified.Fee != fixture.Fee || verified.SerializedSize != fmt.Sprintf("%d", fixture.SerializedSize) {
		t.Fatalf("payment verification mismatch: %+v", verified)
	}
	script, _ := hex.DecodeString("76a914111111111111111111111111111111111111111188ac")
	decoded, tokenSupport, err := DecodeCashAddress("bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue", "bch:bitcoincash")
	if err != nil || tokenSupport || hex.EncodeToString(decoded) != hex.EncodeToString(script) {
		t.Fatalf("CashAddr decode mismatch: %x %v %v", decoded, tokenSupport, err)
	}
	encoded, err := EncodeCashAddress(script, "bch:bitcoincash", false)
	if err != nil || encoded != "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue" {
		t.Fatalf("CashAddr encode mismatch: %s %v", encoded, err)
	}
	if _, _, err := DecodeCashAddress("bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue", "bch:bchtest"); err == nil {
		t.Fatal("cross-network CashAddr accepted")
	}
	addressData, err := os.ReadFile("spec/conformance/v1/addresses.json")
	if err != nil {
		t.Fatal(err)
	}
	var addresses struct {
		Version int `json:"version"`
		Cases   []struct {
			Network, Address, ScriptPubKey string
			TokenSupport                   bool `json:"tokenSupport"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(addressData, &addresses); err != nil || addresses.Version != 1 {
		t.Fatal("invalid address fixture")
	}
	for _, addressCase := range addresses.Cases {
		script, err := hex.DecodeString(addressCase.ScriptPubKey)
		if err != nil {
			t.Fatal(err)
		}
		decoded, token, err := DecodeCashAddress(addressCase.Address, addressCase.Network)
		if err != nil || token != addressCase.TokenSupport || hex.EncodeToString(decoded) != addressCase.ScriptPubKey {
			t.Fatalf("CashAddr fixture mismatch: %s %v", addressCase.Address, err)
		}
		encoded, err := EncodeCashAddress(script, addressCase.Network, addressCase.TokenSupport)
		if err != nil || encoded != addressCase.Address {
			t.Fatalf("CashAddr fixture encode mismatch: %s %v", addressCase.Address, err)
		}
	}
	tokenData, err := os.ReadFile("spec/conformance/v1/cashtoken.json")
	if err != nil {
		t.Fatal(err)
	}
	var tokenFixture struct {
		RawTransaction string `json:"rawTransaction"`
		Txid           string `json:"txid"`
		Asset          string `json:"asset"`
		Amount         string `json:"amount"`
		Value          string `json:"value"`
		SourceValue    string `json:"sourceValue"`
		SourceToken    struct {
			Category string `json:"category"`
			Amount   string `json:"amount"`
		} `json:"sourceToken"`
		SerializedSize int `json:"serializedSize"`
	}
	if err := json.Unmarshal(tokenData, &tokenFixture); err != nil {
		t.Fatal(err)
	}
	tokenTx, err := ParseTransaction(fixtureRawBase64(tokenFixture.RawTransaction))
	if err != nil {
		t.Fatal(err)
	}
	tokenRaw, err := SerializeTransaction(tokenTx)
	if err != nil || hex.EncodeToString(tokenRaw) != tokenFixture.RawTransaction {
		t.Fatalf("CashToken transaction round trip failed: %v", err)
	}
	if tokenTx.Outputs[0].Token == nil || tokenTx.Outputs[0].Token.Amount != 1000 || tokenTx.Outputs[1].Token == nil || tokenTx.Outputs[1].Token.Amount != 500 {
		t.Fatal("CashToken prefix parse mismatch")
	}
	verifiedToken, err := VerifyCashTokenPayment(tokenTx, []CashTokenSource{{Value: tokenFixture.SourceValue, Token: CashToken{Category: tokenFixture.SourceToken.Category, Amount: 1500}}}, tokenFixture.Value, "aa20222222222222222222222222222222222222222222222222222222222222222287", tokenFixture.Asset, tokenFixture.Amount, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedToken.Txid != tokenFixture.Txid || verifiedToken.Fee != "310" || verifiedToken.SerializedSize != fmt.Sprintf("%d", tokenFixture.SerializedSize) {
		t.Fatalf("CashToken verification mismatch: %+v", verifiedToken)
	}
	nftData, err := os.ReadFile("spec/conformance/v1/cashtoken-nft.json")
	if err != nil {
		t.Fatal(err)
	}
	var nftFixture struct {
		RawTransaction string `json:"rawTransaction"`
		Txid           string `json:"txid"`
		Asset          string `json:"asset"`
		Amount         string `json:"amount"`
		Value          string `json:"value"`
		SourceValue    string `json:"sourceValue"`
		SourceToken    struct {
			Category string `json:"category"`
			Amount   string `json:"amount"`
			NFT      struct {
				Capability string `json:"capability"`
				Commitment string `json:"commitment"`
			} `json:"nft"`
		} `json:"sourceToken"`
		Fee            string `json:"fee"`
		SerializedSize int    `json:"serializedSize"`
	}
	if err := json.Unmarshal(nftData, &nftFixture); err != nil {
		t.Fatal(err)
	}
	nftTx, err := ParseTransaction(fixtureRawBase64(nftFixture.RawTransaction))
	if err != nil {
		t.Fatal(err)
	}
	nftRaw, err := SerializeTransaction(nftTx)
	if err != nil || hex.EncodeToString(nftRaw) != nftFixture.RawTransaction {
		t.Fatalf("CashToken NFT transaction round trip failed: %v", err)
	}
	if nftTx.Outputs[0].Token == nil || nftTx.Outputs[0].Token.Nft == nil || hex.EncodeToString(nftTx.Outputs[0].Token.Nft.Commitment) != nftFixture.SourceToken.NFT.Commitment {
		t.Fatal("CashToken NFT prefix parse mismatch")
	}
	commitment, err := hex.DecodeString(nftFixture.SourceToken.NFT.Commitment)
	if err != nil {
		t.Fatal(err)
	}
	verifiedNft, err := VerifyCashTokenPaymentWithNFT(nftTx, []CashTokenSource{{Value: nftFixture.SourceValue, Token: CashToken{Category: nftFixture.SourceToken.Category, Amount: 0, Nft: &NftState{Capability: nftFixture.SourceToken.NFT.Capability, Commitment: commitment}}}}, nftFixture.Value, "76a914111111111111111111111111111111111111111188ac", nftFixture.Asset, nftFixture.Amount, &NftState{Capability: nftFixture.SourceToken.NFT.Capability, Commitment: commitment}, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedNft.Txid != nftFixture.Txid || verifiedNft.Fee != nftFixture.Fee || verifiedNft.SerializedSize != fmt.Sprintf("%d", nftFixture.SerializedSize) {
		t.Fatalf("CashToken NFT verification mismatch: %+v", verifiedNft)
	}
	capabilityData, err := os.ReadFile("spec/conformance/v1/cashtoken-capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var capabilityFixture struct {
		Cases []struct {
			Capability, Asset, Amount, Value, SourceValue, SourceScriptPubKey string
			RawTransaction, Txid, Fee                                         string
			SerializedSize                                                    int
			SourceToken                                                       struct {
				Category, Amount string
				NFT              struct{ Capability, Commitment string } `json:"nft"`
			} `json:"sourceToken"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(capabilityData, &capabilityFixture); err != nil {
		t.Fatal(err)
	}
	if len(capabilityFixture.Cases) != 2 {
		t.Fatal("invalid CashToken capability fixture")
	}
	for _, capabilityCase := range capabilityFixture.Cases {
		if capabilityCase.Capability != "mutable" && capabilityCase.Capability != "minting" {
			t.Fatalf("invalid capability: %s", capabilityCase.Capability)
		}
		capabilityTx, err := ParseTransaction(fixtureRawBase64(capabilityCase.RawTransaction))
		if err != nil {
			t.Fatal(err)
		}
		capabilityRaw, err := SerializeTransaction(capabilityTx)
		if err != nil || hex.EncodeToString(capabilityRaw) != capabilityCase.RawTransaction {
			t.Fatalf("CashToken capability transaction round trip failed: %v", err)
		}
		capabilityCommitment, err := hex.DecodeString(capabilityCase.SourceToken.NFT.Commitment)
		if err != nil {
			t.Fatal(err)
		}
		capabilityNft := &NftState{Capability: capabilityCase.Capability, Commitment: capabilityCommitment}
		verifiedCapability, err := VerifyCashTokenPaymentWithNFT(capabilityTx, []CashTokenSource{{Value: capabilityCase.SourceValue, Token: CashToken{Category: capabilityCase.SourceToken.Category, Amount: 0, Nft: capabilityNft}}}, capabilityCase.Value, "76a914111111111111111111111111111111111111111188ac", capabilityCase.Asset, capabilityCase.Amount, capabilityNft, 1, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if verifiedCapability.Txid != capabilityCase.Txid || verifiedCapability.Fee != capabilityCase.Fee || verifiedCapability.SerializedSize != fmt.Sprintf("%d", capabilityCase.SerializedSize) {
			t.Fatalf("CashToken capability verification mismatch: %+v", verifiedCapability)
		}
	}
}

func TestCashTokenNegativeFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/cashtoken-negative.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Kind, RawTransaction, ErrorCode                                 string
			SourceValue, MerchantValue, MerchantScriptPubKey, Asset, Amount string
			SourceToken                                                     struct{ Category, Amount string } `json:"sourceToken"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 4 {
		t.Fatal("invalid CashToken negative fixture")
	}
	for _, negativeCase := range fixture.Cases {
		tx, err := ParseTransaction(fixtureRawBase64(negativeCase.RawTransaction))
		if negativeCase.Kind == "parse" {
			if err == nil {
				t.Fatalf("negative parse fixture accepted: %s", negativeCase.ErrorCode)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyCashTokenPayment(tx, []CashTokenSource{{
			Value: negativeCase.SourceValue,
			Token: CashToken{Category: negativeCase.SourceToken.Category, Amount: 1499},
		}}, negativeCase.MerchantValue, negativeCase.MerchantScriptPubKey, negativeCase.Asset, negativeCase.Amount, 1, 1000)
		if err == nil {
			t.Fatalf("negative verification fixture accepted: %s", negativeCase.ErrorCode)
		}
	}
}

func TestP2PKHSignatureFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/p2pkh-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			InputIndex                                                                                    int `json:"inputIndex"`
			SourceValue, SourceScriptPubKey, RawTransaction, ExpectedSighash, ExpectedPayerHash, Expected string
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 2 {
		t.Fatal("invalid P2PKH signature fixture")
	}
	for _, signatureCase := range fixture.Cases {
		tx, err := ParseTransaction(fixtureRawBase64(signatureCase.RawTransaction))
		if err != nil {
			t.Fatal(err)
		}
		source := SourceOutput{Value: signatureCase.SourceValue, ScriptPubKey: signatureCase.SourceScriptPubKey}
		digest, err := SigningHash(tx, signatureCase.InputIndex, source)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(digest) != signatureCase.ExpectedSighash {
			t.Fatalf("signing hash mismatch: %s", signatureCase.Expected)
		}
		payerHash, err := VerifyP2PKHInput(tx, signatureCase.InputIndex, source)
		if signatureCase.Expected == "accept" {
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(payerHash) != signatureCase.ExpectedPayerHash {
				t.Fatalf("payer hash mismatch: %x", payerHash)
			}
		} else if err == nil {
			t.Fatalf("mutated signature accepted: %s", signatureCase.Expected)
		}
	}
}

func TestRequestHashFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/request-hash.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			RawTransaction, RequestHash, Expected string
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 3 {
		t.Fatal("invalid request-hash fixture")
	}
	for _, requestHashCase := range fixture.Cases {
		tx, err := ParseTransaction(fixtureRawBase64(requestHashCase.RawTransaction))
		if err != nil {
			t.Fatal(err)
		}
		err = AssertRequestHashCommitment(tx, requestHashCase.RequestHash)
		if requestHashCase.Expected == "accept" && err != nil {
			t.Fatal(err)
		}
		if requestHashCase.Expected == "reject" && err == nil {
			t.Fatalf("request-hash case accepted: %s", requestHashCase.RequestHash)
		}
	}
}

func TestP2SHCommitmentFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/p2sh-commitment.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			InputIndex                                                int `json:"inputIndex"`
			SourceValue, SourceScriptPubKey, RawTransaction, Expected string
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 4 {
		t.Fatal("invalid P2SH commitment fixture")
	}
	for _, p2shCase := range fixture.Cases {
		tx, err := ParseTransaction(fixtureRawBase64(p2shCase.RawTransaction))
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyP2SHRedeemScript(tx, p2shCase.InputIndex, SourceOutput{Value: p2shCase.SourceValue, ScriptPubKey: p2shCase.SourceScriptPubKey})
		if p2shCase.Expected == "accept" && err != nil {
			t.Fatal(err)
		}
		if p2shCase.Expected == "reject" && err == nil {
			t.Fatalf("P2SH case accepted: %s", p2shCase.SourceScriptPubKey)
		}
	}
}

func TestSettlementPolicyFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/settlement-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID               string  `json:"id"`
			Strategy         string  `json:"strategy"`
			Status           string  `json:"status"`
			Confirmations    uint64  `json:"confirmations"`
			Height           *uint64 `json:"height"`
			TipHeight        *uint64 `json:"tipHeight"`
			DoubleSpendProof bool    `json:"doubleSpendProof"`
			ExpectedAccepted bool    `json:"expectedAccepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 13 {
		t.Fatal("invalid settlement policy fixture")
	}
	for _, settlementCase := range fixture.Cases {
		accepted := AcceptsBchSettlement(
			settlementCase.Strategy,
			settlementCase.Status,
			settlementCase.Confirmations,
			settlementCase.Height,
			settlementCase.TipHeight,
			settlementCase.DoubleSpendProof,
		)
		if accepted != settlementCase.ExpectedAccepted {
			t.Fatalf("settlement policy mismatch: %s", settlementCase.ID)
		}
	}
}

func TestProviderObservationFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/provider-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			CandidateTxid  string  `json:"candidateTxid"`
			RawTransaction *string `json:"rawTransaction"`
			Expected       bool    `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 5 {
		t.Fatal("invalid provider observation fixture")
	}
	for _, observationCase := range fixture.Cases {
		var raw []byte
		if observationCase.RawTransaction != nil {
			raw, err = hex.DecodeString(*observationCase.RawTransaction)
			if err != nil {
				t.Fatal(err)
			}
		}
		if ProviderTransactionMatches(observationCase.CandidateTxid, raw) != observationCase.Expected {
			t.Fatalf("provider observation mismatch: %s", observationCase.CandidateTxid)
		}
	}
}

func TestSettlementOutcomeFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/settlement-outcome.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID                  string  `json:"id"`
			CandidateValid      bool    `json:"candidateValid"`
			ProviderObservation string  `json:"providerObservation"`
			Strategy            string  `json:"strategy"`
			Status              string  `json:"status"`
			Confirmations       uint64  `json:"confirmations"`
			Height              *uint64 `json:"height"`
			TipHeight           *uint64 `json:"tipHeight"`
			DoubleSpendProof    bool    `json:"doubleSpendProof"`
			ExpectedOutcome     string  `json:"expectedOutcome"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 8 {
		t.Fatal("invalid settlement outcome fixture")
	}
	for _, outcomeCase := range fixture.Cases {
		outcome := ResolveBchSettlementOutcome(
			outcomeCase.CandidateValid,
			outcomeCase.ProviderObservation,
			outcomeCase.Strategy,
			outcomeCase.Status,
			outcomeCase.Confirmations,
			outcomeCase.Height,
			outcomeCase.TipHeight,
			outcomeCase.DoubleSpendProof,
		)
		if outcome != outcomeCase.ExpectedOutcome {
			t.Fatalf("settlement outcome mismatch: %s", outcomeCase.ID)
		}
	}
}

func TestBchVmFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/bch-vm.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int    `json:"version"`
		Profile string `json:"profile"`
		Cases   []struct {
			ID               string  `json:"id"`
			UnlockingScript  string  `json:"unlockingScript"`
			LockingScript    string  `json:"lockingScript"`
			ExpectedAccepted bool    `json:"expectedAccepted"`
			ExpectedError    *string `json:"expectedError"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || fixture.Profile != "bch-bounded-v1" || len(fixture.Cases) != 12 {
		t.Fatal("invalid BCH VM fixture")
	}
	for _, testCase := range fixture.Cases {
		unlocking, err := hex.DecodeString(testCase.UnlockingScript)
		if err != nil {
			t.Fatal(err)
		}
		locking, err := hex.DecodeString(testCase.LockingScript)
		if err != nil {
			t.Fatal(err)
		}
		result := EvaluateBchVm(unlocking, locking)
		if result.Accepted != testCase.ExpectedAccepted {
			t.Fatalf("%s: accepted mismatch", testCase.ID)
		}
		expectedError := ""
		if testCase.ExpectedError != nil {
			expectedError = *testCase.ExpectedError
		}
		if result.ErrorCode != expectedError {
			t.Fatalf("%s: error mismatch: %s", testCase.ID, result.ErrorCode)
		}
	}
}

func TestSettlementIntegrationFixtures(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/settlement-integration.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID                  string  `json:"id"`
			CandidateTxid       string  `json:"candidateTxid"`
			CandidateValid      bool    `json:"candidateValid"`
			BindingMatches      bool    `json:"bindingMatches"`
			ExistingClaim       string  `json:"existingClaim"`
			ProviderObservation string  `json:"providerObservation"`
			Strategy            string  `json:"strategy"`
			Status              string  `json:"status"`
			Confirmations       uint64  `json:"confirmations"`
			Height              *uint64 `json:"height"`
			TipHeight           *uint64 `json:"tipHeight"`
			BroadcastAttempt    string  `json:"broadcastAttempt"`
			ExpectedState       string  `json:"expectedState"`
			ExpectedTransaction string  `json:"expectedTransactionId"`
			ExpectedAction      string  `json:"expectedAction"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 11 {
		t.Fatal("invalid settlement integration fixture")
	}
	for _, testCase := range fixture.Cases {
		result := ResolveBchSettlementIntegration(
			testCase.CandidateTxid,
			testCase.CandidateValid,
			testCase.BindingMatches,
			testCase.ExistingClaim,
			testCase.ProviderObservation,
			testCase.Strategy,
			testCase.Status,
			testCase.Confirmations,
			testCase.Height,
			testCase.TipHeight,
			testCase.BroadcastAttempt,
		)
		if result.State != testCase.ExpectedState || result.TransactionID != testCase.ExpectedTransaction || result.NextAction != testCase.ExpectedAction {
			t.Fatalf("%s: integration mismatch: %+v", testCase.ID, result)
		}
	}
}

func TestSettlementProviderFixtures(t *testing.T) {
	providerData, err := os.ReadFile("spec/conformance/v1/provider-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	var providerFixture struct {
		Cases []struct {
			ID             string  `json:"id"`
			RawTransaction *string `json:"rawTransaction"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(providerData, &providerFixture); err != nil {
		t.Fatal(err)
	}
	providers := make(map[string][]byte, len(providerFixture.Cases))
	for _, providerCase := range providerFixture.Cases {
		if providerCase.RawTransaction == nil {
			providers[providerCase.ID] = nil
			continue
		}
		raw, err := hex.DecodeString(*providerCase.RawTransaction)
		if err != nil {
			t.Fatal(err)
		}
		providers[providerCase.ID] = raw
	}
	data, err := os.ReadFile("spec/conformance/v1/settlement-provider.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID                  string  `json:"id"`
			ProviderCase        string  `json:"providerCase"`
			CandidateTxid       string  `json:"candidateTxid"`
			CandidateValid      bool    `json:"candidateValid"`
			BindingMatches      bool    `json:"bindingMatches"`
			ExistingClaim       string  `json:"existingClaim"`
			Strategy            string  `json:"strategy"`
			Status              string  `json:"status"`
			Confirmations       uint64  `json:"confirmations"`
			Height              *uint64 `json:"height"`
			TipHeight           *uint64 `json:"tipHeight"`
			BroadcastAttempt    string  `json:"broadcastAttempt"`
			ExpectedObservation string  `json:"expectedObservation"`
			ExpectedState       string  `json:"expectedState"`
			ExpectedTransaction string  `json:"expectedTransactionId"`
			ExpectedAction      string  `json:"expectedAction"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 7 {
		t.Fatal("invalid settlement provider fixture")
	}
	for _, testCase := range fixture.Cases {
		raw, ok := providers[testCase.ProviderCase]
		if !ok {
			t.Fatalf("%s: missing provider case", testCase.ID)
		}
		if ObserveBchProviderTransaction(testCase.CandidateTxid, raw) != testCase.ExpectedObservation {
			t.Fatalf("%s: provider observation mismatch", testCase.ID)
		}
		result := ResolveBchSettlementFromProvider(
			testCase.CandidateTxid,
			testCase.CandidateValid,
			testCase.BindingMatches,
			testCase.ExistingClaim,
			testCase.Strategy,
			testCase.Status,
			testCase.Confirmations,
			testCase.Height,
			testCase.TipHeight,
			testCase.BroadcastAttempt,
			raw,
		)
		if result.State != testCase.ExpectedState || result.TransactionID != testCase.ExpectedTransaction || result.NextAction != testCase.ExpectedAction {
			t.Fatalf("%s: provider settlement mismatch: %+v", testCase.ID, result)
		}
	}
}

func TestProviderSourceOutputFixtures(t *testing.T) {
	providerData, err := os.ReadFile("spec/conformance/v1/provider-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	var providerFixture struct {
		Cases []struct {
			ID             string  `json:"id"`
			RawTransaction *string `json:"rawTransaction"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(providerData, &providerFixture); err != nil {
		t.Fatal(err)
	}
	providers := make(map[string][]byte, len(providerFixture.Cases))
	for _, providerCase := range providerFixture.Cases {
		if providerCase.RawTransaction == nil {
			providers[providerCase.ID] = nil
			continue
		}
		raw, err := hex.DecodeString(*providerCase.RawTransaction)
		if err != nil {
			t.Fatal(err)
		}
		providers[providerCase.ID] = raw
	}
	data, err := os.ReadFile("spec/conformance/v1/provider-source-output.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID                  string  `json:"id"`
			ProviderCase        string  `json:"providerCase"`
			SourceTxid          string  `json:"sourceTxid"`
			Vout                uint32  `json:"vout"`
			ExpectedObservation string  `json:"expectedObservation"`
			ExpectedValue       *string `json:"expectedValue"`
			ExpectedScript      *string `json:"expectedScriptPubKey"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 6 {
		t.Fatal("invalid provider source-output fixture")
	}
	for _, testCase := range fixture.Cases {
		raw, ok := providers[testCase.ProviderCase]
		if !ok {
			t.Fatalf("%s: missing provider case", testCase.ID)
		}
		result := GetBchProviderSourceOutput(testCase.SourceTxid, testCase.Vout, raw)
		if result.Observation != testCase.ExpectedObservation {
			t.Fatalf("%s: observation mismatch: %+v", testCase.ID, result)
		}
		if testCase.ExpectedValue == nil || testCase.ExpectedScript == nil {
			if result.SourceOutput != nil {
				t.Fatalf("%s: unexpected source output", testCase.ID)
			}
			continue
		}
		if result.SourceOutput == nil || result.SourceOutput.Value != *testCase.ExpectedValue || result.SourceOutput.ScriptPubKey != *testCase.ExpectedScript {
			t.Fatalf("%s: source output mismatch: %+v", testCase.ID, result.SourceOutput)
		}
	}
}

func fixtureRawBase64(hexValue string) string {
	// The checked-in fixture is hex; use the standard library's decoder at test time.
	raw, err := hex.DecodeString(hexValue)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
