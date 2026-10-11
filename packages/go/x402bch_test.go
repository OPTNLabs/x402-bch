package x402bch

import "testing"

func TestWireCore(t *testing.T) { r := Requirements{X402Version: 2, Scheme: "exact", Network: "bch:bchtest", Asset: "BCH", PayTo: "bchtest:merchant", Amount: "1000", Extra: map[string]interface{}{"paymentFlow": "upfront"}}; if err := ValidateRequirements(r); err != nil { t.Fatal(err) }; if RequestHash("{\"url\":\"https://example.test/resource\"}") != "1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675" { t.Fatal("request hash mismatch") } }

func TestPaymentPayloadBindsAndValidatesTransaction(t *testing.T) {
	r := Requirements{X402Version: 2, Scheme: "exact", Network: "bch:bchtest", Asset: "BCH", Amount: "1000", PayTo: "bchtest:merchant", Extra: map[string]interface{}{"paymentFlow": "upfront"}}
	p := PaymentPayload{X402Version: 2, Accepted: r}
	p.Payload.Transaction = "AQID"
	if err := ValidatePaymentPayload(p, r); err != nil { t.Fatal(err) }
	p.Payload.Transaction = "not base64"
	if err := ValidatePaymentPayload(p, r); err == nil { t.Fatal("expected invalid transaction") }
}
