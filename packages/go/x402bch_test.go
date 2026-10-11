package x402bch

import "testing"

func TestWireCore(t *testing.T) { r := Requirements{X402Version: 2, Scheme: "exact", Amount: "1000", Extra: map[string]interface{}{"paymentFlow": "upfront"}}; if err := ValidateRequirements(r); err != nil { t.Fatal(err) }; if _, err := RequestHash(map[string]string{"url": "https://example.test/resource"}); err != nil { t.Fatal(err) } }

func TestPaymentPayloadBindsAndValidatesTransaction(t *testing.T) {
	r := Requirements{X402Version: 2, Scheme: "exact", Network: "bch:bchtest", Amount: "1000", PayTo: "bchtest:merchant", Extra: map[string]interface{}{"paymentFlow": "upfront"}}
	p := PaymentPayload{X402Version: 2, Scheme: "exact", Network: r.Network, Accepted: r}
	p.Payload.Transaction = "AQID"
	if err := ValidatePaymentPayload(p, r); err != nil { t.Fatal(err) }
	p.Payload.Transaction = "not base64"
	if err := ValidatePaymentPayload(p, r); err == nil { t.Fatal("expected invalid transaction") }
}
