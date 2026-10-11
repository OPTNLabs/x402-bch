package x402bch

import "testing"

func TestWireCore(t *testing.T) { r := Requirements{X402Version: 2, Scheme: "exact", Amount: "1000", Extra: map[string]interface{}{"paymentFlow": "upfront"}}; if err := ValidateRequirements(r); err != nil { t.Fatal(err) }; if _, err := RequestHash(map[string]string{"url": "https://example.test/resource"}); err != nil { t.Fatal(err) } }
