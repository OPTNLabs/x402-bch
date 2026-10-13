package x402bch

import "testing"

func TestPortableHttpBoundary(t *testing.T) {
	response := CreateBchPaymentRequiredResponse("{\"x402Version\":2}")
	decoded, err := DecodeBchHttpHeader(response.Headers[BchPaymentRequiredHeader])
	if err != nil || response.Status != 402 || decoded != "{\"x402Version\":2}" {
		t.Fatalf("unexpected HTTP boundary: %+v, %v", response, err)
	}
}
