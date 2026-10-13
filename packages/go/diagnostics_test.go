package x402bch

import "testing"

func TestCreateBchDiagnosticRedactsSensitiveContext(t *testing.T) {
	diagnostic := CreateBchDiagnostic("provider", "transaction_identity_mismatch", "provider mismatch", map[string]string{
		"txid":           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"rawTransaction": "deadbeef",
	})
	if diagnostic.Context["rawTransaction"] != DiagnosticRedacted || diagnostic.Context["txid"] == DiagnosticRedacted {
		t.Fatalf("unexpected diagnostic: %+v", diagnostic)
	}
}
