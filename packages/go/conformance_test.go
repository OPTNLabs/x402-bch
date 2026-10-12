package x402bch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestPaymentRequirementsFixture(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "spec", "conformance", "v1", "payment-requirements.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int `json:"version"`
		Cases   []struct {
			Requirements struct {
				Version int    `json:"x402Version"`
				Scheme  string `json:"scheme"`
				Amount  string `json:"amount"`
				Extra   struct {
					RequestHash string `json:"requestHash"`
				} `json:"extra"`
			} `json:"requirements"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Cases) == 0 {
		t.Fatal("invalid fixture")
	}
	for _, c := range fixture.Cases {
		if c.Requirements.Version != 2 || c.Requirements.Scheme != "exact" || !regexp.MustCompile(`^\d+$`).MatchString(c.Requirements.Amount) {
			t.Fatal("requirements mismatch")
		}
		if c.Requirements.Extra.RequestHash != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.Requirements.Extra.RequestHash) {
			t.Fatal("request hash mismatch")
		}
	}
}
