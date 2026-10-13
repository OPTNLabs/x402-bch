package x402bch

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestServerRequirementsFixture(t *testing.T) {
	data, err := os.ReadFile("spec/conformance/v1/server-requirements.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version int `json:"version"`
		Cases   []struct {
			ID       string `json:"id"`
			Input    struct {
				Kind        string `json:"kind"`
				Network     string `json:"network"`
				PayTo       string `json:"payTo"`
				Amount      string `json:"amount"`
				Category    string `json:"category"`
				Value       string `json:"value"`
				RequestHash string `json:"requestHash"`
				Nft         *struct {
					Capability string `json:"capability"`
					Commitment string `json:"commitment"`
				} `json:"nft"`
			} `json:"input"`
			Expected Requirements `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil || fixture.Version != 1 {
		t.Fatal("invalid server requirements fixture")
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			var actual Requirements
			var err error
			if testCase.Input.Kind == "native" {
				actual, err = BuildNativeRequirements(testCase.Input.Network, testCase.Input.PayTo, testCase.Input.Amount, testCase.Input.RequestHash)
			} else {
				var nft *NftState
				if testCase.Input.Nft != nil {
					commitment, decodeErr := hex.DecodeString(testCase.Input.Nft.Commitment)
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					nft = &NftState{Capability: testCase.Input.Nft.Capability, Commitment: commitment}
				}
				actual, err = BuildCashTokenRequirements(testCase.Input.Network, testCase.Input.PayTo, testCase.Input.Category, testCase.Input.Amount, testCase.Input.Value, testCase.Input.RequestHash, nft)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, testCase.Expected) {
				t.Fatalf("server requirements mismatch: got %#v want %#v", actual, testCase.Expected)
			}
		})
	}
}
