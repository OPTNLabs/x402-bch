package covenant

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRegisteredCovenantProfileFixture(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "spec", "conformance", "v1", "covenant-profiles.json"))
	if err != nil { t.Fatal(err) }
	var fixture struct {
		Profile Profile `json:"profile"`
		Cases []struct {
			Transition
			ID string `json:"id"`
			Expected string `json:"expected"`
			ErrorCode string `json:"errorCode"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil { t.Fatal(err) }
	if !ProfileHashesMatch(fixture.Profile) { t.Fatal("profile identity mismatch") }
	for _, testCase := range fixture.Cases {
		got := ValidateTransition(fixture.Profile, testCase.Transition)
		if testCase.Expected == "accept" && got != "" { t.Errorf("%s: got %s", testCase.ID, got) }
		if testCase.Expected == "reject" && got != testCase.ErrorCode { t.Errorf("%s: got %s, want %s", testCase.ID, got, testCase.ErrorCode) }
	}
}
