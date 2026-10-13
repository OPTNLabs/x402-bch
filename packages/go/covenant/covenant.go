package covenant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
)

type Profile struct {
	ID                   string `json:"id"`
	Family               string `json:"family"`
	ProfileVersion       uint64 `json:"profileVersion"`
	Network              string `json:"network"`
	ConstructorParameters map[string]string `json:"constructorParameters"`
	SuccessorPolicy      SuccessorPolicy `json:"successorPolicy"`
	DescriptorHash       string `json:"descriptorHash"`
	LockingBytecodeHash  string `json:"lockingBytecodeHash"`
	SuccessorPolicyHash  string `json:"successorPolicyHash"`
}

type SuccessorPolicy struct {
	LockingBytecode string `json:"lockingBytecode"`
	MaxFee          string `json:"maxFee"`
	OutputIndex     uint32 `json:"outputIndex"`
	StateTransition string `json:"stateTransition"`
	Token           string `json:"token"`
	Value           string `json:"value"`
}

type TokenState struct {
	Category string    `json:"category"`
	Amount   string    `json:"amount"`
	Nft      *NftState `json:"nft"`
}

type NftState struct {
	Capability string `json:"capability"`
	Commitment string `json:"commitment"`
}

type State struct {
	LockingBytecode string      `json:"lockingBytecode"`
	Value           string      `json:"value"`
	Epoch           string      `json:"epoch"`
	RequestHash     string      `json:"requestHash"`
	Token           *TokenState `json:"token"`
}

type Transition struct {
	RequestHash          string `json:"requestHash"`
	SuccessorOutputIndex uint32 `json:"successorOutputIndex"`
	Fee                  string `json:"fee"`
	Source               State  `json:"source"`
	Successor            State  `json:"successor"`
}

const (
	ProfileIdentityMismatch       = "profile-identity-mismatch"
	LockingBytecodeMismatch       = "locking-bytecode-mismatch"
	SuccessorOutputIndexMismatch  = "successor-output-index-mismatch"
	RequestHashMismatch           = "request-hash-mismatch"
	StateTransitionInvalid        = "state-transition-invalid"
	FeeExceedsLimit               = "fee-exceeds-limit"
	TokenStateMismatch             = "token-state-mismatch"
)

func ValidateTransition(profile Profile, transition Transition) string {
	if !ProfileHashesMatch(profile) {
		return ProfileIdentityMismatch
	}
	if transition.Source.LockingBytecode != profile.SuccessorPolicy.LockingBytecode || transition.Successor.LockingBytecode != profile.SuccessorPolicy.LockingBytecode {
		return LockingBytecodeMismatch
	}
	if transition.SuccessorOutputIndex != profile.SuccessorPolicy.OutputIndex {
		return SuccessorOutputIndexMismatch
	}
	if transition.RequestHash != transition.Source.RequestHash || transition.RequestHash != transition.Successor.RequestHash {
		return RequestHashMismatch
	}
	sourceEpoch := uintValue(transition.Source.Epoch)
	successorEpoch := uintValue(transition.Successor.Epoch)
	if profile.SuccessorPolicy.StateTransition == "epoch-plus-one" && successorEpoch.Cmp(new(big.Int).Add(sourceEpoch, big.NewInt(1))) != 0 {
		return StateTransitionInvalid
	}
	fee := uintValue(transition.Fee)
	if fee.Cmp(uintValue(profile.SuccessorPolicy.MaxFee)) > 0 {
		return FeeExceedsLimit
	}
	if profile.SuccessorPolicy.Value == "preserve-minus-fee" {
		expected := new(big.Int).Sub(uintValue(transition.Source.Value), uintValue(transition.Successor.Value))
		if expected.Cmp(fee) != 0 {
			return StateTransitionInvalid
		}
	}
	if profile.SuccessorPolicy.Token == "preserve" && !bytes.Equal(canonicalValue(transition.Source.Token), canonicalValue(transition.Successor.Token)) {
		return TokenStateMismatch
	}
	return ""
}

func ProfileHashesMatch(profile Profile) bool {
	descriptor := map[string]interface{}{
		"id": profile.ID, "family": profile.Family, "profileVersion": profile.ProfileVersion,
		"network": profile.Network, "constructorParameters": profile.ConstructorParameters,
		"successorPolicy": profile.SuccessorPolicy,
	}
	locking, err := hex.DecodeString(profile.SuccessorPolicy.LockingBytecode)
	if err != nil {
		return false
	}
	return sha256Hex(canonicalValue(descriptor)) == profile.DescriptorHash &&
		sha256Hex(locking) == profile.LockingBytecodeHash &&
		sha256Hex(canonicalValue(profile.SuccessorPolicy)) == profile.SuccessorPolicyHash
}

func uintValue(value string) *big.Int {
	result, ok := new(big.Int).SetString(value, 10)
	if !ok || result.Sign() < 0 {
		return new(big.Int).SetUint64(^uint64(0))
	}
	return result
}

func canonicalValue(value interface{}) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return encoded
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
