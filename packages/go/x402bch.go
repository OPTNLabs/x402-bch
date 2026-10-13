package x402bch

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

type transactionReader struct {
	data   []byte
	offset int
}

func (r *transactionReader) read(length int) ([]byte, error) {
	if length < 0 || r.offset+length > len(r.data) {
		return nil, fmt.Errorf("transaction ended while reading bytes")
	}
	value := r.data[r.offset : r.offset+length]
	r.offset += length
	return value, nil
}

func readCompactSize(r *transactionReader) (uint64, error) {
	first, err := r.read(1)
	if err != nil {
		return 0, err
	}
	switch first[0] {
	case 0xfd:
		value, err := r.read(2)
		if err != nil {
			return 0, err
		}
		parsed := uint64(binary.LittleEndian.Uint16(value))
		if parsed < 253 {
			return 0, fmt.Errorf("non-canonical compact size")
		}
		return parsed, nil
	case 0xfe:
		value, err := r.read(4)
		if err != nil {
			return 0, err
		}
		parsed := uint64(binary.LittleEndian.Uint32(value))
		if parsed < 65536 {
			return 0, fmt.Errorf("non-canonical compact size")
		}
		return parsed, nil
	case 0xff:
		value, err := r.read(8)
		if err != nil {
			return 0, err
		}
		parsed := binary.LittleEndian.Uint64(value)
		if parsed < 4294967296 {
			return 0, fmt.Errorf("non-canonical compact size")
		}
		return parsed, nil
	default:
		return uint64(first[0]), nil
	}
}

func writeCompactSize(value uint64) ([]byte, error) {
	if value < 253 {
		return []byte{byte(value)}, nil
	}
	if value <= 0xffff {
		result := []byte{0xfd, 0, 0}
		binary.LittleEndian.PutUint16(result[1:], uint16(value))
		return result, nil
	}
	if value <= 0xffffffff {
		result := make([]byte, 5)
		result[0] = 0xfe
		binary.LittleEndian.PutUint32(result[1:], uint32(value))
		return result, nil
	}
	result := make([]byte, 9)
	result[0] = 0xff
	binary.LittleEndian.PutUint64(result[1:], value)
	return result, nil
}

func parseTokenPrefix(field []byte) (*CashToken, []byte, error) {
	if len(field) == 0 || field[0] != 0xef {
		return nil, field, nil
	}
	if len(field) < 34 {
		return nil, nil, fmt.Errorf("CashToken prefix is too short")
	}
	category := append([]byte(nil), field[1:33]...)
	reverseBytes(category)
	bitfield := field[33]
	structure := bitfield & 0xf0
	capability := bitfield & 0x0f
	if structure&0x80 != 0 {
		return nil, nil, fmt.Errorf("CashToken prefix has a reserved bit")
	}
	if capability > 2 {
		return nil, nil, fmt.Errorf("CashToken NFT capability is invalid")
	}
	hasNft, hasCommitment, hasAmount := structure&0x20 != 0, structure&0x40 != 0, structure&0x10 != 0
	if hasCommitment && !hasNft {
		return nil, nil, fmt.Errorf("CashToken commitment requires an NFT")
	}
	if capability != 0 && !hasNft {
		return nil, nil, fmt.Errorf("CashToken capability requires an NFT")
	}
	offset := 34
	commitment := []byte(nil)
	if hasNft && hasCommitment {
		reader := &transactionReader{data: field, offset: offset}
		length, err := readCompactSize(reader)
		if err != nil || length == 0 || length > 40 {
			return nil, nil, fmt.Errorf("CashToken NFT commitment length is invalid")
		}
		offset = reader.offset
		commitment, err = reader.read(int(length))
		if err != nil {
			return nil, nil, err
		}
		offset = reader.offset
	}
	amount := uint64(0)
	if hasAmount {
		reader := &transactionReader{data: field, offset: offset}
		value, err := readCompactSize(reader)
		if err != nil || value == 0 || value > ^uint64(0)>>1 {
			return nil, nil, fmt.Errorf("CashToken amount is outside the supported range")
		}
		amount, offset = value, reader.offset
	}
	if !hasNft && !hasAmount {
		return nil, nil, fmt.Errorf("CashToken prefix does not encode a token")
	}
	capabilities := [...]string{"none", "mutable", "minting"}
	return &CashToken{Category: hex.EncodeToString(category), Amount: amount, Nft: func() *NftState {
		if !hasNft {
			return nil
		}
		return &NftState{Capability: capabilities[capability], Commitment: commitment}
	}()}, field[offset:], nil
}

func encodeTokenPrefix(token *CashToken) ([]byte, error) {
	if token == nil || (token.Nft == nil && token.Amount == 0) {
		return nil, nil
	}
	category, err := hex.DecodeString(token.Category)
	if err != nil || len(category) != 32 {
		return nil, fmt.Errorf("CashToken category must be 32-byte hexadecimal")
	}
	reverseBytes(category)
	if token.Amount > ^uint64(0)>>1 {
		return nil, fmt.Errorf("CashToken amount is outside the supported range")
	}
	prefix := []byte{0xef}
	prefix = append(prefix, category...)
	bitfield := byte(0)
	if token.Nft != nil {
		capabilities := map[string]byte{"none": 0, "mutable": 1, "minting": 2}
		capability, ok := capabilities[token.Nft.Capability]
		if !ok {
			return nil, fmt.Errorf("CashToken NFT capability is invalid")
		}
		bitfield |= 0x20 | capability
		if len(token.Nft.Commitment) > 40 {
			return nil, fmt.Errorf("CashToken NFT commitment is too large")
		}
		if len(token.Nft.Commitment) > 0 {
			bitfield |= 0x40
		}
	}
	if token.Amount > 0 {
		bitfield |= 0x10
	}
	prefix = append(prefix, bitfield)
	if token.Nft != nil && len(token.Nft.Commitment) > 0 {
		length, _ := writeCompactSize(uint64(len(token.Nft.Commitment)))
		prefix = append(prefix, length...)
		prefix = append(prefix, token.Nft.Commitment...)
	}
	if token.Amount > 0 {
		amount, _ := writeCompactSize(token.Amount)
		prefix = append(prefix, amount...)
	}
	return prefix, nil
}

func ParseTransaction(encoded string) (Transaction, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return Transaction{}, fmt.Errorf("transaction must be non-empty base64")
	}
	r := &transactionReader{data: raw}
	versionBytes, err := r.read(4)
	if err != nil {
		return Transaction{}, err
	}
	tx := Transaction{Version: int32(binary.LittleEndian.Uint32(versionBytes))}
	if tx.Version != 1 && tx.Version != 2 {
		return Transaction{}, fmt.Errorf("unsupported transaction version")
	}
	inputCount, err := readCompactSize(r)
	if err != nil || inputCount == 0 || inputCount > 100 {
		return Transaction{}, fmt.Errorf("invalid transaction input count")
	}
	tx.Inputs = make([]TransactionInput, 0, inputCount)
	for i := uint64(0); i < inputCount; i++ {
		hash, err := r.read(32)
		if err != nil {
			return Transaction{}, err
		}
		reversed := append([]byte(nil), hash...)
		reverseBytes(reversed)
		index, err := r.read(4)
		if err != nil {
			return Transaction{}, err
		}
		scriptLength, err := readCompactSize(r)
		if err != nil || scriptLength > uint64(len(raw)-r.offset) {
			return Transaction{}, fmt.Errorf("transaction ended while reading unlocking script")
		}
		script, err := r.read(int(scriptLength))
		if err != nil {
			return Transaction{}, err
		}
		sequence, err := r.read(4)
		if err != nil {
			return Transaction{}, err
		}
		tx.Inputs = append(tx.Inputs, TransactionInput{Txid: hex.EncodeToString(reversed), Vout: binary.LittleEndian.Uint32(index), ScriptSig: append([]byte(nil), script...), Sequence: binary.LittleEndian.Uint32(sequence)})
	}
	outputCount, err := readCompactSize(r)
	if err != nil || outputCount == 0 || outputCount > 16 {
		return Transaction{}, fmt.Errorf("invalid transaction output count")
	}
	tx.Outputs = make([]TransactionOutput, 0, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		value, err := r.read(8)
		if err != nil {
			return Transaction{}, err
		}
		scriptLength, err := readCompactSize(r)
		if err != nil || scriptLength > uint64(len(raw)-r.offset) {
			return Transaction{}, fmt.Errorf("transaction ended while reading locking script")
		}
		field, err := r.read(int(scriptLength))
		if err != nil {
			return Transaction{}, err
		}
		token, script, err := parseTokenPrefix(field)
		if err != nil {
			return Transaction{}, err
		}
		tx.Outputs = append(tx.Outputs, TransactionOutput{Value: binary.LittleEndian.Uint64(value), ScriptPubKey: append([]byte(nil), script...), Token: token})
	}
	locktime, err := r.read(4)
	if err != nil {
		return Transaction{}, err
	}
	if r.offset != len(raw) {
		return Transaction{}, fmt.Errorf("trailing transaction bytes")
	}
	tx.Locktime = binary.LittleEndian.Uint32(locktime)
	return tx, nil
}

func SerializeTransaction(tx Transaction) ([]byte, error) {
	if len(tx.Inputs) == 0 || len(tx.Inputs) > 100 {
		return nil, fmt.Errorf("invalid transaction input count")
	}
	if len(tx.Outputs) == 0 || len(tx.Outputs) > 16 {
		return nil, fmt.Errorf("invalid transaction output count")
	}
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(tx.Version))
	count, _ := writeCompactSize(uint64(len(tx.Inputs)))
	result = append(result, count...)
	for _, input := range tx.Inputs {
		hash, err := hex.DecodeString(input.Txid)
		if err != nil || len(hash) != 32 {
			return nil, fmt.Errorf("input txid must be 32-byte hexadecimal")
		}
		reverseBytes(hash)
		result = append(result, hash...)
		index := make([]byte, 4)
		binary.LittleEndian.PutUint32(index, input.Vout)
		result = append(result, index...)
		scriptCount, _ := writeCompactSize(uint64(len(input.ScriptSig)))
		result = append(result, scriptCount...)
		result = append(result, input.ScriptSig...)
		sequence := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequence, input.Sequence)
		result = append(result, sequence...)
	}
	count, _ = writeCompactSize(uint64(len(tx.Outputs)))
	result = append(result, count...)
	for _, output := range tx.Outputs {
		value := make([]byte, 8)
		binary.LittleEndian.PutUint64(value, output.Value)
		result = append(result, value...)
		prefix, err := encodeTokenPrefix(output.Token)
		if err != nil {
			return nil, err
		}
		field := append(prefix, output.ScriptPubKey...)
		scriptCount, _ := writeCompactSize(uint64(len(field)))
		result = append(result, scriptCount...)
		result = append(result, field...)
	}
	locktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktime, tx.Locktime)
	result = append(result, locktime...)
	return result, nil
}

func VerifyNativePayment(tx Transaction, sources []SourceOutput, merchantValue, merchantScriptPubKey string, feeRate, dustThreshold uint64) (PaymentVerification, error) {
	if len(sources) != len(tx.Inputs) {
		return PaymentVerification{}, fmt.Errorf("source output count mismatch")
	}
	if tx.Locktime != 0 {
		return PaymentVerification{}, fmt.Errorf("non-zero locktime is unsupported")
	}
	merchantAmount, err := canonicalUint(merchantValue)
	if err != nil {
		return PaymentVerification{}, fmt.Errorf("merchant value: %w", err)
	}
	merchantScript, err := hex.DecodeString(merchantScriptPubKey)
	if err != nil {
		return PaymentVerification{}, fmt.Errorf("merchant script: %w", err)
	}
	var inputValue uint64
	for _, source := range sources {
		value, err := canonicalUint(source.Value)
		if err != nil {
			return PaymentVerification{}, err
		}
		if ^uint64(0)-inputValue < value {
			return PaymentVerification{}, fmt.Errorf("input value exceeds u64")
		}
		inputValue += value
	}
	merchantMatches := 0
	for _, output := range tx.Outputs {
		if output.Value == merchantAmount && bytes.Equal(output.ScriptPubKey, merchantScript) {
			merchantMatches++
		}
	}
	if merchantMatches != 1 {
		return PaymentVerification{}, fmt.Errorf("merchant output must match exactly once")
	}
	var outputValue uint64
	for _, output := range tx.Outputs {
		if output.Token != nil {
			return PaymentVerification{}, fmt.Errorf("native BCH payment contains CashTokens")
		}
		if len(output.ScriptPubKey) == 0 || output.ScriptPubKey[0] != 0x6a {
			if output.Value < dustThreshold {
				return PaymentVerification{}, fmt.Errorf("transaction output is dust")
			}
		}
		if ^uint64(0)-outputValue < output.Value {
			return PaymentVerification{}, fmt.Errorf("output value exceeds u64")
		}
		outputValue += output.Value
	}
	if outputValue > inputValue {
		return PaymentVerification{}, fmt.Errorf("transaction outputs exceed inputs")
	}
	raw, err := SerializeTransaction(tx)
	if err != nil {
		return PaymentVerification{}, err
	}
	fee := inputValue - outputValue
	if feeRate != 0 {
		required := uint64(len(raw))
		if required > ^uint64(0)/feeRate {
			return PaymentVerification{}, fmt.Errorf("required fee exceeds u64")
		}
		required *= feeRate
		if fee < required {
			return PaymentVerification{}, fmt.Errorf("transaction fee is below the required BCH fee rate")
		}
	}
	for _, output := range tx.Outputs {
		if bytes.Equal(output.ScriptPubKey, merchantScript) && output.Value != merchantAmount {
			return PaymentVerification{}, fmt.Errorf("duplicate merchant output")
		}
	}
	return PaymentVerification{Txid: transactionIDFromRaw(raw), Fee: fmt.Sprintf("%d", fee), SerializedSize: fmt.Sprintf("%d", len(raw))}, nil
}

func VerifyCashTokenPayment(tx Transaction, sources []CashTokenSource, merchantValue, merchantScriptPubKey, category, amount string, feeRate, dustThreshold uint64) (PaymentVerification, error) {
	return VerifyCashTokenPaymentWithNFT(tx, sources, merchantValue, merchantScriptPubKey, category, amount, nil, feeRate, dustThreshold)
}

// VerifyCashTokenPaymentWithNFT verifies an optional exact NFT capability and
// commitment on the merchant output. The original entry point remains
// fungible-only for callers that do not provide an NFT target.
func VerifyCashTokenPaymentWithNFT(tx Transaction, sources []CashTokenSource, merchantValue, merchantScriptPubKey, category, amount string, merchantNFT *NftState, feeRate, dustThreshold uint64) (PaymentVerification, error) {
	if len(sources) != len(tx.Inputs) {
		return PaymentVerification{}, fmt.Errorf("source output count mismatch")
	}
	if tx.Locktime != 0 {
		return PaymentVerification{}, fmt.Errorf("non-zero locktime is unsupported")
	}
	if !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(category) {
		return PaymentVerification{}, fmt.Errorf("CashToken category must be 32-byte hexadecimal")
	}
	merchantAmount, err := canonicalUint(merchantValue)
	if err != nil {
		return PaymentVerification{}, err
	}
	targetAmount, err := canonicalUint(amount)
	if err != nil {
		return PaymentVerification{}, err
	}
	merchantScript, err := hex.DecodeString(merchantScriptPubKey)
	if err != nil {
		return PaymentVerification{}, err
	}
	var inputValue uint64
	var sourceAmount uint64
	sourceNft := make(map[string]int)
	for _, source := range sources {
		value, err := canonicalUint(source.Value)
		if err != nil {
			return PaymentVerification{}, err
		}
		if ^uint64(0)-inputValue < value {
			return PaymentVerification{}, fmt.Errorf("input value exceeds u64")
		}
		inputValue += value
		if !strings.EqualFold(source.Token.Category, category) {
			return PaymentVerification{}, fmt.Errorf("CashToken source category mismatch")
		}
		sourceAmount += source.Token.Amount
		if source.Token.Nft != nil {
			sourceNft[source.Token.Nft.Capability+":"+hex.EncodeToString(source.Token.Nft.Commitment)]++
		}
	}
	outputAmount := uint64(0)
	outputNft := make(map[string]int)
	merchantMatches := 0
	var outputValue uint64
	for _, output := range tx.Outputs {
		if output.Token != nil {
			if !strings.EqualFold(output.Token.Category, category) {
				return PaymentVerification{}, fmt.Errorf("CashToken output category mismatch")
			}
			outputAmount += output.Token.Amount
			if output.Token.Nft != nil {
				outputNft[output.Token.Nft.Capability+":"+hex.EncodeToString(output.Token.Nft.Commitment)]++
			}
			if output.Value < dustThreshold {
				return PaymentVerification{}, fmt.Errorf("CashToken output is dust")
			}
			if output.Value == merchantAmount && bytes.Equal(output.ScriptPubKey, merchantScript) && output.Token.Amount == targetAmount && sameNft(output.Token.Nft, merchantNFT) {
				merchantMatches++
			}
		} else if (len(output.ScriptPubKey) == 0 || output.ScriptPubKey[0] != 0x6a) && output.Value < 546 {
			return PaymentVerification{}, fmt.Errorf("transaction output is dust")
		}
		if ^uint64(0)-outputValue < output.Value {
			return PaymentVerification{}, fmt.Errorf("output value exceeds u64")
		}
		outputValue += output.Value
	}
	if outputAmount != sourceAmount || len(outputNft) != len(sourceNft) {
		return PaymentVerification{}, fmt.Errorf("CashToken state is not conserved")
	}
	for key, value := range sourceNft {
		if outputNft[key] != value {
			return PaymentVerification{}, fmt.Errorf("CashToken NFT state is not conserved")
		}
	}
	if merchantMatches != 1 {
		return PaymentVerification{}, fmt.Errorf("merchant output must match exactly once")
	}
	if outputValue > inputValue {
		return PaymentVerification{}, fmt.Errorf("transaction outputs exceed inputs")
	}
	raw, err := SerializeTransaction(tx)
	if err != nil {
		return PaymentVerification{}, err
	}
	fee := inputValue - outputValue
	if feeRate != 0 {
		required := uint64(len(raw))
		if required > ^uint64(0)/feeRate {
			return PaymentVerification{}, fmt.Errorf("required fee exceeds u64")
		}
		required *= feeRate
		if fee < required {
			return PaymentVerification{}, fmt.Errorf("transaction fee is below the required BCH fee rate")
		}
	}
	return PaymentVerification{Txid: transactionIDFromRaw(raw), Fee: fmt.Sprintf("%d", fee), SerializedSize: fmt.Sprintf("%d", len(raw))}, nil
}

func sameNft(left, right *NftState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Capability == right.Capability && bytes.Equal(left.Commitment, right.Commitment)
}

func canonicalUint(value string) (uint64, error) {
	if !regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(value) {
		return 0, fmt.Errorf("value must be canonical unsigned units")
	}
	var parsed uint64
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		return 0, fmt.Errorf("value exceeds u64")
	}
	return parsed, nil
}
func reverseBytes(value []byte) {
	for left, right := 0, len(value)-1; left < right; left, right = left+1, right-1 {
		value[left], value[right] = value[right], value[left]
	}
}
