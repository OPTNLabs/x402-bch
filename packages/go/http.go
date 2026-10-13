package x402bch

import (
	"encoding/base64"
	"fmt"
)

const (
	BchPaymentRequiredHeader  = "PAYMENT-REQUIRED"
	BchPaymentSignatureHeader = "PAYMENT-SIGNATURE"
	BchPaymentResponseHeader  = "PAYMENT-RESPONSE"
)

type BchHttpResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

func CreateBchPaymentRequiredResponse(requirementsJSON string) BchHttpResponse {
	return BchHttpResponse{Status: 402, Headers: map[string]string{BchPaymentRequiredHeader: EncodeBchHttpHeader(requirementsJSON)}, Body: "Payment required"}
}

func CreateBchPaymentSignatureHeader(payloadJSON string) map[string]string {
	return map[string]string{BchPaymentSignatureHeader: EncodeBchHttpHeader(payloadJSON)}
}

func CreateBchPaymentResponse(resultJSON string) map[string]string {
	return map[string]string{BchPaymentResponseHeader: EncodeBchHttpHeader(resultJSON)}
}

func EncodeBchHttpHeader(jsonValue string) string {
	if jsonValue == "" {
		panic("HTTP x402 header JSON must not be empty")
	}
	return base64.StdEncoding.EncodeToString([]byte(jsonValue))
}

func DecodeBchHttpHeader(header string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil || len(decoded) == 0 {
		return "", fmt.Errorf("HTTP x402 header is not valid non-empty base64")
	}
	return string(decoded), nil
}
