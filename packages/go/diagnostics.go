package x402bch

import "strings"

const DiagnosticRedacted = "[redacted]"

type BchDiagnostic struct {
	Stage   string
	Code    string
	Message string
	Context map[string]string
}

func CreateBchDiagnostic(stage, code, message string, context map[string]string) BchDiagnostic {
	safe := make(map[string]string, len(context))
	for key, value := range context {
		switch strings.ToLower(key) {
		case "mnemonic", "privatekey", "seed", "secret", "authorization", "transaction", "rawtransaction", "signedtransaction":
			safe[key] = DiagnosticRedacted
		default:
			safe[key] = value
		}
	}
	return BchDiagnostic{Stage: stage, Code: code, Message: message, Context: safe}
}
