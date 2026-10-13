package x402bch

// Transaction and protocol value types shared by the grouped Go packages.
type TransactionInput struct {
	Txid      string
	Vout      uint32
	ScriptSig []byte
	Sequence  uint32
}

type TransactionOutput struct {
	Value        uint64
	ScriptPubKey []byte
	Token        *CashToken
}

type NftState struct {
	Capability string
	Commitment []byte
}
type CashToken struct {
	Category string
	Amount   uint64
	Nft      *NftState
}
type CashTokenSource struct {
	Value string
	Token CashToken
}
type Transaction struct {
	Version  int32
	Inputs   []TransactionInput
	Outputs  []TransactionOutput
	Locktime uint32
}
type SourceOutput struct {
	Value        string
	ScriptPubKey string
	Token        *CashToken
}
type PaymentVerification struct {
	Txid           string
	Fee            string
	SerializedSize string
}

type Requirements struct {
	X402Version       int                    `json:"x402Version"`
	Scheme            string                 `json:"scheme"`
	Network           string                 `json:"network"`
	Amount            string                 `json:"amount"`
	Asset             string                 `json:"asset"`
	PayTo             string                 `json:"payTo"`
	MaxTimeoutSeconds int                    `json:"maxTimeoutSeconds"`
	Extra             map[string]interface{} `json:"extra"`
}

type PaymentPayload struct {
	X402Version int `json:"x402Version"`
	Payload     struct {
		Transaction string `json:"transaction"`
	} `json:"payload"`
	Accepted Requirements `json:"accepted"`
}
