package x402bch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BchnRpc is the narrow node boundary used for BCHN script and mempool checks.
type BchnRpc interface {
	Request(method string, params interface{}) (interface{}, error)
}

// BchnRpcTransport is a direct BCHN JSON-RPC client over HTTP(S). Authentication
// headers and endpoint selection remain caller-owned.
type BchnRpcTransport struct {
	URL     string
	Client  *http.Client
	Headers map[string]string
}

func NewBchnRpcTransport(url string, timeout time.Duration) (*BchnRpcTransport, error) {
	if len(url) < 8 || (url[:7] != "http://" && url[:8] != "https://") {
		return nil, fmt.Errorf("BCHN RPC URL must use http:// or https://")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &BchnRpcTransport{URL: url, Client: &http.Client{Timeout: timeout}, Headers: map[string]string{}}, nil
}

func (t *BchnRpcTransport) Request(method string, params interface{}) (interface{}, error) {
	if t == nil || t.URL == "" || t.Client == nil {
		return nil, fmt.Errorf("BCHN RPC transport is not configured")
	}
	body, err := json.Marshal(map[string]interface{}{"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, fmt.Errorf("BCHN request encoding failed: %w", err)
	}
	request, err := http.NewRequest(http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("BCHN request creation failed: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range t.Headers {
		request.Header.Set(key, value)
	}
	response, err := t.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("BCHN request failed: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("BCHN response read failed: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("BCHN RPC HTTP status %d", response.StatusCode)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return nil, fmt.Errorf("BCHN response is not JSON: %w", err)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("BCHN RPC error (%d): %s", envelope.Error.Code, envelope.Error.Message)
	}
	if len(envelope.Result) == 0 {
		return nil, fmt.Errorf("BCHN RPC response is missing result")
	}
	var result interface{}
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, fmt.Errorf("BCHN result is invalid: %w", err)
	}
	return result, nil
}

type BchnMempoolResult struct {
	Allowed bool
	Reason  string
	Txid    string
}

// TestMempoolAccept normalizes BCHN's script/mempool admission result.
func TestMempoolAccept(rpc BchnRpc, rawTransaction []byte) (BchnMempoolResult, error) {
	result, err := rpc.Request("testmempoolaccept", [][]string{{hex.EncodeToString(rawTransaction)}})
	if err != nil {
		return BchnMempoolResult{}, err
	}
	entries, ok := result.([]interface{})
	if !ok || len(entries) != 1 {
		return BchnMempoolResult{}, fmt.Errorf("BCHN testmempoolaccept response is malformed")
	}
	entry, ok := entries[0].(map[string]interface{})
	if !ok {
		return BchnMempoolResult{}, fmt.Errorf("BCHN testmempoolaccept entry is malformed")
	}
	allowed, ok := entry["allowed"].(bool)
	if !ok {
		return BchnMempoolResult{}, fmt.Errorf("BCHN testmempoolaccept result has no allowed flag")
	}
	resultValue := BchnMempoolResult{Allowed: allowed}
	if reason, ok := entry["reject-reason"].(string); ok {
		resultValue.Reason = reason
	}
	if txid, ok := entry["txid"].(string); ok {
		resultValue.Txid = txid
	}
	return resultValue, nil
}
