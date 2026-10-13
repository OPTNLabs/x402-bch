package x402bch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBchnRpcTransportRoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Method != "testmempoolaccept" {
			t.Fatalf("unexpected method %q", body.Method)
		}
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{
			"id": 1,
			"result": []interface{}{map[string]interface{}{
				"txid":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"allowed": true,
			}},
		})
	}))
	defer server.Close()
	transport, err := NewBchnRpcTransport(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := TestMempoolAccept(transport, []byte{1, 2, 3})
	if err != nil || !result.Allowed || result.Txid == "" {
		t.Fatalf("unexpected BCHN result: %+v, %v", result, err)
	}
}
