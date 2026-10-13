package x402bch

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// FulcrumSocketTransport is a concrete one-request-per-connection Electrum
// Cash JSON-RPC transport. Endpoint selection and certificate policy remain
// caller-owned; this type only owns framing, deadlines, and RPC decoding.
type FulcrumSocketTransport struct {
	Address    string
	Timeout    time.Duration
	TLS        bool
	ServerName string
}

func NewFulcrumSocketTransport(address string, timeout time.Duration, tlsEnabled bool) (*FulcrumSocketTransport, error) {
	if address == "" {
		return nil, fmt.Errorf("Fulcrum endpoint address is required")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &FulcrumSocketTransport{Address: address, Timeout: timeout, TLS: tlsEnabled}, nil
}

func (t *FulcrumSocketTransport) Request(method string, params []interface{}) (interface{}, error) {
	if t == nil || t.Address == "" {
		return nil, fmt.Errorf("Fulcrum endpoint address is required")
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	var connection net.Conn
	var err error
	if t.TLS {
		serverName := t.ServerName
		if serverName == "" {
			host, _, splitErr := net.SplitHostPort(t.Address)
			if splitErr != nil {
				return nil, fmt.Errorf("invalid Fulcrum endpoint: %w", splitErr)
			}
			serverName = host
		}
		connection, err = tls.DialWithDialer(&dialer, "tcp", t.Address, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	} else {
		connection, err = dialer.Dial("tcp", t.Address)
	}
	if err != nil {
		return nil, fmt.Errorf("Fulcrum connection failed: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	request := map[string]interface{}{"id": 1, "method": method, "params": params}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return nil, fmt.Errorf("Fulcrum request failed: %w", err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("Fulcrum response failed: %w", err)
	}
	var response struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, fmt.Errorf("Fulcrum response is not JSON: %w", err)
	}
	if response.Error != nil {
		return nil, fmt.Errorf("Fulcrum RPC error (%d): %s", response.Error.Code, response.Error.Message)
	}
	if len(response.Result) == 0 || string(response.Result) == "null" {
		return nil, nil
	}
	var result interface{}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		return nil, fmt.Errorf("Fulcrum result is invalid: %w", err)
	}
	return result, nil
}
