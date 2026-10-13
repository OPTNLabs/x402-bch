package x402bch

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestFulcrumSocketTransportRoundTrip(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr != nil {
			serverDone <- readErr
			return
		}
		var request map[string]interface{}
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			serverDone <- err
			return
		}
		if request["method"] != "server.version" {
			serverDone <- fmt.Errorf("unexpected method %v", request["method"])
			return
		}
		_, writeErr := io.WriteString(connection, `{"id":1,"result":["fulcrum-test","1.0"]}`+"\n")
		serverDone <- writeErr
	}()
	transport, err := NewFulcrumSocketTransport(listener.Addr().String(), time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.Request("server.version", []interface{}{"x402-bch", "1.0"})
	if err != nil {
		t.Fatal(err)
	}
	values, ok := result.([]interface{})
	if !ok || len(values) != 2 || values[0] != "fulcrum-test" {
		t.Fatalf("unexpected response %#v", result)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
