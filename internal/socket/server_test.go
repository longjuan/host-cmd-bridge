package socket

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"host-cmd-bridge/internal/model"
)

func TestHandleConn_InvalidJSONReturnsMessage(t *testing.T) {
	resp := roundTripSocketResponse(t, "{bad json}\n")

	if resp.Status != model.StatusFailed {
		t.Fatalf("expected failed status, got %s", resp.Status)
	}
	if !strings.HasPrefix(resp.Message, "invalid request json: ") {
		t.Fatalf("expected invalid json message, got %q", resp.Message)
	}
}

func TestHandleConn_DispatchErrorReturnsMessage(t *testing.T) {
	resp := roundTripSocketResponse(t, `{"action":"unknown","request_id":"r1"}`+"\n")

	if resp.RequestID != "r1" {
		t.Fatalf("expected request id r1, got %q", resp.RequestID)
	}
	if resp.Status != model.StatusFailed {
		t.Fatalf("expected failed status, got %s", resp.Status)
	}
	if resp.Message != "unsupported action: unknown" {
		t.Fatalf("expected unsupported action message, got %q", resp.Message)
	}
}

func roundTripSocketResponse(t *testing.T, payload string) model.SocketResponse {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	srv := &Server{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleConn(serverConn)
	}()

	if _, err := clientConn.Write([]byte(payload)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	line, err := bufio.NewReader(clientConn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var resp model.SocketResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	_ = clientConn.Close()
	<-done
	return resp
}
