package httpserver

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"host-cmd-bridge/internal/httpx"
	"host-cmd-bridge/internal/wecom"
)

func newCallbackRequest(remoteAddr string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/wecom/callback?msg_signature=x&timestamp=1&nonce=2", strings.NewReader("<xml/>"))
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestClientFieldsResolvesCloudflareTunnelIP(t *testing.T) {
	t.Parallel()

	resolver, err := httpx.NewResolver(nil, "")
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	s := &Server{resolver: resolver}

	got := s.clientFields(newCallbackRequest("127.0.0.1:36194", map[string]string{
		"CF-Connecting-IP": "203.0.113.9",
		"X-Forwarded-For":  "203.0.113.9",
	}))

	want := `client_ip=203.0.113.9 ip_source=cf-connecting-ip remote=127.0.0.1:36194 forwarded="203.0.113.9"`
	if got != want {
		t.Fatalf("clientFields() = %q, want %q", got, want)
	}
}

func TestClientFieldsWithoutResolverUsesRemote(t *testing.T) {
	t.Parallel()

	s := &Server{}

	got := s.clientFields(newCallbackRequest("127.0.0.1:36194", map[string]string{
		"CF-Connecting-IP": "203.0.113.9",
	}))

	if !strings.Contains(got, "client_ip=127.0.0.1") {
		t.Fatalf("clientFields() = %q, want loopback client ip", got)
	}
	if strings.Contains(got, "203.0.113.9") {
		t.Fatalf("clientFields() = %q, must not trust headers without resolver", got)
	}
}

func TestClientFieldsSanitizesControlChars(t *testing.T) {
	t.Parallel()

	resolver, err := httpx.NewResolver(nil, "")
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	s := &Server{resolver: resolver}

	got := s.clientFields(newCallbackRequest("127.0.0.1:36194", map[string]string{
		"X-Forwarded-For": "203.0.113.9\ninjected=1",
	}))

	if strings.Contains(got, "\n") {
		t.Fatalf("clientFields() = %q, want newlines sanitized", got)
	}
}

func TestClientFieldsUntrustedPeerEmitsHint(t *testing.T) {
	t.Parallel()

	resolver, err := httpx.NewResolver([]string{"127.0.0.1/32"}, "")
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	s := &Server{resolver: resolver}

	got := s.clientFields(newCallbackRequest("172.17.0.1:12000", map[string]string{
		"CF-Connecting-IP": "203.0.113.9",
	}))

	if !strings.Contains(got, "client_ip=172.17.0.1") {
		t.Fatalf("clientFields() = %q, want peer ip", got)
	}
	if !strings.Contains(got, "hint=") {
		t.Fatalf("clientFields() = %q, want hint for untrusted peer", got)
	}
}

// TestHandleWeComCallbackLogsRealClientIP 走一遍真实回调处理链路，
// 确认日志里出现的是 Cloudflare Tunnel 还原出的客户端 IP。
func TestHandleWeComCallbackLogsRealClientIP(t *testing.T) {
	// 该用例需要抓取全局 log 输出，不能并行执行。
	verifier, err := wecom.NewCallbackVerifier("test-token", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", "corp", 300*time.Second)
	if err != nil {
		t.Fatalf("NewCallbackVerifier() error = %v", err)
	}
	resolver, err := httpx.NewResolver(nil, "")
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	s := &Server{callbackPathPrefix: "/wecom/callback", resolver: resolver, verifier: verifier}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	req := newCallbackRequest("127.0.0.1:36194", map[string]string{"CF-Connecting-IP": "203.0.113.9"})
	rec := httptest.NewRecorder()
	s.route(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (bogus signature)", rec.Code, http.StatusUnauthorized)
	}

	out := buf.String()
	if !strings.Contains(out, "client_ip=203.0.113.9") {
		t.Fatalf("log output missing resolved client ip: %s", out)
	}
	if !strings.Contains(out, "ip_source=cf-connecting-ip") {
		t.Fatalf("log output missing ip source: %s", out)
	}
	if !strings.Contains(out, "remote=127.0.0.1:36194") {
		t.Fatalf("log output missing raw remote addr: %s", out)
	}
}
