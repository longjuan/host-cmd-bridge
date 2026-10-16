package httpx

import (
	"net/http"
	"strings"
	"testing"
)

func newRequest(remoteAddr string, headers map[string]string) *http.Request {
	req, err := http.NewRequest(http.MethodPost, "https://bridge.example.com/wecom/callback", nil)
	if err != nil {
		panic(err)
	}
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func mustResolver(t *testing.T, trusted []string, header string) *Resolver {
	t.Helper()
	r, err := NewResolver(trusted, header)
	if err != nil {
		t.Fatalf("NewResolver(%v, %q) error = %v", trusted, header, err)
	}
	return r
}

func TestResolveCloudflareTunnelFromLoopback(t *testing.T) {
	t.Parallel()

	// cloudflared 从本机回环发起连接，真实来源只在 CF-Connecting-IP 里。
	r := mustResolver(t, nil, "")
	res := r.Resolve(newRequest("127.0.0.1:36194", map[string]string{
		HeaderCFConnectingIP: "203.0.113.9",
		HeaderXForwardedFor:  "203.0.113.9",
	}))

	if res.IP != "203.0.113.9" {
		t.Fatalf("IP = %q, want %q", res.IP, "203.0.113.9")
	}
	if res.Source != "cf-connecting-ip" {
		t.Fatalf("Source = %q, want %q", res.Source, "cf-connecting-ip")
	}
	if !res.Trusted {
		t.Fatalf("Trusted = false, want true for loopback peer")
	}
	if res.Remote != "127.0.0.1:36194" {
		t.Fatalf("Remote = %q", res.Remote)
	}
}

func TestResolveIgnoresProxyHeadersFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	// 直连对端不可信时，任何代理头都不可采信，否则可被伪造。
	r := mustResolver(t, []string{"127.0.0.1/32"}, "")
	res := r.Resolve(newRequest("198.51.100.7:52345", map[string]string{
		HeaderCFConnectingIP: "203.0.113.9",
		HeaderXForwardedFor:  "203.0.113.9, 198.51.100.7",
	}))

	if res.IP != "198.51.100.7" {
		t.Fatalf("IP = %q, want peer ip %q", res.IP, "198.51.100.7")
	}
	if res.Source != SourceRemote {
		t.Fatalf("Source = %q, want %q", res.Source, SourceRemote)
	}
	if res.Trusted {
		t.Fatalf("Trusted = true, want false")
	}
	if res.Hint == "" {
		t.Fatalf("Hint should point to trusted_proxies config")
	}
	if !strings.Contains(res.Hint, "198.51.100.7") {
		t.Fatalf("Hint = %q, want peer ip inside", res.Hint)
	}
}

func TestResolveHintOnlyOncePerPeer(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, []string{"127.0.0.1/32"}, "")
	req := newRequest("198.51.100.7:1000", map[string]string{HeaderXForwardedFor: "203.0.113.9"})

	if first := r.Resolve(req); first.Hint == "" {
		t.Fatalf("first resolve should carry hint")
	}
	if second := r.Resolve(req); second.Hint != "" {
		t.Fatalf("second resolve should not repeat hint, got %q", second.Hint)
	}
}

func TestResolveWalksForwardedChainRightToLeft(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, []string{"127.0.0.1/32", "10.0.0.0/8"}, "")
	res := r.Resolve(newRequest("127.0.0.1:1000", map[string]string{
		HeaderXForwardedFor: "203.0.113.9, 10.0.0.5, 10.0.0.6",
	}))

	if res.IP != "203.0.113.9" {
		t.Fatalf("IP = %q, want %q", res.IP, "203.0.113.9")
	}
	if res.Source != "x-forwarded-for" {
		t.Fatalf("Source = %q", res.Source)
	}
}

func TestResolveAllTrustedChainFallsBackToLeftmost(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, []string{"loopback", "private"}, "")
	res := r.Resolve(newRequest("127.0.0.1:1000", map[string]string{
		HeaderXForwardedFor: "10.0.0.5, 10.0.0.6",
	}))

	if res.IP != "10.0.0.5" {
		t.Fatalf("IP = %q, want leftmost %q", res.IP, "10.0.0.5")
	}
}

func TestResolvePrefersCFHeaderOverForwardedFor(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, nil, "")
	res := r.Resolve(newRequest("127.0.0.1:1000", map[string]string{
		HeaderCFConnectingIP: "203.0.113.9",
		HeaderXRealIP:        "198.51.100.4",
		HeaderXForwardedFor:  "198.51.100.5",
	}))

	if res.IP != "203.0.113.9" || res.Source != "cf-connecting-ip" {
		t.Fatalf("got IP=%q Source=%q, want cf-connecting-ip", res.IP, res.Source)
	}
}

func TestResolveSkipsInvalidHeaderValues(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, nil, "")
	res := r.Resolve(newRequest("127.0.0.1:1000", map[string]string{
		HeaderCFConnectingIP: "unknown",
		HeaderTrueClientIP:   "_hidden",
		HeaderXRealIP:        "198.51.100.4:8080",
	}))

	if res.IP != "198.51.100.4" || res.Source != "x-real-ip" {
		t.Fatalf("got IP=%q Source=%q, want 198.51.100.4 via x-real-ip", res.IP, res.Source)
	}
}

func TestResolveParsesBracketedIPv6InChain(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, []string{"127.0.0.1/32", "::1/128"}, "")
	res := r.Resolve(newRequest("[::1]:1000", map[string]string{
		HeaderXForwardedFor: `"[2001:db8::1]:443", ::1`,
	}))

	if res.IP != "2001:db8::1" {
		t.Fatalf("IP = %q, want %q", res.IP, "2001:db8::1")
	}
}

func TestResolveExplicitHeaderMode(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, nil, HeaderXForwardedFor)
	res := r.Resolve(newRequest("127.0.0.1:1000", map[string]string{
		HeaderCFConnectingIP: "203.0.113.9",
		HeaderXForwardedFor:  "198.51.100.5",
	}))

	if res.IP != "198.51.100.5" || res.Source != "x-forwarded-for" {
		t.Fatalf("got IP=%q Source=%q, want x-forwarded-for only", res.IP, res.Source)
	}
}

func TestResolveRFC7239ForwardedHeader(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, nil, "")
	res := r.Resolve(newRequest("127.0.0.1:1000", map[string]string{
		HeaderForwarded: `for=203.0.113.9;proto=https, for="198.51.100.4:4711"`,
	}))

	if res.IP != "198.51.100.4" || res.Source != "forwarded" {
		t.Fatalf("got IP=%q Source=%q, want 198.51.100.4 via forwarded", res.IP, res.Source)
	}
}

func TestResolveFallsBackToPeerWhenNoHeaders(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, nil, "")
	res := r.Resolve(newRequest("127.0.0.1:36194", nil))

	if res.IP != "127.0.0.1" || res.Source != SourceRemote {
		t.Fatalf("got IP=%q Source=%q, want loopback via remote", res.IP, res.Source)
	}
	if res.Chain != "" {
		t.Fatalf("Chain = %q, want empty", res.Chain)
	}
}

func TestResolveTrustsDockerGateway(t *testing.T) {
	t.Parallel()

	// cloudflared 跑在容器里时直连对端是 docker 网关。
	r := mustResolver(t, []string{"172.17.0.1/32"}, "")
	res := r.Resolve(newRequest("172.17.0.1:44210", map[string]string{
		HeaderCFConnectingIP: "203.0.113.9",
	}))

	if res.IP != "203.0.113.9" || res.Source != "cf-connecting-ip" {
		t.Fatalf("got IP=%q Source=%q", res.IP, res.Source)
	}
}

func TestNilResolverDegradesGracefully(t *testing.T) {
	t.Parallel()

	var r *Resolver
	res := r.Resolve(newRequest("127.0.0.1:36194", map[string]string{HeaderXForwardedFor: "203.0.113.9"}))

	if res.IP != "127.0.0.1" || res.Source != SourceRemote {
		t.Fatalf("got IP=%q Source=%q, want remote fallback", res.IP, res.Source)
	}
	if desc := r.Describe(); !strings.Contains(desc, "disabled") {
		t.Fatalf("Describe() = %q, want disabled marker", desc)
	}
}

func TestNewResolverRejectsBadConfig(t *testing.T) {
	t.Parallel()

	if _, err := NewResolver(nil, "x-client-ip"); err == nil {
		t.Fatalf("expected error for unsupported real_ip_header")
	}
	if _, err := NewResolver([]string{"10.0.0.0/33"}, ""); err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
	if _, err := NewResolver([]string{"not-an-ip"}, ""); err == nil {
		t.Fatalf("expected error for invalid trusted proxy entry")
	}
}

func TestDefaultTrustedProxiesIsLoopbackOnly(t *testing.T) {
	t.Parallel()

	r := mustResolver(t, nil, "")
	if len(r.entries) != len(DefaultTrustedProxies) {
		t.Fatalf("entries = %v, want defaults %v", r.entries, DefaultTrustedProxies)
	}
	if !r.isTrusted("127.0.0.1") || !r.isTrusted("::1") {
		t.Fatalf("loopback should be trusted by default")
	}
	if r.isTrusted("10.1.2.3") {
		t.Fatalf("private range should not be trusted by default")
	}
	if !strings.Contains(r.Describe(), "real_ip_header=auto") {
		t.Fatalf("Describe() = %q, want auto mode", r.Describe())
	}
}
