// Package httpx 提供 HTTP 请求相关的通用辅助能力。
package httpx

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// 常见反向代理使用到的客户端 IP 头。
const (
	HeaderCFConnectingIP = "CF-Connecting-IP"
	HeaderTrueClientIP   = "True-Client-IP"
	HeaderXRealIP        = "X-Real-IP"
	HeaderXForwardedFor  = "X-Forwarded-For"
	HeaderForwarded      = "Forwarded"
)

// SourceRemote 表示没有采信任何代理头，直接使用 TCP 直连对端地址。
const SourceRemote = "remote"

// RealIPHeaderAuto 让 Resolver 按内置优先级自动挑选代理头。
const RealIPHeaderAuto = "auto"

// DefaultTrustedProxies 是默认的可信代理列表：仅本机回环。
// cloudflared（Cloudflare Tunnel）从本机发起连接，因此默认即可还原真实 IP。
var DefaultTrustedProxies = []string{"127.0.0.1/32", "::1/128"}

// autoOrder 定义了 real_ip_header=auto 时的头优先级：
// Cloudflare 的 CF-Connecting-IP 最可信，其次 nginx 常用的 X-Real-IP，
// 最后才是可以被任意前置代理追加的 X-Forwarded-For / Forwarded。
var autoOrder = []string{
	HeaderCFConnectingIP,
	HeaderTrueClientIP,
	HeaderXRealIP,
	HeaderXForwardedFor,
	HeaderForwarded,
}

// Result 描述一次真实客户端 IP 解析的结果。
type Result struct {
	IP      string // 真实客户端 IP（不含端口）
	Source  string // IP 的取值来源：remote / cf-connecting-ip / x-forwarded-for ...
	Remote  string // 直连对端原始值（host:port）
	PeerIP  string // 直连对端 IP（不含端口）
	Trusted bool   // 直连对端是否命中 trusted_proxies
	Chain   string // 原始转发链（X-Forwarded-For 或 Forwarded）
	Hint    string // 直连对端未被信任却又带了代理头时的配置提示（同一对端只提示一次）
}

// Resolver 依据可信代理列表解析真实客户端 IP。
//
// 安全前提：只有当直连对端命中 trusted_proxies 时才会采信代理头，
// 否则任何人都可以通过伪造 X-Forwarded-For 污染日志。
type Resolver struct {
	trusted []*net.IPNet
	entries []string
	header  string
	hinted  sync.Map
}

// NewResolver 构建解析器。trustedProxies 支持：
//
//	CIDR（10.0.0.0/8）、裸 IP（172.17.0.1）、关键字 loopback / private。
//
// 为空时使用 DefaultTrustedProxies。realIPHeader 为空或 "auto" 表示自动模式。
func NewResolver(trustedProxies []string, realIPHeader string) (*Resolver, error) {
	header, err := normalizeHeader(realIPHeader)
	if err != nil {
		return nil, err
	}

	entries := trustedProxies
	if len(entries) == 0 {
		entries = DefaultTrustedProxies
	}

	r := &Resolver{header: header}
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		nets, err := parseTrustedEntry(raw)
		if err != nil {
			return nil, err
		}
		r.trusted = append(r.trusted, nets...)
		r.entries = append(r.entries, raw)
	}
	return r, nil
}

// ValidateConfig 仅校验代理相关配置是否合法，供配置加载阶段提前报错。
func ValidateConfig(trustedProxies []string, realIPHeader string) error {
	_, err := NewResolver(trustedProxies, realIPHeader)
	return err
}

// Describe 返回便于启动日志输出的配置摘要。
func (r *Resolver) Describe() string {
	if r == nil {
		return "trusted_proxies=<nil> real_ip_header=disabled"
	}
	entries := r.entries
	if len(entries) == 0 {
		entries = DefaultTrustedProxies
	}
	return fmt.Sprintf("trusted_proxies=[%s] real_ip_header=%s", strings.Join(entries, ","), r.modeString())
}

func (r *Resolver) modeString() string {
	if r.header == "" {
		return RealIPHeaderAuto
	}
	return strings.ToLower(r.header)
}

// Resolve 解析请求的真实客户端 IP。
func (r *Resolver) Resolve(req *http.Request) Result {
	if req == nil {
		return Result{Source: SourceRemote}
	}

	res := Result{Remote: req.RemoteAddr, Source: SourceRemote}
	res.PeerIP = hostOnly(req.RemoteAddr)
	res.IP = res.PeerIP

	cf := headerValue(req, HeaderCFConnectingIP)
	trueClient := headerValue(req, HeaderTrueClientIP)
	xreal := headerValue(req, HeaderXRealIP)
	xff := headerValue(req, HeaderXForwardedFor)
	fwd := headerValue(req, HeaderForwarded)
	res.Chain = strings.TrimSpace(xff)
	if res.Chain == "" {
		res.Chain = strings.TrimSpace(fwd)
	}
	hasProxyHeader := cf != "" || trueClient != "" || xreal != "" || xff != "" || fwd != ""

	if r == nil {
		return res
	}

	res.Trusted = r.isTrusted(res.PeerIP)
	if !res.Trusted {
		// 直连对端不可信：拒绝采信任何代理头，避免伪造。
		if hasProxyHeader {
			res.Hint = r.hintOnce(res.PeerIP)
		}
		return res
	}

	for _, h := range r.headerOrder() {
		switch strings.ToLower(h) {
		case strings.ToLower(HeaderCFConnectingIP):
			if ip := parseIPValue(cf); ip != nil {
				return res.with(ip, "cf-connecting-ip")
			}
		case strings.ToLower(HeaderTrueClientIP):
			if ip := parseIPValue(trueClient); ip != nil {
				return res.with(ip, "true-client-ip")
			}
		case strings.ToLower(HeaderXRealIP):
			if ip := parseIPValue(xreal); ip != nil {
				return res.with(ip, "x-real-ip")
			}
		case strings.ToLower(HeaderXForwardedFor):
			if ip := r.pickFromChain(xff); ip != nil {
				return res.with(ip, "x-forwarded-for")
			}
		case strings.ToLower(HeaderForwarded):
			if ip := r.pickFromForwarded(fwd); ip != nil {
				return res.with(ip, "forwarded")
			}
		}
	}

	// 直连对端可信但没有任何可用的代理头：退回直连地址。
	return res
}

func (res Result) with(ip net.IP, source string) Result {
	res.IP = ip.String()
	res.Source = source
	return res
}

func (r *Resolver) headerOrder() []string {
	if r.header != "" {
		return []string{r.header}
	}
	return autoOrder
}

func (r *Resolver) isTrusted(host string) bool {
	ip := parseIPValue(host)
	if ip == nil {
		return false
	}
	for _, n := range r.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// pickFromChain 从右往左扫描 X-Forwarded-For，返回第一个不在可信代理内的地址
// （最接近客户端的真实来源）。若整条链都可信，则返回最左侧地址。
func (r *Resolver) pickFromChain(chain string) net.IP {
	parts := strings.Split(chain, ",")
	parsed := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		if ip := parseIPValue(part); ip != nil {
			parsed = append(parsed, ip)
		}
	}
	if len(parsed) == 0 {
		return nil
	}
	for i := len(parsed) - 1; i >= 0; i-- {
		if !r.isTrusted(parsed[i].String()) {
			return parsed[i]
		}
	}
	return parsed[0]
}

// pickFromForwarded 解析 RFC 7239 的 Forwarded 头，如 for=203.0.113.9;proto=https。
func (r *Resolver) pickFromForwarded(v string) net.IP {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	segments := strings.Split(v, ",")
	var leftmost net.IP
	for i := len(segments) - 1; i >= 0; i-- {
		for _, kv := range strings.Split(segments[i], ";") {
			key, val, ok := strings.Cut(kv, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "for") {
				continue
			}
			ip := parseIPValue(val)
			if ip == nil {
				continue
			}
			leftmost = ip
			if !r.isTrusted(ip.String()) {
				return ip
			}
		}
	}
	return leftmost
}

// hintOnce 保证同一个直连对端只会提示一次，避免刷屏。
func (r *Resolver) hintOnce(peerIP string) string {
	if peerIP == "" {
		return ""
	}
	if _, loaded := r.hinted.LoadOrStore(peerIP, struct{}{}); loaded {
		return ""
	}
	return fmt.Sprintf("peer %s is not in trusted_proxies; proxy headers ignored, add it (e.g. %s/32) to http.trusted_proxies to resolve the real client ip", peerIP, peerIP)
}

func headerValue(req *http.Request, name string) string {
	if req == nil {
		return ""
	}
	return strings.TrimSpace(req.Header.Get(name))
}

func normalizeHeader(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", RealIPHeaderAuto:
		return "", nil
	case "cf-connecting-ip", "true-client-ip", "x-real-ip", "x-forwarded-for", "forwarded":
		return v, nil
	default:
		return "", fmt.Errorf("unsupported real_ip_header %q (want auto, cf-connecting-ip, true-client-ip, x-real-ip, x-forwarded-for or forwarded)", v)
	}
}

func parseTrustedEntry(raw string) ([]*net.IPNet, error) {
	switch strings.ToLower(raw) {
	case "loopback", "localhost":
		return mustCIDRs("127.0.0.0/8", "::1/128"), nil
	case "private", "lan":
		return mustCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"), nil
	}

	if _, n, err := net.ParseCIDR(raw); err == nil {
		return []*net.IPNet{n}, nil
	}

	if ip := net.ParseIP(raw); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return []*net.IPNet{{IP: ip, Mask: net.CIDRMask(bits, bits)}}, nil
	}

	return nil, fmt.Errorf("invalid trusted_proxies entry %q (want CIDR, IP, loopback or private)", raw)
}

func mustCIDRs(vals ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(vals))
	for _, v := range vals {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			panic(fmt.Sprintf("httpx: invalid builtin CIDR %q: %v", v, err))
		}
		out = append(out, n)
	}
	return out
}

// hostOnly 从 host:port 中取出 host，同时兼容 [::1]:8080 与裸 IP。
func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

// parseIPValue 解析各类代理头里的地址写法：裸 IP、[v6]:port、v4:port、带引号、
// 带 zone，以及 Cloudflare 的 "unknown" / "_hidden" 之类占位值。
func parseIPValue(raw string) net.IP {
	v := strings.TrimSpace(raw)
	v = strings.Trim(v, `"`)
	if v == "" || strings.EqualFold(v, "unknown") || strings.EqualFold(v, "_hidden") {
		return nil
	}

	if i := strings.IndexByte(v, '%'); i > 0 {
		v = v[:i] // 去掉 IPv6 zone，如 fe80::1%lo0
	}

	if strings.HasPrefix(v, "[") {
		if end := strings.IndexByte(v, ']'); end > 0 {
			return net.ParseIP(v[1:end])
		}
		return nil
	}

	if ip := net.ParseIP(v); ip != nil {
		return ip
	}

	if host, _, err := net.SplitHostPort(v); err == nil {
		return net.ParseIP(strings.Trim(host, "[]"))
	}

	return nil
}
