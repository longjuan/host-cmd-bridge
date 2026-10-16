package httpserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"host-cmd-bridge/internal/httpx"
	"host-cmd-bridge/internal/service"
	"host-cmd-bridge/internal/wecom"
)

type Server struct {
	addr               string
	callbackPathPrefix string
	svc                *service.Service
	verifier           *wecom.CallbackVerifier
	resolver           *httpx.Resolver
}

// New 创建回调服务。resolver 用于还原反向代理（Cloudflare Tunnel / nginx 等）
// 后的真实客户端 IP，可为 nil（此时日志只显示直连对端地址）。
func New(addr string, callbackPathPrefix string, resolver *httpx.Resolver, svc *service.Service, verifier *wecom.CallbackVerifier) *Server {
	return &Server{
		addr:               addr,
		callbackPathPrefix: normalizePathPrefix(callbackPathPrefix),
		svc:                svc,
		verifier:           verifier,
		resolver:           resolver,
	}
}

// clientFields 生成日志用的客户端标识字段：真实客户端 IP、来源头与直连对端。
func (s *Server) clientFields(r *http.Request) string {
	res := httpx.Result{Remote: r.RemoteAddr, PeerIP: hostOnly(r.RemoteAddr), IP: hostOnly(r.RemoteAddr), Source: httpx.SourceRemote}
	if s.resolver != nil {
		res = s.resolver.Resolve(r)
	}

	fields := fmt.Sprintf("client_ip=%s ip_source=%s remote=%s", res.IP, res.Source, res.Remote)
	if res.Chain != "" {
		fields += fmt.Sprintf(" forwarded=%q", sanitizeLogValue(res.Chain))
	}
	if res.Hint != "" {
		fields += fmt.Sprintf(" hint=%q", sanitizeLogValue(res.Hint))
	}
	return fields
}

// hostOnly 从 host:port 中取出主机部分。
func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

// sanitizeLogValue 去掉控制字符，避免请求头内容污染日志行。
func sanitizeLogValue(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, v)
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.route)

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("http server listening on %s callback_path_prefix=%s %s", s.addr, s.callbackPathPrefix, s.resolver.Describe())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if !s.matchCallbackPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	s.handleWeComCallback(w, r)
}

func (s *Server) matchCallbackPath(path string) bool {
	prefix := s.callbackPathPrefix
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

func normalizePathPrefix(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "/wecom/callback"
	}
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	if len(v) > 1 {
		v = strings.TrimSuffix(v, "/")
	}
	return v
}

func (s *Server) handleWeComCallback(w http.ResponseWriter, r *http.Request) {
	msgSignature := r.URL.Query().Get("msg_signature")
	timestamp := r.URL.Query().Get("timestamp")
	nonce := r.URL.Query().Get("nonce")
	log.Printf("[wecom-callback] request %s method=%s path=%s query=%s", s.clientFields(r), r.Method, r.URL.Path, r.URL.RawQuery)

	switch r.Method {
	case http.MethodGet:
		echoStr := r.URL.Query().Get("echostr")
		plain, err := s.verifier.VerifyURL(msgSignature, timestamp, nonce, echoStr)
		if err != nil {
			log.Printf("[wecom-callback] verify-url failed %s err=%v", s.clientFields(r), err)
			http.Error(w, fmt.Sprintf("verify callback url failed: %v", err), http.StatusUnauthorized)
			return
		}
		log.Printf("[wecom-callback] verify-url success %s", s.clientFields(r))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(plain))
		return
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[wecom-callback] read-body failed %s err=%v", s.clientFields(r), err)
			http.Error(w, "read callback body failed", http.StatusBadRequest)
			return
		}
		evt, err := s.verifier.ParseApprovalEvent(msgSignature, timestamp, nonce, body)
		if err != nil {
			log.Printf("[wecom-callback] parse-event failed %s err=%v body=%s", s.clientFields(r), err, string(body))
			http.Error(w, fmt.Sprintf("parse callback failed: %v", err), http.StatusUnauthorized)
			return
		}
		log.Printf("[wecom-callback] parse-event success %s approval_id=%s sp_status=%d event_time=%s", s.clientFields(r), evt.ApprovalID, evt.SpStatus, evt.EventTime.Format(time.RFC3339))
		if err := s.svc.HandleApprovalEvent(r.Context(), evt); err != nil {
			log.Printf("[wecom-callback] handle-event failed %s approval_id=%s err=%v", s.clientFields(r), evt.ApprovalID, err)
			http.Error(w, fmt.Sprintf("handle callback failed: %v", err), http.StatusInternalServerError)
			return
		}
		log.Printf("[wecom-callback] handle-event success %s approval_id=%s", s.clientFields(r), evt.ApprovalID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
		return
	default:
		log.Printf("[wecom-callback] method-not-allowed %s method=%s", s.clientFields(r), r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}
