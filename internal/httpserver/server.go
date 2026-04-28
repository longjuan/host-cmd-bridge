package httpserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"host-cmd-bridge/internal/service"
	"host-cmd-bridge/internal/wecom"
)

type Server struct {
	addr               string
	callbackPathPrefix string
	svc                *service.Service
	verifier           *wecom.CallbackVerifier
}

func New(addr string, callbackPathPrefix string, svc *service.Service, verifier *wecom.CallbackVerifier) *Server {
	return &Server{
		addr:               addr,
		callbackPathPrefix: normalizePathPrefix(callbackPathPrefix),
		svc:                svc,
		verifier:           verifier,
	}
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
		log.Printf("http server listening on %s callback_path_prefix=%s", s.addr, s.callbackPathPrefix)
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
	log.Printf("[wecom-callback] request remote=%s method=%s path=%s query=%s", r.RemoteAddr, r.Method, r.URL.Path, r.URL.RawQuery)

	switch r.Method {
	case http.MethodGet:
		echoStr := r.URL.Query().Get("echostr")
		plain, err := s.verifier.VerifyURL(msgSignature, timestamp, nonce, echoStr)
		if err != nil {
			log.Printf("[wecom-callback] verify-url failed remote=%s err=%v", r.RemoteAddr, err)
			http.Error(w, fmt.Sprintf("verify callback url failed: %v", err), http.StatusUnauthorized)
			return
		}
		log.Printf("[wecom-callback] verify-url success remote=%s", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(plain))
		return
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[wecom-callback] read-body failed remote=%s err=%v", r.RemoteAddr, err)
			http.Error(w, "read callback body failed", http.StatusBadRequest)
			return
		}
		evt, err := s.verifier.ParseApprovalEvent(msgSignature, timestamp, nonce, body)
		if err != nil {
			log.Printf("[wecom-callback] parse-event failed remote=%s err=%v body=%s", r.RemoteAddr, err, string(body))
			http.Error(w, fmt.Sprintf("parse callback failed: %v", err), http.StatusUnauthorized)
			return
		}
		log.Printf("[wecom-callback] parse-event success remote=%s approval_id=%s sp_status=%d event_time=%s", r.RemoteAddr, evt.ApprovalID, evt.SpStatus, evt.EventTime.Format(time.RFC3339))
		if err := s.svc.HandleApprovalEvent(r.Context(), evt); err != nil {
			log.Printf("[wecom-callback] handle-event failed remote=%s approval_id=%s err=%v", r.RemoteAddr, evt.ApprovalID, err)
			http.Error(w, fmt.Sprintf("handle callback failed: %v", err), http.StatusInternalServerError)
			return
		}
		log.Printf("[wecom-callback] handle-event success remote=%s approval_id=%s", r.RemoteAddr, evt.ApprovalID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
		return
	default:
		log.Printf("[wecom-callback] method-not-allowed remote=%s method=%s", r.RemoteAddr, r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}
