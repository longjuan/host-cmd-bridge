package socket

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"host-cmd-bridge/internal/model"
	"host-cmd-bridge/internal/service"
)

type Server struct {
	path string
	mode os.FileMode
	svc  *service.Service
}

func New(path string, mode os.FileMode, svc *service.Service) *Server {
	return &Server{path: path, mode: mode, svc: svc}
}

func (s *Server) Run(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	_ = os.Remove(s.path)

	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}
	if err := os.Chmod(s.path, s.mode); err != nil {
		_ = ln.Close()
		_ = os.Remove(s.path)
		return fmt.Errorf("chmod unix socket to %#o: %w", s.mode, err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(s.path)
	}()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		line := scanner.Bytes()
		var req model.SocketRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(model.SocketResponse{
				Status:  model.StatusFailed,
				Message: fmt.Sprintf("invalid request json: %v", err),
			})
			continue
		}

		resp, err := s.dispatch(req)
		if err != nil {
			resp = model.SocketResponse{
				RequestID: req.RequestID,
				Status:    model.StatusFailed,
				Message:   err.Error(),
			}
		}
		if err := enc.Encode(resp); err != nil {
			log.Printf("write socket response failed: %v", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("socket read failed: %v", err)
	}
}

func (s *Server) dispatch(req model.SocketRequest) (model.SocketResponse, error) {
	switch req.Action {
	case model.ActionSubmit:
		return s.svc.Submit(context.Background(), req)
	case model.ActionQuery:
		if req.RequestID == "" {
			return model.SocketResponse{}, errors.New("request_id is required")
		}
		return s.svc.Query(context.Background(), req.RequestID)
	default:
		return model.SocketResponse{}, fmt.Errorf("unsupported action: %s", req.Action)
	}
}
