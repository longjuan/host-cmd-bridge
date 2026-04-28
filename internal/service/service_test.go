package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"host-cmd-bridge/internal/config"
	"host-cmd-bridge/internal/executor"
	"host-cmd-bridge/internal/model"
	"host-cmd-bridge/internal/policy"
	"host-cmd-bridge/internal/store"
	"host-cmd-bridge/internal/wecom"
)

type fakeApprover struct {
	approvalID string
	err        error
}

func (f fakeApprover) CreateApproval(context.Context, wecom.ApprovalPayload) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.approvalID, nil
}

func TestSubmit_ClampsTimeout(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
whitelist:
  - command: /bin/echo
    arg_patterns: ['^[a-z]+$']
arg_blacklist: ['(;|\||&&)']
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm, err := policy.NewManager(policyPath, 0)
	if err != nil {
		t.Fatalf("new policy manager: %v", err)
	}

	dbPath := filepath.Join(dir, "hostcmd.db")
	st, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	defer st.Close()
	if err := st.Init(context.Background()); err != nil {
		t.Fatalf("init store: %v", err)
	}

	execRunner, err := executor.New("")
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}

	cfg := config.Config{
		Exec: config.ExecConfig{
			MaxConcurrent: 1,
			MaxTimeoutSec: 5,
		},
		Approval: config.ApprovalConfig{
			TimeoutSec:        10,
			CallbackWindowSec: 300,
		},
	}
	svc := New(cfg, st, pm, fakeApprover{err: errors.New("create failed")}, execRunner)

	resp, err := svc.Submit(context.Background(), model.SocketRequest{
		Action:     model.ActionSubmit,
		RequestID:  "r1",
		Command:    "/bin/echo",
		Args:       []string{"hello"},
		Reason:     "test",
		TimeoutSec: 100,
	})
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if resp.Status != model.StatusFailed {
		t.Fatalf("expected failed status, got %s", resp.Status)
	}

	rec, err := st.GetByRequestID(context.Background(), "r1")
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if rec.TimeoutSec != 5 {
		t.Fatalf("expected clamped timeout 5, got %d", rec.TimeoutSec)
	}
}

func TestSubmit_DuplicateRequestIDWithDifferentPayload(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
whitelist:
  - command: /bin/echo
    arg_patterns: ['^[a-z]+$']
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm, err := policy.NewManager(policyPath, 0)
	if err != nil {
		t.Fatalf("new policy manager: %v", err)
	}
	st, err := store.NewSQLiteStore(filepath.Join(dir, "hostcmd.db"))
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	defer st.Close()
	if err := st.Init(context.Background()); err != nil {
		t.Fatalf("init store: %v", err)
	}
	execRunner, err := executor.New("")
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	cfg := config.Config{
		Exec: config.ExecConfig{
			MaxConcurrent: 1,
			MaxTimeoutSec: 5,
		},
		Approval: config.ApprovalConfig{
			TimeoutSec:        10,
			CallbackWindowSec: 300,
		},
	}
	svc := New(cfg, st, pm, fakeApprover{err: errors.New("create failed")}, execRunner)

	_, err = svc.Submit(context.Background(), model.SocketRequest{
		Action:     model.ActionSubmit,
		RequestID:  "dup",
		Command:    "/bin/echo",
		Args:       []string{"hello"},
		Reason:     "test",
		TimeoutSec: 3,
	})
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}

	_, err = svc.Submit(context.Background(), model.SocketRequest{
		Action:     model.ActionSubmit,
		RequestID:  "dup",
		Command:    "/bin/echo",
		Args:       []string{"world"},
		Reason:     "test",
		TimeoutSec: 3,
	})
	if err == nil {
		t.Fatalf("expected duplicate payload conflict error")
	}
}

func TestSubmit_DuplicateRequestIDWithSamePayloadReturnsQueryHint(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
whitelist:
  - command: /bin/echo
    arg_patterns: ['^[a-z]+$']
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm, err := policy.NewManager(policyPath, 0)
	if err != nil {
		t.Fatalf("new policy manager: %v", err)
	}
	st, err := store.NewSQLiteStore(filepath.Join(dir, "hostcmd.db"))
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	defer st.Close()
	if err := st.Init(context.Background()); err != nil {
		t.Fatalf("init store: %v", err)
	}
	execRunner, err := executor.New("")
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	cfg := config.Config{
		Exec: config.ExecConfig{
			MaxConcurrent: 1,
			MaxTimeoutSec: 5,
		},
		Approval: config.ApprovalConfig{
			TimeoutSec:        10,
			CallbackWindowSec: 300,
		},
	}
	svc := New(cfg, st, pm, fakeApprover{err: errors.New("create failed")}, execRunner)

	_, err = svc.Submit(context.Background(), model.SocketRequest{
		Action:     model.ActionSubmit,
		RequestID:  "same",
		Command:    "/bin/echo",
		Args:       []string{"hello"},
		Reason:     "test",
		TimeoutSec: 3,
	})
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}

	_, err = svc.Submit(context.Background(), model.SocketRequest{
		Action:     model.ActionSubmit,
		RequestID:  "same",
		Command:    "/bin/echo",
		Args:       []string{"hello"},
		Reason:     "test",
		TimeoutSec: 3,
	})
	if err == nil {
		t.Fatalf("expected duplicate request error")
	}
	if !strings.Contains(err.Error(), "use action=query") {
		t.Fatalf("expected query hint in error, got: %v", err)
	}
}

func TestSubmit_NonWhitelistCommandGoesApprovalPath(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
whitelist:
  - command: /bin/echo
    arg_patterns: ['^[a-z]+$']
command_blacklist:
  - '(?i)(^|/)rm$'
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm, err := policy.NewManager(policyPath, 0)
	if err != nil {
		t.Fatalf("new policy manager: %v", err)
	}
	st, err := store.NewSQLiteStore(filepath.Join(dir, "hostcmd.db"))
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	defer st.Close()
	if err := st.Init(context.Background()); err != nil {
		t.Fatalf("init store: %v", err)
	}
	execRunner, err := executor.New("")
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	cfg := config.Config{
		Exec: config.ExecConfig{
			MaxConcurrent: 1,
			MaxTimeoutSec: 5,
		},
		Approval: config.ApprovalConfig{
			TimeoutSec:        10,
			CallbackWindowSec: 300,
		},
	}
	svc := New(cfg, st, pm, fakeApprover{err: errors.New("create failed")}, execRunner)

	resp, err := svc.Submit(context.Background(), model.SocketRequest{
		Action:     model.ActionSubmit,
		RequestID:  "non-whitelist-approval",
		Command:    "/bin/hostname",
		Args:       []string{},
		Reason:     "test approval path",
		TimeoutSec: 3,
	})
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if resp.Status != model.StatusFailed {
		t.Fatalf("expected failed status, got %s", resp.Status)
	}
	if !strings.Contains(resp.ErrorReason, "create approval failed") {
		t.Fatalf("expected approval-path failure, got: %s", resp.ErrorReason)
	}
	if strings.Contains(resp.ErrorReason, "not whitelisted") {
		t.Fatalf("unexpected whitelist rejection: %s", resp.ErrorReason)
	}
}
