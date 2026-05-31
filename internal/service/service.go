package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"host-cmd-bridge/internal/config"
	"host-cmd-bridge/internal/executor"
	"host-cmd-bridge/internal/model"
	"host-cmd-bridge/internal/policy"
	"host-cmd-bridge/internal/security"
	"host-cmd-bridge/internal/store"
	"host-cmd-bridge/internal/wecom"
)

type Service struct {
	cfg       config.Config
	store     *store.SQLiteStore
	policyMgr *policy.Manager
	wecom     approvalCreator
	executor  *executor.Executor

	hub *waitHub
	sem chan struct{}

	timerMu sync.Mutex
	timers  map[string]context.CancelFunc
}

type approvalCreator interface {
	CreateApproval(context.Context, wecom.ApprovalPayload) (string, error)
}

func New(cfg config.Config, st *store.SQLiteStore, pm *policy.Manager, wc approvalCreator, ex *executor.Executor) *Service {
	return &Service{
		cfg:       cfg,
		store:     st,
		policyMgr: pm,
		wecom:     wc,
		executor:  ex,
		hub:       newWaitHub(),
		sem:       make(chan struct{}, cfg.Exec.MaxConcurrent),
		timers:    make(map[string]context.CancelFunc),
	}
}

func (s *Service) ResumePendingApprovalWatchers(ctx context.Context) error {
	recs, err := s.store.ListPendingApprovals(ctx)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		s.startApprovalTimeoutWatcher(rec.RequestID, rec.ApprovalDeadline)
	}
	return nil
}

func (s *Service) Submit(ctx context.Context, req model.SocketRequest) (model.SocketResponse, error) {
	if req.RequestID == "" {
		return model.SocketResponse{}, errors.New("request_id is required")
	}
	if req.Command == "" {
		return model.SocketResponse{}, errors.New("command is required")
	}
	if req.Reason == "" {
		return model.SocketResponse{}, errors.New("reason is required")
	}
	if req.TimeoutSec <= 0 {
		return model.SocketResponse{}, errors.New("timeout_sec must be > 0")
	}

	effectiveTimeout := req.TimeoutSec
	if effectiveTimeout > s.cfg.Exec.MaxTimeoutSec {
		effectiveTimeout = s.cfg.Exec.MaxTimeoutSec
	}
	log.Printf("[audit] submit received request_id=%s command=%s args=%q timeout_sec=%d", req.RequestID, req.Command, req.Args, effectiveTimeout)

	compiled := s.policyMgr.Get()
	validated, err := security.ValidateAndDigest(compiled, req.Command, req.Args, req.Reason)
	if err != nil {
		log.Printf("[audit] submit rejected by policy request_id=%s reason=%v", req.RequestID, err)
		return model.SocketResponse{RequestID: req.RequestID, Status: model.StatusFailed, Message: err.Error()}, nil
	}

	rec, err := s.store.GetByRequestID(ctx, req.RequestID)
	if err == nil {
		if rec.Command != req.Command || rec.Reason != req.Reason || rec.Normalized != validated.Normalized {
			log.Printf("[audit] duplicate request_id with different payload request_id=%s", req.RequestID)
			return model.SocketResponse{}, requestIDConflictError(req.RequestID)
		}
		log.Printf("[audit] duplicate request_id rejected request_id=%s status=%s", req.RequestID, rec.Status)
		return model.SocketResponse{}, duplicateRequestError(rec.RequestID, rec.CreatedAt)
	}
	if !errors.Is(err, store.ErrNotFound) {
		return model.SocketResponse{}, err
	}

	submitAt := time.Now().UTC()
	approvalDeadline := submitAt.Add(config.DurationSec(s.cfg.Approval.TimeoutSec))
	createErr := s.store.CreateRequest(ctx, store.CreateRequestInput{
		RequestID:        req.RequestID,
		Command:          req.Command,
		Args:             req.Args,
		Reason:           req.Reason,
		TimeoutSec:       effectiveTimeout,
		Normalized:       validated.Normalized,
		Digest:           validated.Digest,
		ApprovalDeadline: approvalDeadline,
	})
	if createErr != nil {
		if errors.Is(createErr, store.ErrRequestExists) {
			log.Printf("[audit] create request raced request_id=%s", req.RequestID)
			existing, getErr := s.store.GetByRequestID(ctx, req.RequestID)
			if getErr != nil {
				return model.SocketResponse{}, duplicateRequestError(req.RequestID, time.Now().UTC())
			}
			if existing.Command != req.Command || existing.Reason != req.Reason || existing.Normalized != validated.Normalized {
				return model.SocketResponse{}, requestIDConflictError(req.RequestID)
			}
			return model.SocketResponse{}, duplicateRequestError(req.RequestID, existing.CreatedAt)
		}
		return model.SocketResponse{}, createErr
	}
	_ = s.store.AddAudit(ctx, req.RequestID, "submit_received", map[string]any{
		"command":     req.Command,
		"args":        req.Args,
		"reason":      req.Reason,
		"timeout_sec": effectiveTimeout,
		"digest":      validated.Digest,
	})

	autoApprove := compiled.Raw().AutoApproveWhitelist && validated.Whitelisted
	if autoApprove {
		log.Printf("[audit] whitelist auto-approve request_id=%s", req.RequestID)
		approvalID, err := s.wecom.CreateApproval(ctx, wecom.ApprovalPayload{
			RequestID:        req.RequestID,
			Command:          req.Command,
			Args:             req.Args,
			Reason:           req.Reason,
			TimeoutSec:       effectiveTimeout,
			Digest:           validated.Digest,
			RequestAt:        submitAt,
			ApprovalDeadline: approvalDeadline,
			AutoApproved:     true,
		})
		if err != nil {
			log.Printf("[audit] auto-approve notify failed request_id=%s err=%v", req.RequestID, err)
			_ = s.store.AddAudit(ctx, req.RequestID, "approval_notify_failed", map[string]any{"error": err.Error()})
		} else {
			if err := s.store.SetApprovalID(ctx, req.RequestID, approvalID); err != nil {
				return model.SocketResponse{}, err
			}
			log.Printf("[audit] auto-approve notify sent request_id=%s approval_id=%s", req.RequestID, approvalID)
			_ = s.store.AddAudit(ctx, req.RequestID, "approval_notify_sent", map[string]any{"approval_id": approvalID})
		}

		updated, err := s.store.UpdateApprovalDecision(ctx, req.RequestID, model.StatusApproved, time.Now().UTC(), "auto approved by whitelist")
		if err != nil {
			return model.SocketResponse{}, err
		}
		if updated {
			_ = s.store.AddAudit(ctx, req.RequestID, "approval_auto_approved", map[string]any{"mode": "whitelist"})
			go s.executeApprovedRequest(req.RequestID)
			return s.waitForFinal(ctx, req.RequestID)
		}
		log.Printf("[audit] auto-approve skipped, state changed request_id=%s", req.RequestID)
		return s.waitForFinal(ctx, req.RequestID)
	}

	approvalID, err := s.wecom.CreateApproval(ctx, wecom.ApprovalPayload{
		RequestID:        req.RequestID,
		Command:          req.Command,
		Args:             req.Args,
		Reason:           req.Reason,
		TimeoutSec:       effectiveTimeout,
		Digest:           validated.Digest,
		RequestAt:        submitAt,
		ApprovalDeadline: approvalDeadline,
		AutoApproved:     false,
	})
	if err != nil {
		log.Printf("[audit] approval create failed request_id=%s err=%v", req.RequestID, err)
		_, _ = s.store.SetStatusIfCurrent(context.Background(), req.RequestID, model.StatusPendingApproval, model.StatusFailed, fmt.Sprintf("create approval failed: %v", err))
		_ = s.store.AddAudit(context.Background(), req.RequestID, "approval_create_failed", map[string]any{"error": err.Error()})
		s.hub.publish(req.RequestID)
		return s.waitForFinal(ctx, req.RequestID)
	}
	if err := s.store.SetApprovalID(ctx, req.RequestID, approvalID); err != nil {
		return model.SocketResponse{}, err
	}
	log.Printf("[audit] approval created request_id=%s approval_id=%s", req.RequestID, approvalID)
	_ = s.store.AddAudit(ctx, req.RequestID, "approval_created", map[string]any{"approval_id": approvalID})

	s.startApprovalTimeoutWatcher(req.RequestID, approvalDeadline)
	return s.waitForFinal(ctx, req.RequestID)
}

func (s *Service) Query(ctx context.Context, requestID string) (model.SocketResponse, error) {
	rec, err := s.store.GetByRequestID(ctx, requestID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.SocketResponse{RequestID: requestID, Status: model.StatusFailed, Message: "request not found"}, nil
		}
		return model.SocketResponse{}, err
	}
	return toSocketResponse(rec), nil
}

func (s *Service) HandleApprovalEvent(ctx context.Context, evt wecom.ApprovalEvent) error {
	log.Printf("[audit] approval callback received approval_id=%s sp_status=%d event_time=%s", evt.ApprovalID, evt.SpStatus, evt.EventTime.Format(time.RFC3339))
	rec, err := s.store.GetByApprovalID(ctx, evt.ApprovalID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}

	decisionStatus, ok := mapApprovalStatus(evt.SpStatus)
	if !ok {
		return nil
	}

	if decisionStatus == model.StatusApproved {
		if time.Now().UTC().After(rec.ApprovalDeadline) {
			updated, err := s.store.MarkApprovalTimeoutIfPending(ctx, rec.RequestID, "approval callback arrived after deadline")
			if err != nil {
				return err
			}
			if updated {
				log.Printf("[audit] approval timeout after callback request_id=%s approval_id=%s", rec.RequestID, rec.ApprovalID)
				_ = s.store.AddAudit(ctx, rec.RequestID, "approval_timeout", map[string]any{"approval_id": rec.ApprovalID})
				s.hub.publish(rec.RequestID)
			}
			return nil
		}
	}

	updated, err := s.store.UpdateApprovalDecision(ctx, rec.RequestID, decisionStatus, evt.EventTime, "callback")
	if err != nil {
		return err
	}
	if !updated {
		log.Printf("[audit] approval callback ignored (state changed) request_id=%s approval_id=%s", rec.RequestID, rec.ApprovalID)
		return nil
	}
	log.Printf("[audit] approval decided request_id=%s approval_id=%s decision=%s", rec.RequestID, rec.ApprovalID, decisionStatus)
	s.stopApprovalTimeoutWatcher(rec.RequestID)
	_ = s.store.AddAudit(ctx, rec.RequestID, "approval_decision", map[string]any{"status": decisionStatus, "approval_id": rec.ApprovalID})

	if decisionStatus == model.StatusApproved {
		log.Printf("[audit] approval passed, enqueue execution request_id=%s", rec.RequestID)
		go s.executeApprovedRequest(rec.RequestID)
		return nil
	}
	log.Printf("[audit] request ended without execution request_id=%s status=%s", rec.RequestID, decisionStatus)
	s.hub.publish(rec.RequestID)
	return nil
}

func (s *Service) waitForFinal(ctx context.Context, requestID string) (model.SocketResponse, error) {
	for {
		rec, err := s.store.GetByRequestID(ctx, requestID)
		if err != nil {
			return model.SocketResponse{}, err
		}
		if model.IsTerminalStatus(rec.Status) {
			return toSocketResponse(rec), nil
		}
		ch := s.hub.subscribe(requestID)
		rec2, err := s.store.GetByRequestID(ctx, requestID)
		if err != nil {
			s.hub.unsubscribe(requestID, ch)
			return model.SocketResponse{}, err
		}
		if model.IsTerminalStatus(rec2.Status) {
			s.hub.unsubscribe(requestID, ch)
			return toSocketResponse(rec2), nil
		}

		select {
		case <-ctx.Done():
			s.hub.unsubscribe(requestID, ch)
			return model.SocketResponse{}, ctx.Err()
		case <-ch:
			s.hub.unsubscribe(requestID, ch)
		}
	}
}

func (s *Service) executeApprovedRequest(requestID string) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	ctx := context.Background()
	rec, err := s.store.GetByRequestID(ctx, requestID)
	if err != nil {
		log.Printf("load request for execution failed: request_id=%s err=%v", requestID, err)
		return
	}
	log.Printf("[audit] execution worker begin request_id=%s command=%s args=%q", requestID, rec.Command, rec.Args)

	compiled := s.policyMgr.Get()
	res, err := security.ValidateAndDigest(compiled, rec.Command, rec.Args, rec.Reason)
	if err != nil {
		_, _ = s.store.SetStatusIfCurrent(ctx, requestID, model.StatusApproved, model.StatusFailed, fmt.Sprintf("second validation failed: %v", err))
		_ = s.store.AddAudit(ctx, requestID, "execution_rejected", map[string]any{"error": err.Error()})
		log.Printf("[audit] execution rejected in second validation request_id=%s err=%v", requestID, err)
		s.hub.publish(requestID)
		return
	}
	if res.Digest != rec.Digest {
		_, _ = s.store.SetStatusIfCurrent(ctx, requestID, model.StatusApproved, model.StatusFailed, "digest mismatch before execution")
		_ = s.store.AddAudit(ctx, requestID, "execution_rejected", map[string]any{"error": "digest mismatch"})
		log.Printf("[audit] execution rejected by digest mismatch request_id=%s", requestID)
		s.hub.publish(requestID)
		return
	}

	startedAt := time.Now().UTC()
	ok, err := s.store.TryMarkExecuting(ctx, requestID, startedAt)
	if err != nil || !ok {
		if err != nil {
			log.Printf("mark executing failed: request_id=%s err=%v", requestID, err)
		}
		if !ok {
			log.Printf("[audit] execution skipped because state is not APPROVED request_id=%s", requestID)
		}
		return
	}
	log.Printf("[audit] execution started request_id=%s started_at=%s", requestID, startedAt.Format(time.RFC3339))
	_ = s.store.AddAudit(ctx, requestID, "execution_started", map[string]any{"started_at": startedAt})

	execRes := s.executor.Run(ctx, rec.Command, rec.Args, rec.TimeoutSec)
	errorReason := ""
	if execRes.Err != nil {
		errorReason = execRes.Err.Error()
	}
	if err := s.store.FinishExecution(ctx, requestID, execRes, errorReason); err != nil {
		log.Printf("finish execution failed: request_id=%s err=%v", requestID, err)
		return
	}
	log.Printf("[audit] execution finished request_id=%s exit_code=%d timed_out=%v error=%q", requestID, execRes.ExitCode, execRes.TimedOut, errorReason)
	_ = s.store.AddAudit(ctx, requestID, "execution_finished", map[string]any{
		"exit_code": execRes.ExitCode,
		"timed_out": execRes.TimedOut,
		"error":     errorReason,
	})
	s.hub.publish(requestID)
}

func mapApprovalStatus(spStatus int) (model.Status, bool) {
	switch spStatus {
	case 1:
		return model.StatusPendingApproval, false
	case 2:
		return model.StatusApproved, true
	case 3:
		return model.StatusRejected, true
	case 4, 6:
		return model.StatusWithdrawn, true
	default:
		return model.StatusFailed, false
	}
}

func toSocketResponse(rec store.RequestRecord) model.SocketResponse {
	resp := model.SocketResponse{
		RequestID: rec.RequestID,
		Status:    rec.Status,
		ExitCode:  rec.ExitCode,
		Stdout:    rec.Stdout,
		Stderr:    rec.Stderr,
		TimedOut:  rec.TimedOut,
		Message:   responseMessage(rec),
	}
	if rec.StartedAt != nil {
		resp.StartedAt = *rec.StartedAt
	}
	if rec.EndedAt != nil {
		resp.EndedAt = *rec.EndedAt
	}
	return resp
}

func responseMessage(rec store.RequestRecord) string {
	if rec.Status == model.StatusSucceeded {
		return ""
	}
	if rec.ErrorReason != "" {
		return rec.ErrorReason
	}
	switch rec.Status {
	case model.StatusPendingApproval:
		return "waiting for approval"
	case model.StatusApproved:
		return "approval passed, waiting for execution"
	case model.StatusExecuting:
		return "command is executing"
	case model.StatusRejected:
		return "approval rejected by approver, command was not executed"
	case model.StatusWithdrawn:
		return "approval withdrawn before completion, command was not executed"
	case model.StatusApprovalTimeout:
		return "approval not completed before deadline, command was not executed"
	case model.StatusExecTimeout:
		return "command execution timed out, command was terminated"
	case model.StatusFailed:
		return "request failed before or during command execution"
	default:
		return ""
	}
}

func (s *Service) startApprovalTimeoutWatcher(requestID string, deadline time.Time) {
	s.timerMu.Lock()
	if cancel, ok := s.timers[requestID]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.timers[requestID] = cancel
	s.timerMu.Unlock()

	go func() {
		defer func() {
			s.timerMu.Lock()
			delete(s.timers, requestID)
			s.timerMu.Unlock()
		}()

		d := time.Until(deadline)
		if d < 0 {
			d = 0
		}
		timer := time.NewTimer(d)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			updated, err := s.store.MarkApprovalTimeoutIfPending(context.Background(), requestID, "approval not completed before deadline")
			if err != nil {
				log.Printf("mark approval timeout failed: request_id=%s err=%v", requestID, err)
				return
			}
			if updated {
				log.Printf("[audit] approval timeout reached request_id=%s", requestID)
				_ = s.store.AddAudit(context.Background(), requestID, "approval_timeout", map[string]any{"reason": "deadline reached"})
				s.hub.publish(requestID)
			}
		}
	}()
}

func (s *Service) stopApprovalTimeoutWatcher(requestID string) {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if cancel, ok := s.timers[requestID]; ok {
		cancel()
		delete(s.timers, requestID)
	}
}

func duplicateRequestError(requestID string, createdAt time.Time) error {
	usedAgoSec := int(time.Since(createdAt).Seconds())
	if usedAgoSec < 0 {
		usedAgoSec = 0
	}
	return fmt.Errorf("request_id=%s has already been used %d seconds ago; use action=query to check status/result", requestID, usedAgoSec)
}

func requestIDConflictError(requestID string) error {
	return fmt.Errorf("request_id=%s is already used by a different request payload; please generate a new request_id", requestID)
}
