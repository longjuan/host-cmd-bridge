package model

import "time"

type Action string

const (
	ActionSubmit Action = "submit"
	ActionQuery  Action = "query"
)

type Status string

const (
	StatusPendingApproval Status = "PENDING_APPROVAL"
	StatusApproved        Status = "APPROVED"
	StatusRejected        Status = "REJECTED"
	StatusWithdrawn       Status = "WITHDRAWN"
	StatusApprovalTimeout Status = "APPROVAL_TIMEOUT"
	StatusExecuting       Status = "EXECUTING"
	StatusSucceeded       Status = "SUCCEEDED"
	StatusFailed          Status = "FAILED"
	StatusExecTimeout     Status = "EXEC_TIMEOUT"
)

func IsTerminalStatus(s Status) bool {
	switch s {
	case StatusRejected, StatusWithdrawn, StatusApprovalTimeout, StatusSucceeded, StatusFailed, StatusExecTimeout:
		return true
	default:
		return false
	}
}

type SocketRequest struct {
	Action     Action   `json:"action"`
	RequestID  string   `json:"request_id"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	TimeoutSec int      `json:"timeout_sec,omitempty"`
}

type SocketResponse struct {
	RequestID string    `json:"request_id"`
	Status    Status    `json:"status,omitempty"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Stdout    string    `json:"stdout,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	TimedOut  bool      `json:"timed_out,omitempty"`
	Message   string    `json:"message,omitempty"`
}

type ExecuteRequest struct {
	RequestID    string
	Command      string
	Args         []string
	Reason       string
	TimeoutSec   int
	Digest       string
	Normalized   string
	CreatedAt    time.Time
	ApprovalBy   time.Time
	Status       Status
	ApprovalID   string
	ApprovalAt   *time.Time
	ApprovalNote string
}

type ExecutionResult struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	StartedAt time.Time
	EndedAt   time.Time
	TimedOut  bool
	Err       error
}

type ApprovalDecision string

const (
	ApprovalApproved ApprovalDecision = "APPROVED"
	ApprovalRejected ApprovalDecision = "REJECTED"
	ApprovalWithdraw ApprovalDecision = "WITHDRAWN"
	ApprovalTimeout  ApprovalDecision = "TIMEOUT"
)

type ApprovalCallback struct {
	ApprovalID string
	Decision   ApprovalDecision
	DecisionAt time.Time
	Reason     string
}

func DecisionToStatus(d ApprovalDecision) Status {
	switch d {
	case ApprovalApproved:
		return StatusApproved
	case ApprovalRejected:
		return StatusRejected
	case ApprovalWithdraw:
		return StatusWithdrawn
	case ApprovalTimeout:
		return StatusApprovalTimeout
	default:
		return StatusFailed
	}
}
