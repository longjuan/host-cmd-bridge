package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"host-cmd-bridge/internal/model"

	_ "modernc.org/sqlite"
)

var (
	ErrRequestExists = errors.New("request id already exists")
	ErrNotFound      = errors.New("record not found")
)

type SQLiteStore struct {
	db *sql.DB
}

type RequestRecord struct {
	RequestID        string
	Command          string
	Args             []string
	Reason           string
	TimeoutSec       int
	Normalized       string
	Digest           string
	Status           model.Status
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ApprovalDeadline time.Time
	ApprovalID       string
	ApprovalStatus   string
	ApprovalTime     *time.Time
	ApprovalReason   string
	StartedAt        *time.Time
	EndedAt          *time.Time
	ExitCode         int
	Stdout           string
	Stderr           string
	TimedOut         bool
	ErrorReason      string
}

type CreateRequestInput struct {
	RequestID        string
	Command          string
	Args             []string
	Reason           string
	TimeoutSec       int
	Normalized       string
	Digest           string
	ApprovalDeadline time.Time
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) Init(ctx context.Context) error {
	schema := `
CREATE TABLE IF NOT EXISTS requests (
  request_id TEXT PRIMARY KEY,
  command TEXT NOT NULL,
  args_json TEXT NOT NULL,
  reason TEXT NOT NULL,
  timeout_sec INTEGER NOT NULL,
  normalized TEXT NOT NULL,
  digest TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  approval_deadline TIMESTAMP NOT NULL,
  approval_id TEXT,
  approval_status TEXT,
  approval_time TIMESTAMP,
  approval_reason TEXT,
  started_at TIMESTAMP,
  ended_at TIMESTAMP,
  exit_code INTEGER,
  stdout TEXT,
  stderr TEXT,
  timed_out INTEGER,
  error_reason TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_approval_id ON requests(approval_id) WHERE approval_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_time TIMESTAMP NOT NULL,
  payload TEXT NOT NULL
);`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *SQLiteStore) CreateRequest(ctx context.Context, in CreateRequestInput) error {
	argsJSON, err := json.Marshal(in.Args)
	if err != nil {
		return fmt.Errorf("marshal args: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO requests(
  request_id, command, args_json, reason, timeout_sec, normalized, digest,
  status, created_at, updated_at, approval_deadline
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.RequestID, in.Command, string(argsJSON), in.Reason, in.TimeoutSec, in.Normalized, in.Digest,
		model.StatusPendingApproval, now, now, in.ApprovalDeadline.UTC(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: requests.request_id") {
			return ErrRequestExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStore) SetApprovalID(ctx context.Context, requestID, approvalID string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE requests
SET approval_id = ?, updated_at = ?
WHERE request_id = ?`, approvalID, time.Now().UTC(), requestID)
	return err
}

func (s *SQLiteStore) GetByRequestID(ctx context.Context, requestID string) (RequestRecord, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT request_id, command, args_json, reason, timeout_sec, normalized, digest, status, created_at, updated_at,
       approval_deadline, approval_id, approval_status, approval_time, approval_reason, started_at, ended_at, exit_code,
       stdout, stderr, timed_out, error_reason
FROM requests WHERE request_id = ?`, requestID)
	return scanRequest(row)
}

func (s *SQLiteStore) GetByApprovalID(ctx context.Context, approvalID string) (RequestRecord, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT request_id, command, args_json, reason, timeout_sec, normalized, digest, status, created_at, updated_at,
       approval_deadline, approval_id, approval_status, approval_time, approval_reason, started_at, ended_at, exit_code,
       stdout, stderr, timed_out, error_reason
FROM requests WHERE approval_id = ?`, approvalID)
	return scanRequest(row)
}

func (s *SQLiteStore) UpdateApprovalDecision(ctx context.Context, requestID string, status model.Status, at time.Time, reason string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE requests
SET status = ?, approval_status = ?, approval_time = ?, approval_reason = ?, updated_at = ?
WHERE request_id = ? AND status = ?`,
		status, status, at.UTC(), reason, time.Now().UTC(), requestID, model.StatusPendingApproval,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *SQLiteStore) MarkApprovalTimeoutIfPending(ctx context.Context, requestID string, reason string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE requests
SET status = ?, approval_status = ?, approval_reason = ?, updated_at = ?
WHERE request_id = ? AND status = ?`,
		model.StatusApprovalTimeout, model.StatusApprovalTimeout, reason, time.Now().UTC(), requestID, model.StatusPendingApproval,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *SQLiteStore) SetStatusIfCurrent(ctx context.Context, requestID string, from model.Status, to model.Status, reason string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE requests
SET status = ?, error_reason = ?, updated_at = ?
WHERE request_id = ? AND status = ?`,
		to, reason, time.Now().UTC(), requestID, from,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *SQLiteStore) TryMarkExecuting(ctx context.Context, requestID string, startedAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE requests
SET status = ?, started_at = ?, updated_at = ?
WHERE request_id = ? AND status = ?`,
		model.StatusExecuting, startedAt.UTC(), time.Now().UTC(), requestID, model.StatusApproved,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *SQLiteStore) FinishExecution(ctx context.Context, requestID string, result model.ExecutionResult, errorReason string) error {
	status := model.StatusSucceeded
	if result.TimedOut {
		status = model.StatusExecTimeout
	} else if result.Err != nil || result.ExitCode != 0 {
		status = model.StatusFailed
	}
	timedOut := 0
	if result.TimedOut {
		timedOut = 1
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE requests
SET status = ?, ended_at = ?, updated_at = ?, exit_code = ?, stdout = ?, stderr = ?, timed_out = ?, error_reason = ?
WHERE request_id = ? AND status = ?`,
		status, result.EndedAt.UTC(), time.Now().UTC(), result.ExitCode, result.Stdout, result.Stderr, timedOut, errorReason,
		requestID, model.StatusExecuting,
	)
	return err
}

func (s *SQLiteStore) AddAudit(ctx context.Context, requestID string, eventType string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal audit payload: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_logs(request_id, event_type, event_time, payload)
VALUES(?, ?, ?, ?)`, requestID, eventType, time.Now().UTC(), string(body))
	return err
}

func (s *SQLiteStore) ListPendingApprovals(ctx context.Context) ([]RequestRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT request_id, command, args_json, reason, timeout_sec, normalized, digest, status, created_at, updated_at,
       approval_deadline, approval_id, approval_status, approval_time, approval_reason, started_at, ended_at, exit_code,
       stdout, stderr, timed_out, error_reason
FROM requests WHERE status = ?`, model.StatusPendingApproval)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RequestRecord
	for rows.Next() {
		rec, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func scanRequest(row rowScanner) (RequestRecord, error) {
	var rec RequestRecord
	var argsJSON string
	var status string
	var approvalStatus sql.NullString
	var approvalID sql.NullString
	var approvalTime sql.NullTime
	var startedAt sql.NullTime
	var endedAt sql.NullTime
	var exitCode sql.NullInt64
	var timedOut sql.NullInt64
	var stdout sql.NullString
	var stderr sql.NullString
	var errReason sql.NullString
	var approvalReason sql.NullString
	err := row.Scan(
		&rec.RequestID, &rec.Command, &argsJSON, &rec.Reason, &rec.TimeoutSec, &rec.Normalized, &rec.Digest, &status, &rec.CreatedAt, &rec.UpdatedAt,
		&rec.ApprovalDeadline, &approvalID, &approvalStatus, &approvalTime, &approvalReason, &startedAt, &endedAt, &exitCode,
		&stdout, &stderr, &timedOut, &errReason,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RequestRecord{}, ErrNotFound
		}
		return RequestRecord{}, err
	}
	if err := json.Unmarshal([]byte(argsJSON), &rec.Args); err != nil {
		return RequestRecord{}, fmt.Errorf("unmarshal args: %w", err)
	}
	rec.Status = model.Status(status)
	if approvalID.Valid {
		rec.ApprovalID = approvalID.String
	}
	if approvalStatus.Valid {
		rec.ApprovalStatus = approvalStatus.String
	}
	if approvalTime.Valid {
		t := approvalTime.Time
		rec.ApprovalTime = &t
	}
	if startedAt.Valid {
		t := startedAt.Time
		rec.StartedAt = &t
	}
	if endedAt.Valid {
		t := endedAt.Time
		rec.EndedAt = &t
	}
	if exitCode.Valid {
		rec.ExitCode = int(exitCode.Int64)
	}
	if timedOut.Valid {
		rec.TimedOut = timedOut.Int64 == 1
	}
	if stdout.Valid {
		rec.Stdout = stdout.String
	}
	if stderr.Valid {
		rec.Stderr = stderr.String
	}
	if errReason.Valid {
		rec.ErrorReason = errReason.String
	}
	if approvalReason.Valid {
		rec.ApprovalReason = approvalReason.String
	}
	return rec, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}
