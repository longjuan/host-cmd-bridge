package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"host-cmd-bridge/internal/model"
)

type Executor struct {
	runUser string
	uid     *uint32
	gid     *uint32
}

func New(runUser string) (*Executor, error) {
	e := &Executor{runUser: runUser}
	if runUser == "" {
		return e, nil
	}
	u, err := user.Lookup(runUser)
	if err != nil {
		return nil, fmt.Errorf("lookup run user %q: %w", runUser, err)
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse uid: %w", err)
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse gid: %w", err)
	}
	uid := uint32(uid64)
	gid := uint32(gid64)
	e.uid = &uid
	e.gid = &gid
	return e, nil
}

func (e *Executor) Run(parent context.Context, command string, args []string, timeoutSec int) model.ExecutionResult {
	startedAt := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if e.uid != nil && e.gid != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: *e.uid, Gid: *e.gid}
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		now := time.Now().UTC()
		return model.ExecutionResult{
			StartedAt: startedAt,
			EndedAt:   now,
			Err:       fmt.Errorf("start command: %w", err),
			Stderr:    stderrBuf.String(),
		}
	}

	done := make(chan struct{})
	go func(pid int) {
		defer close(done)
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}(cmd.Process.Pid)

	waitErr := cmd.Wait()
	timedOut := ctx.Err() == context.DeadlineExceeded
	cancel()
	<-done

	res := model.ExecutionResult{
		StartedAt: startedAt,
		EndedAt:   time.Now().UTC(),
		Stdout:    stdoutBuf.String(),
		Stderr:    stderrBuf.String(),
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	res.TimedOut = timedOut
	if waitErr != nil {
		res.Err = waitErr
	}
	return res
}
