package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"host-cmd-bridge/internal/policy"
)

var (
	ErrCommandNotWhitelisted = errors.New("command is not whitelisted")
	ErrCommandBlacklisted    = errors.New("command is blacklisted")
	ErrArgBlacklisted        = errors.New("arg is blacklisted")
	ErrArgInvalid            = errors.New("arg contains disallowed characters")
	ErrArgTooLong            = errors.New("arg is too long")
	ErrReasonTooLong         = errors.New("reason too long")
)

type ValidationResult struct {
	Normalized  string
	Digest      string
	Whitelisted bool
}

func ValidateAndDigest(p *policy.Compiled, command string, args []string, reason string) (ValidationResult, error) {
	raw := p.Raw()
	if len(reason) > raw.MaxReasonLength {
		return ValidationResult{}, ErrReasonTooLong
	}
	if p.IsCommandBlacklisted(command) {
		return ValidationResult{}, ErrCommandBlacklisted
	}

	for _, arg := range args {
		if len(arg) > raw.MaxArgLength {
			return ValidationResult{}, fmt.Errorf("%w: %q", ErrArgTooLong, arg)
		}
		if !p.IsArgAllowed(arg) {
			return ValidationResult{}, fmt.Errorf("%w: %q", ErrArgInvalid, arg)
		}
		if p.IsArgBlacklisted(arg) {
			return ValidationResult{}, fmt.Errorf("%w: %q", ErrArgBlacklisted, arg)
		}
	}

	normalized := Normalize(command, args)
	d := sha256.Sum256([]byte(normalized))
	return ValidationResult{
		Normalized:  normalized,
		Digest:      hex.EncodeToString(d[:]),
		Whitelisted: p.MatchWhitelist(command, args),
	}, nil
}

func Normalize(command string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, strings.TrimSpace(command))
	for _, a := range args {
		parts = append(parts, strings.TrimSpace(a))
	}
	return strings.Join(parts, "\x1f")
}
