package security

import (
	"testing"

	"host-cmd-bridge/internal/policy"
)

func TestValidateAndDigest_AllowsWhitelistedCommand(t *testing.T) {
	p, err := policy.Compile(policy.FilePolicy{
		Whitelist: []policy.WhitelistTemplate{
			{Command: "/bin/echo", ArgPatterns: []string{`^[a-z]+$`}},
		},
		CommandBlacklist: []string{`(?i)rm`},
		ArgBlacklist:     []string{`(;|\||&&)`},
		MaxArgLength:     100,
		MaxReasonLength:  100,
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	res, err := ValidateAndDigest(p, "/bin/echo", []string{"hello"}, "for test")
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if res.Digest == "" {
		t.Fatalf("digest should not be empty")
	}
	if res.Normalized == "" {
		t.Fatalf("normalized should not be empty")
	}
	if !res.Whitelisted {
		t.Fatalf("expected whitelisted=true")
	}
}

func TestValidateAndDigest_RejectsBlacklistedArg(t *testing.T) {
	p, err := policy.Compile(policy.FilePolicy{
		Whitelist: []policy.WhitelistTemplate{
			{Command: "/bin/echo", ArgPatterns: []string{`^.*$`}},
		},
		ArgBlacklist:    []string{`(;|\||&&)`},
		MaxArgLength:    100,
		MaxReasonLength: 100,
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	_, err = ValidateAndDigest(p, "/bin/echo", []string{"a;b"}, "for test")
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestValidateAndDigest_AllowsNonWhitelistedCommandForApprovalPath(t *testing.T) {
	p, err := policy.Compile(policy.FilePolicy{
		Whitelist: []policy.WhitelistTemplate{
			{Command: "/bin/echo", ArgPatterns: []string{`^[a-z]+$`}},
		},
		CommandBlacklist: []string{`(?i)(^|/)rm$`},
		ArgBlacklist:     []string{`(;|\||&&)`},
		MaxArgLength:     100,
		MaxReasonLength:  100,
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	res, err := ValidateAndDigest(p, "/bin/hostname", []string{}, "for approval")
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if res.Whitelisted {
		t.Fatalf("expected whitelisted=false for non-whitelist command")
	}
}
