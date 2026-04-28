package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type FilePolicy struct {
	Whitelist            []WhitelistTemplate `yaml:"whitelist" json:"whitelist"`
	CommandBlacklist     []string            `yaml:"command_blacklist" json:"command_blacklist"`
	ArgBlacklist         []string            `yaml:"arg_blacklist" json:"arg_blacklist"`
	AutoApproveWhitelist bool                `yaml:"auto_approve_whitelist" json:"auto_approve_whitelist"`
	MaxArgLength         int                 `yaml:"max_arg_length" json:"max_arg_length"`
	MaxReasonLength      int                 `yaml:"max_reason_length" json:"max_reason_length"`
	AllowedArgPattern    string              `yaml:"allowed_arg_pattern" json:"allowed_arg_pattern"`
}

type WhitelistTemplate struct {
	Command     string   `yaml:"command" json:"command"`
	ArgPatterns []string `yaml:"arg_patterns" json:"arg_patterns"`
}

type Compiled struct {
	raw                FilePolicy
	commandBlacklistRE []*regexp.Regexp
	argBlacklistRE     []*regexp.Regexp
	allowedArgRE       *regexp.Regexp
	whitelistCompiled  []compiledTemplate
}

type compiledTemplate struct {
	command string
	args    []*regexp.Regexp
}

func (c *Compiled) Raw() FilePolicy {
	return c.raw
}

func (c *Compiled) MatchWhitelist(command string, args []string) bool {
	for _, t := range c.whitelistCompiled {
		if t.command != command {
			continue
		}
		if len(t.args) != len(args) {
			continue
		}
		ok := true
		for i := range args {
			if !t.args[i].MatchString(args[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (c *Compiled) IsCommandBlacklisted(command string) bool {
	for _, re := range c.commandBlacklistRE {
		if re.MatchString(command) {
			return true
		}
	}
	return false
}

func (c *Compiled) IsArgBlacklisted(arg string) bool {
	for _, re := range c.argBlacklistRE {
		if re.MatchString(arg) {
			return true
		}
	}
	return false
}

func (c *Compiled) IsArgAllowed(arg string) bool {
	if c.allowedArgRE == nil {
		return true
	}
	return c.allowedArgRE.MatchString(arg)
}

func Load(path string) (*Compiled, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	var p FilePolicy
	if err := yaml.Unmarshal(b, &p); err != nil {
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("parse policy: %w", err)
		}
	}
	applyDefaults(&p)
	return Compile(p)
}

func Compile(p FilePolicy) (*Compiled, error) {
	cp := &Compiled{raw: p}
	for _, r := range p.CommandBlacklist {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid command_blacklist regex %q: %w", r, err)
		}
		cp.commandBlacklistRE = append(cp.commandBlacklistRE, re)
	}
	for _, r := range p.ArgBlacklist {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid arg_blacklist regex %q: %w", r, err)
		}
		cp.argBlacklistRE = append(cp.argBlacklistRE, re)
	}
	if p.AllowedArgPattern != "" {
		re, err := regexp.Compile(p.AllowedArgPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed_arg_pattern regex: %w", err)
		}
		cp.allowedArgRE = re
	}

	for _, t := range p.Whitelist {
		if t.Command == "" {
			return nil, fmt.Errorf("whitelist command cannot be empty")
		}
		ct := compiledTemplate{command: t.Command}
		for _, ap := range t.ArgPatterns {
			re, err := regexp.Compile(ap)
			if err != nil {
				return nil, fmt.Errorf("invalid whitelist arg regex %q: %w", ap, err)
			}
			ct.args = append(ct.args, re)
		}
		cp.whitelistCompiled = append(cp.whitelistCompiled, ct)
	}

	return cp, nil
}

func applyDefaults(p *FilePolicy) {
	if p.MaxArgLength <= 0 {
		p.MaxArgLength = 256
	}
	if p.MaxReasonLength <= 0 {
		p.MaxReasonLength = 1024
	}
	if p.AllowedArgPattern == "" {
		p.AllowedArgPattern = `^[a-zA-Z0-9._/:=@,+-]+$`
	}
}

type Manager struct {
	path     string
	interval time.Duration

	mu      sync.RWMutex
	current *Compiled
	modTime time.Time
}

func NewManager(path string, interval time.Duration) (*Manager, error) {
	cp, err := Load(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat policy: %w", err)
	}
	return &Manager{path: path, interval: interval, current: cp, modTime: st.ModTime()}, nil
}

func (m *Manager) Get() *Compiled {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *Manager) Start(ctx context.Context, logf func(string, ...any)) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.reloadIfChanged(logf); err != nil && logf != nil {
				logf("policy reload failed: %v", err)
			}
		}
	}
}

func (m *Manager) reloadIfChanged(logf func(string, ...any)) error {
	st, err := os.Stat(m.path)
	if err != nil {
		return fmt.Errorf("stat policy: %w", err)
	}
	if !st.ModTime().After(m.modTime) {
		return nil
	}
	cp, err := Load(m.path)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.current = cp
	m.modTime = st.ModTime()
	m.mu.Unlock()

	if logf != nil {
		logf("policy reloaded from %s", m.path)
	}
	return nil
}
