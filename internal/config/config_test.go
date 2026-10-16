package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppliesDefaultSocketPath(t *testing.T) {
	t.Parallel()

	cfgPath := writeTempConfig(t, `
http:
  listen_addr: ":18080"
store:
  sqlite_path: ./data/test.db
exec:
  max_concurrent: 1
approval:
  timeout_sec: 60
wecom:
  corp_id: "corp"
  corp_secret: "secret"
  template_id: "tpl"
  creator_user_id: "zhangsan"
  token: "token"
  encoding_aes_key: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
policy:
  path: ./policy.yaml
`)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Socket.Path != defaultSocketPath() {
		t.Fatalf("default socket path mismatch: got %q want %q", cfg.Socket.Path, defaultSocketPath())
	}
	if cfg.Socket.FileMode != "0666" {
		t.Fatalf("default socket file_mode mismatch: got %q want %q", cfg.Socket.FileMode, "0666")
	}
	mode, err := cfg.Socket.ParseFileMode()
	if err != nil {
		t.Fatalf("ParseFileMode() error = %v", err)
	}
	if mode != 0o666 {
		t.Fatalf("default socket mode mismatch: got %#o want %#o", mode, os.FileMode(0o666))
	}
}

func TestLoadKeepsExplicitSocketPath(t *testing.T) {
	t.Parallel()

	cfgPath := writeTempConfig(t, `
socket:
  path: /tmp/custom.sock
  file_mode: "0660"
http:
  listen_addr: ":18080"
store:
  sqlite_path: ./data/test.db
exec:
  max_concurrent: 1
approval:
  timeout_sec: 60
wecom:
  corp_id: "corp"
  corp_secret: "secret"
  template_id: "tpl"
  creator_user_id: "zhangsan"
  token: "token"
  encoding_aes_key: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
policy:
  path: ./policy.yaml
`)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Socket.Path != "/tmp/custom.sock" {
		t.Fatalf("explicit socket path changed: got %q", cfg.Socket.Path)
	}
	if cfg.Socket.FileMode != "0660" {
		t.Fatalf("explicit socket file_mode changed: got %q", cfg.Socket.FileMode)
	}
	mode, err := cfg.Socket.ParseFileMode()
	if err != nil {
		t.Fatalf("ParseFileMode() error = %v", err)
	}
	if mode != 0o660 {
		t.Fatalf("explicit socket mode mismatch: got %#o want %#o", mode, os.FileMode(0o660))
	}
}

func TestLoadRejectsInvalidSocketFileMode(t *testing.T) {
	t.Parallel()

	cfgPath := writeTempConfig(t, `
socket:
  file_mode: "not-octal"
http:
  listen_addr: ":18080"
store:
  sqlite_path: ./data/test.db
exec:
  max_concurrent: 1
approval:
  timeout_sec: 60
wecom:
  corp_id: "corp"
  corp_secret: "secret"
  template_id: "tpl"
  creator_user_id: "zhangsan"
  token: "token"
  encoding_aes_key: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
policy:
  path: ./policy.yaml
`)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatalf("Load() expected error for invalid socket.file_mode, got nil")
	}
}

const minimalConfigBody = `
http:
  listen_addr: ":18080"
store:
  sqlite_path: ./data/test.db
exec:
  max_concurrent: 1
approval:
  timeout_sec: 60
wecom:
  corp_id: "corp"
  corp_secret: "secret"
  template_id: "tpl"
  creator_user_id: "zhangsan"
  token: "token"
  encoding_aes_key: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
policy:
  path: ./policy.yaml
`

func TestLoadAppliesRealIPDefaults(t *testing.T) {
	t.Parallel()

	cfgPath := writeTempConfig(t, minimalConfigBody)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.HTTP.TrustedProxies) != 2 || cfg.HTTP.TrustedProxies[0] != "127.0.0.1/32" {
		t.Fatalf("default trusted_proxies mismatch: got %v", cfg.HTTP.TrustedProxies)
	}
	if cfg.HTTP.RealIPHeader != "auto" {
		t.Fatalf("default real_ip_header mismatch: got %q want %q", cfg.HTTP.RealIPHeader, "auto")
	}
}

func TestLoadKeepsExplicitProxyConfig(t *testing.T) {
	t.Parallel()

	cfgPath := writeTempConfig(t, `
http:
  listen_addr: ":18080"
  trusted_proxies: ["172.17.0.1/32", "private"]
  real_ip_header: "cf-connecting-ip"
store:
  sqlite_path: ./data/test.db
exec:
  max_concurrent: 1
approval:
  timeout_sec: 60
wecom:
  corp_id: "corp"
  corp_secret: "secret"
  template_id: "tpl"
  creator_user_id: "zhangsan"
  token: "token"
  encoding_aes_key: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
policy:
  path: ./policy.yaml
`)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.HTTP.TrustedProxies) != 2 || cfg.HTTP.TrustedProxies[0] != "172.17.0.1/32" {
		t.Fatalf("explicit trusted_proxies changed: got %v", cfg.HTTP.TrustedProxies)
	}
	if cfg.HTTP.RealIPHeader != "cf-connecting-ip" {
		t.Fatalf("explicit real_ip_header changed: got %q", cfg.HTTP.RealIPHeader)
	}
}

func TestLoadRejectsInvalidProxyConfig(t *testing.T) {
	t.Parallel()

	badProxy := strings.Replace(minimalConfigBody, "http:\n  listen_addr: \":18080\"", "http:\n  listen_addr: \":18080\"\n  trusted_proxies: [\"10.0.0.0/33\"]", 1)
	if _, err := Load(writeTempConfig(t, badProxy)); err == nil {
		t.Fatalf("Load() expected error for invalid trusted_proxies CIDR")
	}

	badHeader := strings.Replace(minimalConfigBody, "http:\n  listen_addr: \":18080\"", "http:\n  listen_addr: \":18080\"\n  real_ip_header: \"x-client-ip\"", 1)
	if _, err := Load(writeTempConfig(t, badHeader)); err == nil {
		t.Fatalf("Load() expected error for unsupported real_ip_header")
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}
