package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Socket   SocketConfig        `yaml:"socket" json:"socket"`
	HTTP     HTTPConfig          `yaml:"http" json:"http"`
	Store    StoreConfig         `yaml:"store" json:"store"`
	Exec     ExecConfig          `yaml:"exec" json:"exec"`
	Approval ApprovalConfig      `yaml:"approval" json:"approval"`
	WeCom    WeComConfig         `yaml:"wecom" json:"wecom"`
	Policy   PolicyRuntimeConfig `yaml:"policy" json:"policy"`
}

type SocketConfig struct {
	Path     string `yaml:"path" json:"path"`
	FileMode string `yaml:"file_mode" json:"file_mode"`
}

type HTTPConfig struct {
	ListenAddr         string `yaml:"listen_addr" json:"listen_addr"`
	CallbackPathPrefix string `yaml:"callback_path_prefix" json:"callback_path_prefix"`
}

type StoreConfig struct {
	SQLitePath string `yaml:"sqlite_path" json:"sqlite_path"`
}

type ExecConfig struct {
	MaxConcurrent int    `yaml:"max_concurrent" json:"max_concurrent"`
	MaxTimeoutSec int    `yaml:"max_timeout_sec" json:"max_timeout_sec"`
	RunUser       string `yaml:"run_user" json:"run_user"`
}

type ApprovalConfig struct {
	TimeoutSec        int `yaml:"timeout_sec" json:"timeout_sec"`
	CallbackWindowSec int `yaml:"callback_window_sec" json:"callback_window_sec"`
}

type WeComConfig struct {
	CorpID          string           `yaml:"corp_id" json:"corp_id"`
	CorpSecret      string           `yaml:"corp_secret" json:"corp_secret"`
	AgentID         int              `yaml:"agent_id" json:"agent_id"`
	TemplateID      string           `yaml:"template_id" json:"template_id"`
	CreatorUserID   string           `yaml:"creator_user_id" json:"creator_user_id"`
	ApproverUserIDs []string         `yaml:"approver_user_ids" json:"approver_user_ids"`
	Token           string           `yaml:"token" json:"token"`
	EncodingAESKey  string           `yaml:"encoding_aes_key" json:"encoding_aes_key"`
	APIBaseURL      string           `yaml:"api_base_url" json:"api_base_url"`
	FieldTitles     WeComFieldTitles `yaml:"field_titles" json:"field_titles"`
}

type WeComFieldTitles struct {
	RequestID  string `yaml:"request_id" json:"request_id"`
	Command    string `yaml:"command" json:"command"`
	Args       string `yaml:"args" json:"args"`
	Reason     string `yaml:"reason" json:"reason"`
	TimeoutSec string `yaml:"timeout_sec" json:"timeout_sec"`
	Digest     string `yaml:"digest" json:"digest"`
}

type PolicyRuntimeConfig struct {
	Path              string `yaml:"path" json:"path"`
	ReloadIntervalSec int    `yaml:"reload_interval_sec" json:"reload_interval_sec"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config: %w", err)
		}
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Socket.Path == "" {
		c.Socket.Path = defaultSocketPath()
	}
	if c.Socket.FileMode == "" {
		c.Socket.FileMode = "0666"
	}
	if c.HTTP.ListenAddr == "" {
		c.HTTP.ListenAddr = ":8080"
	}
	if c.HTTP.CallbackPathPrefix == "" {
		c.HTTP.CallbackPathPrefix = "/wecom/callback"
	}
	if c.Store.SQLitePath == "" {
		c.Store.SQLitePath = "./data/hostcmd.db"
	}
	if c.Exec.MaxConcurrent <= 0 {
		c.Exec.MaxConcurrent = 2
	}
	if c.Exec.MaxTimeoutSec <= 0 {
		c.Exec.MaxTimeoutSec = 180
	}
	if c.Approval.TimeoutSec <= 0 {
		c.Approval.TimeoutSec = 600
	}
	if c.Approval.CallbackWindowSec <= 0 {
		c.Approval.CallbackWindowSec = 300
	}
	if c.Policy.ReloadIntervalSec <= 0 {
		c.Policy.ReloadIntervalSec = 2
	}
	if c.WeCom.APIBaseURL == "" {
		c.WeCom.APIBaseURL = "https://qyapi.weixin.qq.com"
	}
	if c.WeCom.FieldTitles.RequestID == "" {
		c.WeCom.FieldTitles.RequestID = "请求ID"
	}
	if c.WeCom.FieldTitles.Command == "" {
		c.WeCom.FieldTitles.Command = "执行命令"
	}
	if c.WeCom.FieldTitles.Args == "" {
		c.WeCom.FieldTitles.Args = "命令参数"
	}
	if c.WeCom.FieldTitles.Reason == "" {
		c.WeCom.FieldTitles.Reason = "执行原因"
	}
	if c.WeCom.FieldTitles.TimeoutSec == "" {
		c.WeCom.FieldTitles.TimeoutSec = "超时时间(秒)"
	}
	if c.WeCom.FieldTitles.Digest == "" {
		c.WeCom.FieldTitles.Digest = "命令摘要"
	}
}

func defaultSocketPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "./containerskill/host-cmd-bridge/hostcmd.sock"
	}
	exeDir := filepath.Dir(exePath)
	return filepath.Join(exeDir, "containerskill", "host-cmd-bridge", "hostcmd.sock")
}

func (c Config) validate() error {
	if c.Store.SQLitePath == "" {
		return fmt.Errorf("store.sqlite_path is required")
	}
	if c.Socket.Path == "" {
		return fmt.Errorf("socket.path is required")
	}
	if _, err := c.Socket.ParseFileMode(); err != nil {
		return err
	}
	if c.Policy.Path == "" {
		return fmt.Errorf("policy.path is required")
	}
	if c.WeCom.CorpID == "" || c.WeCom.CorpSecret == "" {
		return fmt.Errorf("wecom.corp_id and wecom.corp_secret are required")
	}
	if c.WeCom.TemplateID == "" || c.WeCom.CreatorUserID == "" {
		return fmt.Errorf("wecom.template_id and wecom.creator_user_id are required")
	}
	if c.WeCom.Token == "" || c.WeCom.EncodingAESKey == "" {
		return fmt.Errorf("wecom.token and wecom.encoding_aes_key are required")
	}
	return nil
}

func (s SocketConfig) ParseFileMode() (os.FileMode, error) {
	modeStr := strings.TrimSpace(s.FileMode)
	if modeStr == "" {
		modeStr = "0666"
	}
	v, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("socket.file_mode must be octal (e.g. 0666), got %q", s.FileMode)
	}
	return os.FileMode(v), nil
}

type Dynamic[T any] struct {
	v atomic.Value
}

func NewDynamic[T any](t T) *Dynamic[T] {
	d := &Dynamic[T]{}
	d.v.Store(t)
	return d
}

func (d *Dynamic[T]) Get() T {
	return d.v.Load().(T)
}

func (d *Dynamic[T]) Set(v T) {
	d.v.Store(v)
}

func DurationSec(sec int) time.Duration {
	return time.Duration(sec) * time.Second
}
