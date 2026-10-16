package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"host-cmd-bridge/internal/config"
	"host-cmd-bridge/internal/executor"
	"host-cmd-bridge/internal/httpserver"
	"host-cmd-bridge/internal/httpx"
	"host-cmd-bridge/internal/policy"
	"host-cmd-bridge/internal/service"
	"host-cmd-bridge/internal/socket"
	"host-cmd-bridge/internal/store"
	"host-cmd-bridge/internal/version"
	"host-cmd-bridge/internal/wecom"
)

// fatal 用于真正致命的启动错误：打到 stderr 并退出，便于进程管理器识别为错误。
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	// Go 标准 log 默认输出到 stderr，会把运行期诊断日志也当作错误。
	// 这里把普通运行日志改到 stdout（info 流），stderr 只留给致命错误。
	log.SetOutput(os.Stdout)

	cfgPath := flag.String("config", "./config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("host-cmd-bridge version=%s commit=%s build_time=%s\n", version.Version, version.Commit, version.BuildTime)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("load config failed: %v", err)
	}
	socketMode, err := cfg.Socket.ParseFileMode()
	if err != nil {
		fatal("parse socket file mode failed: %v", err)
	}

	st, err := store.NewSQLiteStore(cfg.Store.SQLitePath)
	if err != nil {
		fatal("init sqlite store failed: %v", err)
	}
	defer st.Close()
	if err := st.Init(context.Background()); err != nil {
		fatal("init sqlite schema failed: %v", err)
	}

	pm, err := policy.NewManager(cfg.Policy.Path, config.DurationSec(cfg.Policy.ReloadIntervalSec))
	if err != nil {
		fatal("init policy manager failed: %v", err)
	}

	execRunner, err := executor.New(cfg.Exec.RunUser)
	if err != nil {
		fatal("init executor failed: %v", err)
	}
	wc := wecom.NewClient(cfg.WeCom)
	if err := wc.WarmupTemplate(context.Background()); err != nil {
		fatal("warmup wecom template failed: %v", err)
	}
	verifier, err := wecom.NewCallbackVerifier(cfg.WeCom.Token, cfg.WeCom.EncodingAESKey, cfg.WeCom.CorpID, config.DurationSec(cfg.Approval.CallbackWindowSec))
	if err != nil {
		fatal("init callback verifier failed: %v", err)
	}

	svc := service.New(cfg, st, pm, wc, execRunner)
	if err := svc.ResumePendingApprovalWatchers(context.Background()); err != nil {
		fatal("resume pending approval watchers failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go pm.Start(ctx, log.Printf)

	socketServer := socket.New(cfg.Socket.Path, socketMode, svc)
	realIPResolver, err := httpx.NewResolver(cfg.HTTP.TrustedProxies, cfg.HTTP.RealIPHeader)
	if err != nil {
		fatal("init real ip resolver failed: %v", err)
	}
	log.Printf("real ip resolver ready %s", realIPResolver.Describe())
	httpServer := httpserver.New(cfg.HTTP.ListenAddr, cfg.HTTP.CallbackPathPrefix, realIPResolver, svc, verifier)

	errCh := make(chan error, 2)
	go func() { errCh <- socketServer.Run(ctx) }()
	go func() { errCh <- httpServer.Run(ctx) }()

	select {
	case <-ctx.Done():
		log.Printf("shutdown requested")
	case err := <-errCh:
		if err != nil {
			fatal("server stopped with error: %v", err)
		}
	}
}
