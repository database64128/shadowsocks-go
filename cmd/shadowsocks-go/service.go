package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/service"
	"github.com/database64128/shadowsocks-go/tslog"
)

const usageService = `Run service

Usage: %s [options] [path]...

Arguments:
  [path]...   Paths to the config files (default: "config.json")

Logging Flags:
  -logLevel <level>       Log level, one of: DEBUG, INFO, WARN, ERROR (default: INFO)
  -logFormat <format>     Log format, one of: default, slog-text, slog-json, tint-text
  -logNoColor             Disable colored log output
  -logNoTime              Disable timestamp in log output
`

func runService(name string, args []string) int {
	var (
		fs     flag.FlagSet
		logCfg tslog.Config
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageService, name)
	}
	fs.Init(name, flag.ContinueOnError)
	fs.TextVar(&logCfg.Level, "logLevel", slog.LevelInfo, "log `level`, one of: DEBUG, INFO, WARN, ERROR")
	fs.TextVar(&logCfg.Format, "logFormat", tslog.FormatDefault, "log `format`, one of: default, slog-text, slog-json, tint-text")
	fs.BoolVar(&logCfg.NoColor, "logNoColor", defaultLogNoColor, "disable colored log output")
	fs.BoolVar(&logCfg.NoTime, "logNoTime", false, "disable timestamp in log output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	logger := logCfg.NewLogger(os.Stderr)
	logger.Info("shadowsocks-go", slog.String("version", shadowsocks.Version))

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"config.json"}
	}

	var svcCfg service.Config
	if err := jsoncfg.Load(paths[0], &svcCfg); err != nil {
		logger.Error("Failed to load config",
			slog.String("path", paths[0]),
			tslog.Err(err),
		)
		return 1
	}
	for _, path := range paths[1:] {
		var otherCfg service.Config
		if err := jsoncfg.Load(path, &otherCfg); err != nil {
			logger.Error("Failed to load config",
				slog.String("path", path),
				tslog.Err(err),
			)
			return 1
		}
		svcCfg.Merge(&otherCfg)
	}

	m, err := svcCfg.NewManager(logger)
	if err != nil {
		logger.Error("Failed to create service manager", tslog.Err(err))
		return 1
	}
	defer m.Close()

	ctx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	stopAF := context.AfterFunc(ctx, func() {
		stopSig()
	})
	defer func() {
		if stopAF() {
			stopSig()
		}
	}()

	if !m.Run(ctx) {
		return 1
	}
	return 0
}
