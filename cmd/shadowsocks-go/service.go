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
  -logLevel <level>   Log level, one of: DEBUG, INFO, WARN, ERROR (default: INFO)
  -logNoColor         Disable colored log output
  -logNoTime          Disable timestamp in log output
  -logKVPairs         Format logs as key=value pairs
  -logJSON            Format logs as line-delimited JSON
`

func runService(name string, args []string) int {
	var (
		fs         flag.FlagSet
		logLevel   slog.Level
		logNoColor = defaultLogNoColor
		logNoTime  bool
		logKVPairs bool
		logJSON    bool
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageService, name)
	}
	fs.Init(name, flag.ContinueOnError)
	fs.TextVar(&logLevel, "logLevel", slog.LevelInfo, "log `level`, one of: DEBUG, INFO, WARN, ERROR")
	fs.BoolVar(&logNoColor, "logNoColor", defaultLogNoColor, "disable colored log output")
	fs.BoolVar(&logNoTime, "logNoTime", false, "disable timestamp in log output")
	fs.BoolVar(&logKVPairs, "logKVPairs", false, "format logs as key=value pairs")
	fs.BoolVar(&logJSON, "logJSON", false, "format logs as line-delimited JSON")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	logCfg := tslog.Config{
		Level:          logLevel,
		NoColor:        logNoColor,
		NoTime:         logNoTime,
		UseTextHandler: logKVPairs,
		UseJSONHandler: logJSON,
	}
	logger := logCfg.NewLogger(os.Stderr)
	logger.Info("shadowsocks-go", slog.String("version", shadowsocks.Version))

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"config.json"}
	}

	var svcCfg service.Config
	for _, path := range paths {
		if err := jsoncfg.Load(path, &svcCfg); err != nil {
			logger.Error("Failed to load config",
				slog.String("path", path),
				tslog.Err(err),
			)
			return 1
		}
	}

	m, err := svcCfg.Manager(logger)
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
