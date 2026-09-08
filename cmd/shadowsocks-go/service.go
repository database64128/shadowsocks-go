package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/service"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const usageService = `Run service

Usage: %s [options] [path]...

Arguments:
  [path]...   Paths to the config files (default: "config.json")

Flags:
  -zapConf    Preset name or path to the JSON config file for building the zap logger (default: "console")
              Available presets: console, console-nocolor, console-notime, systemd, production, development
  -logLevel   Log level for the console and systemd presets (default: info)
              Available levels: debug, info, warn, error, dpanic, panic, fatal
`

func runService(name string, args []string) int {
	var (
		fs       flag.FlagSet
		zapConf  string
		logLevel zapcore.Level
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageService, name)
	}
	fs.Init(name, flag.ExitOnError)
	fs.StringVar(&zapConf, "zapConf", "console", "preset name or path to the JSON config file for building the zap logger\navailable presets: console, console-nocolor, console-notime, systemd, production, development")
	fs.TextVar(&logLevel, "logLevel", zapcore.InfoLevel, "log `level` for the console and systemd presets\navailable levels: debug, info, warn, error, dpanic, panic, fatal")
	fs.Parse(args)

	logger, err := logging.NewZapLogger(zapConf, logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to build logger:", err)
		return 1
	}
	defer logger.Sync()

	logger.Info("shadowsocks-go", zap.String("version", shadowsocks.Version))

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"config.json"}
	}

	var svcCfg service.Config
	for _, path := range paths {
		if err = jsoncfg.Load(path, &svcCfg); err != nil {
			logger.Error("Failed to load config",
				zap.String("path", path),
				zap.Error(err),
			)
			return 1
		}
	}

	m, err := svcCfg.Manager(logger)
	if err != nil {
		logger.Error("Failed to create service manager", zap.Error(err))
		return 1
	}
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("Received exit signal", zap.Stringer("signal", sig))
		signal.Stop(sigCh)
		cancel()
	}()

	if !m.Run(ctx) {
		return 1
	}
	return 0
}
