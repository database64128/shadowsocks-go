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

func runService(name string, args []string) int {
	var (
		fs       flag.FlagSet
		confPath string
		zapConf  string
		logLevel zapcore.Level
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Run service\n\nUsage of %s:\n", name)
		fs.PrintDefaults()
	}
	fs.Init(name, flag.ExitOnError)
	fs.StringVar(&confPath, "confPath", "config.json", "`path` to the JSON configuration file")
	fs.StringVar(&zapConf, "zapConf", "console", "preset name or path to the JSON configuration file for building the zap logger\navailable presets: console, console-nocolor, console-notime, systemd, production, development")
	fs.TextVar(&logLevel, "logLevel", zapcore.InfoLevel, "log `level` for the console and systemd presets\navailable levels: debug, info, warn, error, dpanic, panic, fatal")
	fs.Parse(args)

	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "Unexpected arguments: %v\nRun '%s -h' for usage.\n", fs.Args(), name)
		return 2
	}

	logger, err := logging.NewZapLogger(zapConf, logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to build logger:", err)
		return 1
	}
	defer logger.Sync()

	logger.Info("shadowsocks-go", zap.String("version", shadowsocks.Version))

	var sc service.Config
	if err = jsoncfg.Load(confPath, &sc); err != nil {
		logger.Error("Failed to load config",
			zap.String("confPath", confPath),
			zap.Error(err),
		)
		return 1
	}

	m, err := sc.Manager(logger)
	if err != nil {
		logger.Error("Failed to create service manager",
			zap.String("confPath", confPath),
			zap.Error(err),
		)
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
