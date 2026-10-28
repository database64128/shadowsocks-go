package main

import (
	"context"
	"encoding"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
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
  -logLevel <level>       Log level, one of: DEBUG, INFO, WARN, ERROR
  -logFormat <format>     Log format, one of: default, slog-text, slog-json, tint-text
  -logNoColor             Disable colored log output
  -logNoTime              Disable timestamp in log output
`

func runService(name string, args []string) int {
	var (
		fs            flag.FlagSet
		logLevel      slog.Level
		logFormat     tslog.Format
		logNoColor    bool
		logNoTime     bool
		hasLogLevel   bool
		hasLogFormat  bool
		hasLogNoColor bool
		hasLogNoTime  bool
	)

	newOptionalTextValue := func(v encoding.TextUnmarshaler, hasValue *bool) func(string) error {
		return func(s string) error {
			if err := v.UnmarshalText([]byte(s)); err != nil {
				return err
			}
			*hasValue = true
			return nil
		}
	}

	newOptionalBoolValue := func(v, hasValue *bool) func(string) error {
		return func(s string) error {
			parsed, err := strconv.ParseBool(s)
			if err != nil {
				return errors.New("parse error") // align with the flag package
			}
			*v = parsed
			*hasValue = true
			return nil
		}
	}

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageService, name)
	}
	fs.Init(name, flag.ContinueOnError)
	fs.Func("logLevel", "log `level`, one of: DEBUG, INFO, WARN, ERROR", newOptionalTextValue(&logLevel, &hasLogLevel))
	fs.Func("logFormat", "log `format`, one of: default, slog-text, slog-json, tint-text", newOptionalTextValue(&logFormat, &hasLogFormat))
	fs.BoolFunc("logNoColor", "disable colored log output", newOptionalBoolValue(&logNoColor, &hasLogNoColor))
	fs.BoolFunc("logNoTime", "disable timestamp in log output", newOptionalBoolValue(&logNoTime, &hasLogNoTime))
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"config.json"}
	}

	var svcCfg service.Config
	if err := jsoncfg.Load(paths[0], &svcCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file %q: %v\n", paths[0], err)
		return 1
	}

	if len(paths) > 1 {
		var mergeState service.ConfigMergeState
		for _, path := range paths[1:] {
			mergeState.Update(&svcCfg)
			if err := jsoncfg.Load(path, &svcCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load config file %q: %v\n", path, err)
				return 1
			}
		}
		mergeState.Finalize(&svcCfg)
	}

	if hasLogLevel {
		svcCfg.Log.Level = logLevel
	}
	if hasLogFormat {
		svcCfg.Log.Format = logFormat
	}
	if hasLogNoColor {
		svcCfg.Log.NoColor = logNoColor
	}
	if hasLogNoTime {
		svcCfg.Log.NoTime = logNoTime
	}

	logger, err := svcCfg.Log.NewLogger(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		return 1
	}
	logger.Info("shadowsocks-go", slog.String("version", shadowsocks.Version))

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
