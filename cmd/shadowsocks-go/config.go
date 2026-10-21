package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/service"
	"github.com/database64128/shadowsocks-go/tslog"
)

const usageConfig = `Manage configuration files

Usage: %s [-format] [-test] [path]...

Arguments:
  [path]...   Paths to the config files (default: "config.json")

Flags:
  -format     Format the config files
  -test       Test the config files

Logging Flags:
  -logLevel <level>       Log level, one of: DEBUG, INFO, WARN, ERROR (default: INFO)
  -logFormat <format>     Log format, one of: default, slog-text, slog-json, tint-text
  -logNoColor             Disable colored log output
  -logNoTime              Disable timestamp in log output
`

func runConfig(name string, args []string) int {
	var (
		fs     flag.FlagSet
		format bool
		test   bool
		logCfg tslog.Config
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageConfig, name)
	}
	fs.Init(name, flag.ContinueOnError)
	fs.BoolVar(&format, "format", false, "format the config files")
	fs.BoolVar(&test, "test", false, "test the config files")
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

	if !format && !test {
		fmt.Fprintf(fs.Output(), "Please specify at least one of -format or -test\nRun '%s -h' for usage.\n", name)
		return 2
	}

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"config.json"}
	}

	logger := logCfg.NewLogger(os.Stderr)

	if format {
		for _, path := range paths {
			if !formatConfigFile(path, logger) {
				return 1
			}
		}
	}

	if test {
		var svcCfg service.Config
		if err := jsoncfg.Load(paths[0], &svcCfg); err != nil {
			logger.Error("Failed to load config file", slog.String("path", paths[0]), tslog.Err(err))
			return 1
		}

		if len(paths) > 1 {
			var mergeState service.ConfigMergeState
			for _, path := range paths[1:] {
				mergeState.Update(&svcCfg)
				if err := jsoncfg.Load(path, &svcCfg); err != nil {
					logger.Error("Failed to load config file", slog.String("path", path), tslog.Err(err))
					return 1
				}
			}
			mergeState.Finalize(&svcCfg)
		}

		m, err := svcCfg.NewManager(logger)
		if err != nil {
			logger.Error("Config test failed", tslog.Err(err))
			return 1
		}
		m.Close()
		logger.Info("Config test passed")
	}

	return 0
}

func formatConfigFile(path string, logger *tslog.Logger) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		logger.Error("Failed to open config file", slog.String("path", path), tslog.Err(err))
		return false
	}
	defer f.Close()

	var svcCfg service.Config
	if err := json.UnmarshalRead(f, &svcCfg, json.RejectUnknownMembers(true)); err != nil {
		logger.Error("Failed to unmarshal config file", slog.String("path", path), tslog.Err(err))
		return false
	}

	svcCfg.Migrate()

	if err := f.Truncate(0); err != nil {
		logger.Error("Failed to truncate config file", slog.String("path", path), tslog.Err(err))
		return false
	}
	if _, err := f.Seek(0, 0); err != nil {
		logger.Error("Failed to seek to start of config file", slog.String("path", path), tslog.Err(err))
		return false
	}
	if err := json.MarshalWrite(f, &svcCfg, jsontext.Multiline(true)); err != nil {
		logger.Error("Failed to marshal config file", slog.String("path", path), tslog.Err(err))
		return false
	}

	logger.Info("Formatted config file", slog.String("path", path))
	return true
}
