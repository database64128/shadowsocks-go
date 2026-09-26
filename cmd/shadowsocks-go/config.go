package main

import (
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
`

func runConfig(name string, args []string) int {
	var (
		fs     flag.FlagSet
		format bool
		test   bool
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageConfig, name)
	}
	fs.Init(name, flag.ContinueOnError)
	fs.BoolVar(&format, "format", false, "format the config files")
	fs.BoolVar(&test, "test", false, "test the config files")
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

	logCfg := tslog.Config{
		Level:   slog.LevelInfo,
		NoColor: defaultLogNoColor,
	}
	logger := logCfg.NewLogger(os.Stderr)

	var svcCfg service.Config
	if !processConfigFile(paths[0], &svcCfg, logger, format) {
		return 1
	}
	for _, path := range paths[1:] {
		var otherCfg service.Config
		if !processConfigFile(path, &otherCfg, logger, format) {
			return 1
		}
		svcCfg.Merge(&otherCfg)
	}

	if test {
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

func processConfigFile(path string, svcCfg *service.Config, logger *tslog.Logger, format bool) bool {
	if err := jsoncfg.Load(path, svcCfg); err != nil {
		logger.Error("Failed to load config file", slog.String("path", path), tslog.Err(err))
		return false
	}

	if format {
		svcCfg.Migrate()
		if err := jsoncfg.Save(path, svcCfg); err != nil {
			logger.Error("Failed to save config file", slog.String("path", path), tslog.Err(err))
			return false
		}
		logger.Info("Formatted config file", slog.String("path", path))
	}

	return true
}
