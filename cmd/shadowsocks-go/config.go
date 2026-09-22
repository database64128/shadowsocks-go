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

	var exitCode int
	for _, path := range paths {
		if !processConfigFile(logger, path, format, test) {
			exitCode = 1
		}
	}
	return exitCode
}

func processConfigFile(logger *tslog.Logger, path string, format bool, test bool) bool {
	var svcCfg service.Config
	if err := jsoncfg.Load(path, &svcCfg); err != nil {
		logger.Error("Failed to load config file", slog.String("path", path), tslog.Err(err))
		return false
	}

	if format {
		svcCfg.Migrate()
		if err := jsoncfg.Save(path, &svcCfg); err != nil {
			logger.Error("Failed to save config file", slog.String("path", path), tslog.Err(err))
			return false
		}
		logger.Info("Formatted config file", slog.String("path", path))
	}

	if test {
		m, err := svcCfg.Manager(logger)
		if err != nil {
			logger.Error("Invalid config file", slog.String("path", path), tslog.Err(err))
			return false
		}
		m.Close()
		logger.Info("Config file is valid", slog.String("path", path))
	}

	return true
}
