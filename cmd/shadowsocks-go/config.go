package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/database64128/shadowsocks-go/jsoncfg"
	"github.com/database64128/shadowsocks-go/service"
	"go.uber.org/zap"
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
	fs.Init(name, flag.ExitOnError)
	fs.BoolVar(&format, "format", false, "format the config files")
	fs.BoolVar(&test, "test", false, "test the config files")
	fs.Parse(args)

	if !format && !test {
		fmt.Fprintf(fs.Output(), "Please specify at least one of -format or -test\nRun '%s -h' for usage.\n", name)
		return 2
	}

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"config.json"}
	}

	var exitCode int
	for _, path := range paths {
		if !processConfigFile(path, format, test) {
			exitCode = 1
		}
	}
	return exitCode
}

func processConfigFile(path string, format bool, test bool) bool {
	var svcCfg service.Config
	if err := jsoncfg.Load(path, &svcCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file %q: %v\n", path, err)
		return false
	}

	if format {
		svcCfg.Migrate()
		if err := jsoncfg.Save(path, &svcCfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save config file %q: %v\n", path, err)
			return false
		}
		fmt.Printf("Formatted config file %q\n", path)
	}

	if test {
		m, err := svcCfg.Manager(zap.NewNop())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid config file %q: %v\n", path, err)
			return false
		}
		m.Close()
		fmt.Printf("Config file %q is valid\n", path)
	}

	return true
}
