package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/database64128/shadowsocks-go"
)

const usage = `A versatile and efficient proxy platform for secure communications

Usage: %s [command]

Commands:
  config      Manage configuration files
  service     Run service
  domain-set  Manage domain set files

Flags:
  -h, --help      Show this help message and exit
  -V, --version   Show version information and exit

Run '%s [command] -h' for more information on a command.
`

func printUsage(name string) {
	fmt.Fprintf(os.Stderr, usage, name, name)
}

func main() {
	var exitCode int
	name, args := os.Args[0], os.Args[1:]
	switch strings.TrimSuffix(filepath.Base(name), ".exe") {
	case "shadowsocks-go-config":
		exitCode = runConfig(name, args)
	case "shadowsocks-go-service":
		exitCode = runService(name, args)
	case "shadowsocks-go-domain-set-converter":
		exitCode = runDomainSetConvert(name, args)
	default:
		if len(args) == 0 {
			printUsage(name)
			exitCode = 2
			break
		}
		command := args[0]
		nameSpaceCommand := name + " " + command
		args = args[1:]
		switch command {
		case "config":
			exitCode = runConfig(nameSpaceCommand, args)
		case "service":
			exitCode = runService(nameSpaceCommand, args)
		case "domain-set":
			exitCode = runDomainSet(nameSpaceCommand, args)
		case "--version", "-version", "-V":
			printVersion()
		case "--help", "-help", "-h":
			printUsage(name)
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %q\nRun '%s -h' for usage.\n", command, name)
			exitCode = 2
		}
	}
	os.Exit(exitCode)
}

func printVersion() {
	os.Stdout.WriteString("shadowsocks-go " + shadowsocks.Version + "\n")
	if info, ok := debug.ReadBuildInfo(); ok {
		os.Stdout.WriteString(info.String())
	}
}
