package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"

	"github.com/database64128/shadowsocks-go/prefixset"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/worker"
	"github.com/gaissmai/bart"
)

const usagePrefixSet = `Manage prefix set files

Usage: %s [command]

Commands:
  convert     Convert prefix set files between different formats

Run '%s [command] -h' for more information on a command.
`

func printUsagePrefixSet(name string) {
	fmt.Fprintf(os.Stderr, usagePrefixSet, name, name)
}

func runPrefixSet(name string, args []string) int {
	if len(args) == 0 {
		printUsagePrefixSet(name)
		return 2
	}
	switch args[0] {
	case "convert":
		return runPrefixSetConvert(name+" "+"convert", args[1:])
	case "--help", "-help", "-h":
		printUsagePrefixSet(name)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %q\nRun '%s -h' for usage.\n", args[0], name)
		return 2
	}
}

const usagePrefixSetConvert = `Convert prefix set files between different formats

Usage: %s [options]

An input flag (-inText or -inBinary) and one or more output flags (-outText and/or -outBinary) form a conversion job.
Input and output flags can be specified multiple times to convert multiple files in a single run.

Flags:
  -inText <path>          Path to input prefix set file in text format
  -inBinary <path>        Path to input prefix set file in binary format
  -outText <path>         Path to output prefix set file in text format
  -outBinary <path>       Path to output prefix set file in binary format
  -concurrency <number>   Number of concurrent conversion jobs (default: auto)

Logging Flags:
  -logLevel <level>   Log level, one of: DEBUG, INFO, WARN, ERROR (default: INFO)
  -logNoColor         Disable colored log output
  -logNoTime          Disable timestamp in log output
  -logKVPairs         Format logs as key=value pairs
  -logJSON            Format logs as line-delimited JSON

Examples:
  Convert a text file to binary format:
    %s -inText prefixes.txt -outBinary prefixes

  Convert multiple files in a single run:
    %s -inText a.txt -outBinary a -inBinary b -outText b.txt
`

func runPrefixSetConvert(name string, args []string) int {
	var (
		fs          flag.FlagSet
		jobs        []worker.Job
		job         *prefixSetConversionJob
		failCount   atomic.Int32
		concurrency int
		logLevel    slog.Level
		logNoColor  = defaultLogNoColor
		logNoTime   bool
		logKVPairs  bool
		logJSON     bool
	)

	setJobInput := func(inPath string, unmarshalRead func(io.Reader, *bart.Lite) error) error {
		if inPath == "" {
			return errors.New("empty input path")
		}
		if job != nil {
			if job.outTextPath != "" || job.outBinaryPath != "" {
				jobs = append(jobs, job)
			} else {
				return errors.New("previous -inText or -inBinary has no paired -outText and/or -outBinary")
			}
		}
		job = &prefixSetConversionJob{
			inPath:        inPath,
			unmarshalRead: unmarshalRead,
			failCount:     &failCount,
		}
		return nil
	}

	setJobOutput := func(outPath string, isText bool) error {
		if outPath == "" {
			return errors.New("empty output path")
		}
		if job == nil {
			return errors.New("output path specified before any input path")
		}
		var jobOutPathp *string
		if isText {
			jobOutPathp = &job.outTextPath
		} else {
			jobOutPathp = &job.outBinaryPath
		}
		if *jobOutPathp != "" {
			return errors.New("output path for the same format already specified")
		}
		*jobOutPathp = outPath
		return nil
	}

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usagePrefixSetConvert, name, name, name)
	}
	fs.Init(name, flag.ExitOnError)
	fs.Func("inText", "`path` to input prefix set file in text format", func(s string) error {
		return setJobInput(s, func(r io.Reader, s *bart.Lite) error {
			br := bufio.NewReaderSize(r, 128*1024)
			return prefixset.UnmarshalReadText(br, s)
		})
	})
	fs.Func("inBinary", "`path` to input prefix set file in binary format", func(s string) error {
		return setJobInput(s, prefixset.UnmarshalReadBinary)
	})
	fs.Func("outText", "`path` to output prefix set file in text format", func(s string) error {
		return setJobOutput(s, true)
	})
	fs.Func("outBinary", "`path` to output prefix set file in binary format", func(s string) error {
		return setJobOutput(s, false)
	})
	fs.IntVar(&concurrency, "concurrency", 0, "`number` of concurrent conversion jobs")
	fs.TextVar(&logLevel, "logLevel", slog.LevelInfo, "log `level`, one of: DEBUG, INFO, WARN, ERROR")
	fs.BoolVar(&logNoColor, "logNoColor", defaultLogNoColor, "disable colored log output")
	fs.BoolVar(&logNoTime, "logNoTime", false, "disable timestamp in log output")
	fs.BoolVar(&logKVPairs, "logKVPairs", false, "format logs as key=value pairs")
	fs.BoolVar(&logJSON, "logJSON", false, "format logs as line-delimited JSON")
	fs.Parse(args)

	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "Unexpected arguments: %v\nRun '%s -h' for usage.\n", fs.Args(), name)
		return 2
	}

	if job == nil {
		fmt.Fprintf(fs.Output(), "No input prefix set file paths specified\nRun '%s -h' for usage.\n", name)
		return 2
	}
	if job.outTextPath == "" && job.outBinaryPath == "" {
		fmt.Fprintf(fs.Output(), "Trailing -inText or -inBinary has no paired -outText and/or -outBinary\nRun '%s -h' for usage.\n", name)
		return 2
	}
	jobs = append(jobs, job)

	if concurrency <= 0 {
		concurrency = min(len(jobs), runtime.NumCPU())
	}

	logCfg := tslog.Config{
		Level:          logLevel,
		NoColor:        logNoColor,
		NoTime:         logNoTime,
		UseTextHandler: logKVPairs,
		UseJSONHandler: logJSON,
	}
	logger := logCfg.NewLogger(os.Stderr)

	ctx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	stopAF := context.AfterFunc(ctx, func() {
		stopSig()
	})
	defer func() {
		if stopAF() {
			stopSig()
		}
	}()

	fleet := worker.NewFleet(logger, concurrency)
	fleet.Run(ctx, jobs)
	fleet.Close()

	fail := int(failCount.Load())
	success := len(jobs) - fail
	logger.Info("Conversion summary",
		slog.Int("success", success),
		slog.Int("fail", fail),
	)
	if fail > 0 {
		return 1
	}
	return 0
}

// prefixSetConversionJob implements [worker.Job].
type prefixSetConversionJob struct {
	inPath        string
	unmarshalRead func(io.Reader, *bart.Lite) error
	outTextPath   string
	outBinaryPath string
	failCount     *atomic.Int32
}

// SlogAttr implements [worker.Job.SlogAttr].
func (job *prefixSetConversionJob) SlogAttr() slog.Attr {
	return slog.GroupAttrs("prefixSetConversionJob",
		slog.String("inPath", job.inPath),
		slog.String("outTextPath", job.outTextPath),
		slog.String("outBinaryPath", job.outBinaryPath),
	)
}

// Run implements [worker.Job.Run].
func (job *prefixSetConversionJob) Run(_ context.Context, logger *tslog.Logger) {
	logger.Debug("Opening input prefix set file", slog.String("path", job.inPath))

	f, err := os.Open(job.inPath)
	if err != nil {
		logger.Error("Failed to open input prefix set file",
			slog.String("path", job.inPath),
			tslog.Err(err),
		)
		job.failCount.Add(1)
		return
	}
	defer f.Close()

	logger.Debug("Reading prefix set from input file", slog.String("path", job.inPath))

	var s bart.Lite
	if err := job.unmarshalRead(f, &s); err != nil {
		logger.Error("Failed to unmarshal prefix set from input file",
			slog.String("path", job.inPath),
			tslog.Err(err),
		)
		job.failCount.Add(1)
		return
	}

	logger.Info("Unmarshaled prefix set from input file",
		slog.String("path", job.inPath),
		slog.Int("ipv4Count", s.Size4()),
		slog.Int("ipv6Count", s.Size6()),
	)

	var failed bool
	if job.outTextPath != "" {
		if !writePrefixSetFile(logger, job.outTextPath, &s, prefixset.MarshalWriteText) {
			failed = true
		}
	}
	if job.outBinaryPath != "" {
		if !writePrefixSetFile(logger, job.outBinaryPath, &s, prefixset.MarshalWriteBinary) {
			failed = true
		}
	}
	if failed {
		job.failCount.Add(1)
	}
}

func writePrefixSetFile(
	logger *tslog.Logger,
	path string,
	s *bart.Lite,
	marshalWrite func(io.Writer, *bart.Lite) error,
) bool {
	logger.Debug("Creating output prefix set file", slog.String("path", path))

	f, err := os.Create(path)
	if err != nil {
		logger.Error("Failed to create output prefix set file",
			slog.String("path", path),
			tslog.Err(err),
		)
		return false
	}
	defer f.Close()

	logger.Debug("Writing to output prefix set file", slog.String("path", path))

	if err := marshalWrite(f, s); err != nil {
		logger.Error("Failed to marshal prefix set to output file",
			slog.String("path", path),
			tslog.Err(err),
		)
		return false
	}

	logger.Info("Marshaled prefix set to output file", slog.String("path", path))

	return true
}
