package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"
	"syscall"

	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/mmap"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/worker"
)

const usageDomainSet = `Manage domain set files

Usage: %s [command]

Commands:
  show        Inspect domain set files
  convert     Convert domain set files between different formats

Run '%s [command] -h' for more information on a command.
`

func printUsageDomainSet(name string) {
	fmt.Fprintf(os.Stderr, usageDomainSet, name, name)
}

func runDomainSet(name string, args []string) int {
	if len(args) == 0 {
		printUsageDomainSet(name)
		return 2
	}
	switch args[0] {
	case "show":
		return runDomainSetShow(name+" show", args[1:])
	case "convert":
		return runDomainSetConvert(name+" convert", args[1:])
	case "--help", "-help", "-h":
		printUsageDomainSet(name)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %q\nRun '%s -h' for usage.\n", args[0], name)
		return 2
	}
}

const usageDomainSetShow = `Inspect domain set files

Usage: %s [options]

Input flags can be specified multiple times to inspect multiple files in one run.

Flags:
  -inDlc <path>       Path to input domain set file in v2fly/domain-list-community exported plaintext format
  -inText <path>      Path to input domain set file in plaintext format
  -inGob <path>       Path to input domain set file in gob format
  -v, -verbose        Dump domain set rules
  -sort               When -verbose, dump rules in alphabetical order

Examples:
  Show domain set rule counts:
    %s -inText domains.txt

  Dump rules in alphabetical order:
    %s -inGob domains -verbose -sort
`

func runDomainSetShow(name string, args []string) int {
	var (
		fs      flag.FlagSet
		items   []domainSetShowItem
		verbose bool
		sorted  bool
	)

	addItem := func(path string, unmarshal func(text, attr string) (domainset.Builder, error)) error {
		if path == "" {
			return errors.New("empty input path")
		}
		items = append(items, domainSetShowItem{
			inPath:    path,
			unmarshal: unmarshal,
		})
		return nil
	}

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageDomainSetShow, name, name, name)
	}
	fs.Init(name, flag.ContinueOnError)
	fs.Func("inDlc", "`path` to input domain set file in v2fly/domain-list-community exported plaintext format", func(s string) error {
		return addItem(s, domainset.BuilderFromDLC)
	})
	fs.Func("inText", "`path` to input domain set file in plaintext format", func(s string) error {
		return addItem(s, func(text, _ string) (domainset.Builder, error) {
			return domainset.BuilderFromText(text)
		})
	})
	fs.Func("inGob", "`path` to input domain set file in gob format", func(s string) error {
		return addItem(s, func(text, _ string) (domainset.Builder, error) {
			return domainset.BuilderFromGobString(text)
		})
	})
	fs.BoolVar(&verbose, "verbose", false, "dump domain set rules")
	fs.BoolVar(&verbose, "v", false, "alias for -verbose")
	fs.BoolVar(&sorted, "sort", false, "when -verbose, dump rules in alphabetical order")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "Unexpected arguments: %v\nRun '%s -h' for usage.\n", fs.Args(), name)
		return 2
	}

	if len(items) == 0 {
		fmt.Fprintf(fs.Output(), "Please specify domain set files with -inDlc, -inText, and/or -inGob.\nRun '%s -h' for usage.\n", name)
		return 2
	}

	var exitCode int
	bw := bufio.NewWriter(os.Stdout)
	for i, item := range items {
		if i > 0 {
			if err := bw.WriteByte('\n'); err != nil {
				fmt.Fprintf(fs.Output(), "Failed to write newline to stdout: %v\n", err)
				exitCode = 1
			}
		}
		if err := item.WriteOutput(bw, verbose, sorted); err != nil {
			fmt.Fprintf(fs.Output(), "Failed to show domain set file %q: %v\n", item.inPath, err)
			exitCode = 1
		}
	}
	if err := bw.Flush(); err != nil {
		fmt.Fprintf(fs.Output(), "Failed to flush to stdout: %v\n", err)
		exitCode = 1
	}
	return exitCode
}

type domainSetShowItem struct {
	inPath    string
	unmarshal func(text, attr string) (domainset.Builder, error)
}

func (item *domainSetShowItem) WriteOutput(bw *bufio.Writer, verbose, sorted bool) error {
	data, close, err := mmap.ReadFile[string](item.inPath)
	if err != nil {
		return err
	}
	defer close()

	dsb, err := item.unmarshal(data, "")
	if err != nil {
		return fmt.Errorf("failed to unmarshal domain set from file %q: %w", item.inPath, err)
	}

	domainCount, domainSeq := dsb.DomainMatcherBuilder().Rules()
	suffixCount, suffixSeq := dsb.SuffixMatcherBuilder().Rules()
	keywordCount, keywordSeq := dsb.KeywordMatcherBuilder().Rules()
	regexpCount, regexpSeq := dsb.RegexpMatcherBuilder().Rules()

	if _, err := bw.WriteString("Path: "); err != nil {
		return err
	}
	if _, err := bw.WriteString(item.inPath); err != nil {
		return err
	}
	if _, err := bw.WriteString("\nRule counts:\n"); err != nil {
		return err
	}

	for _, section := range [...]struct {
		name  string
		count int
	}{
		{"  domain:  ", domainCount},
		{"  suffix:  ", suffixCount},
		{"  keyword: ", keywordCount},
		{"  regexp:  ", regexpCount},
	} {
		if _, err := bw.WriteString(section.name); err != nil {
			return err
		}
		b := strconv.AppendInt(bw.AvailableBuffer(), int64(section.count), 10)
		if _, err := bw.Write(b); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}

	if verbose {
		if _, err := bw.WriteString("\nRules:\n"); err != nil {
			return err
		}

		for _, section := range [...]struct {
			title string
			count int
			rules iter.Seq[string]
		}{
			{"  domain:\n", domainCount, domainSeq},
			{"  suffix:\n", suffixCount, suffixSeq},
			{"  keyword:\n", keywordCount, keywordSeq},
			{"  regexp:\n", regexpCount, regexpSeq},
		} {
			if _, err := bw.WriteString(section.title); err != nil {
				return err
			}

			if sorted {
				rules := slices.AppendSeq(make([]string, 0, section.count), section.rules)
				slices.Sort(rules)
				section.rules = slices.Values(rules)
			}

			for rule := range section.rules {
				if _, err := bw.WriteString("    "); err != nil {
					return err
				}
				if _, err := bw.WriteString(rule); err != nil {
					return err
				}
				if err := bw.WriteByte('\n'); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

const usageDomainSetConvert = `Convert domain set files between different formats

Usage: %s [options]

An input flag (-inDlc, -inText, or -inGob) and one or more output flags (-outText and/or -outGob) form a conversion job.
Input and output flags can be specified multiple times to convert multiple files in a single run.
Filter flags (-attr and -skipRegexp) apply to the immediately preceding input file.

Flags:
  -inDlc <path>           Path to input domain set file in v2fly/domain-list-community exported plaintext format
  -inText <path>          Path to input domain set file in plaintext format
  -inGob <path>           Path to input domain set file in gob format
  -outText <path>         Path to output domain set file in plaintext format
  -outGob <path>          Path to output domain set file in gob format
  -attr <attribute>       With -inDlc, select rules with the specified attribute
  -tag <attribute>        Alias for -attr
  -skipRegexp             Skip regular expression rules
  -concurrency <number>   Number of concurrent conversion jobs (default: auto)

Logging Flags:
  -logLevel <level>   Log level, one of: DEBUG, INFO, WARN, ERROR (default: INFO)
  -logNoColor         Disable colored log output
  -logNoTime          Disable timestamp in log output
  -logKVPairs         Format logs as key=value pairs
  -logJSON            Format logs as line-delimited JSON

Examples:
  Convert a v2fly/dlc file to text and gob formats:
    %s -inDlc dlc-domains.txt -outText domains.txt -outGob domains

  Convert multiple files in a single run:
    %s -inDlc google.txt -attr ads -outText google-ads.txt -outGob google-ads \
      -inText private.txt -skipRegexp -outGob private
`

func runDomainSetConvert(name string, args []string) int {
	var (
		fs          flag.FlagSet
		jobs        []worker.Job
		job         *domainSetConversionJob
		failCount   atomic.Int32
		concurrency int
		logLevel    slog.Level
		logNoColor  = defaultLogNoColor
		logNoTime   bool
		logKVPairs  bool
		logJSON     bool
	)

	setJobInput := func(inPath string, unmarshal func(text, attr string) (domainset.Builder, error)) error {
		if inPath == "" {
			return errors.New("empty input path")
		}
		if job != nil {
			if job.outTextPath != "" || job.outGobPath != "" {
				jobs = append(jobs, job)
			} else {
				return errors.New("previous input has no paired -outText and/or -outGob")
			}
		}
		job = &domainSetConversionJob{
			inPath:    inPath,
			unmarshal: unmarshal,
			failCount: &failCount,
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
			jobOutPathp = &job.outGobPath
		}
		if *jobOutPathp != "" {
			return errors.New("output path for the same format already specified")
		}
		*jobOutPathp = outPath
		return nil
	}

	setJobAttr := func(attr string) error {
		if job == nil {
			return errors.New("attribute specified before any input path")
		}
		job.attr = attr
		return nil
	}

	setJobSkipRegexp := func(s string) error {
		if job == nil {
			return errors.New("skipRegexp specified before any input path")
		}
		skipRegexp, err := strconv.ParseBool(s)
		if err != nil {
			return errors.New("parse error") // align with the flag package
		}
		job.skipRegexp = skipRegexp
		return nil
	}

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), usageDomainSetConvert, name, name, name)
	}
	fs.Init(name, flag.ContinueOnError)
	fs.Func("inDlc", "`path` to input domain set file in v2fly/domain-list-community exported plaintext format", func(s string) error {
		return setJobInput(s, domainset.BuilderFromDLC)
	})
	fs.Func("inText", "`path` to input domain set file in plaintext format", func(s string) error {
		return setJobInput(s, func(text, _ string) (domainset.Builder, error) {
			return domainset.BuilderFromText(text)
		})
	})
	fs.Func("inGob", "`path` to input domain set file in gob format", func(s string) error {
		return setJobInput(s, func(text, _ string) (domainset.Builder, error) {
			return domainset.BuilderFromGobString(text)
		})
	})
	fs.Func("outText", "`path` to output domain set file in plaintext format", func(s string) error {
		return setJobOutput(s, true)
	})
	fs.Func("outGob", "`path` to output domain set file in gob format", func(s string) error {
		return setJobOutput(s, false)
	})
	fs.Func("attr", "with -inDlc, select rules with the specified `attribute` rather than all rules", setJobAttr)
	fs.Func("tag", "alias for -attr", setJobAttr)
	fs.BoolFunc("skipRegexp", "skip regular expression rules", setJobSkipRegexp)
	fs.IntVar(&concurrency, "concurrency", 0, "`number` of concurrent conversion jobs")
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

	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "Unexpected arguments: %v\nRun '%s -h' for usage.\n", fs.Args(), name)
		return 2
	}

	if job == nil {
		fmt.Fprintf(fs.Output(), "No input domain set file paths specified\nRun '%s -h' for usage.\n", name)
		return 2
	}
	if job.outTextPath == "" && job.outGobPath == "" {
		fmt.Fprintf(fs.Output(), "Trailing input has no paired -outText and/or -outGob\nRun '%s -h' for usage.\n", name)
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

// domainSetConversionJob implements [worker.Job].
type domainSetConversionJob struct {
	inPath      string
	unmarshal   func(text, attr string) (domainset.Builder, error)
	attr        string
	skipRegexp  bool
	outTextPath string
	outGobPath  string
	failCount   *atomic.Int32
}

// SlogAttr implements [worker.Job.SlogAttr].
func (job *domainSetConversionJob) SlogAttr() slog.Attr {
	return slog.GroupAttrs("domainSetConversionJob",
		slog.String("inPath", job.inPath),
		slog.String("attr", job.attr),
		slog.Bool("skipRegexp", job.skipRegexp),
		slog.String("outTextPath", job.outTextPath),
		slog.String("outGobPath", job.outGobPath),
	)
}

// Run implements [worker.Job.Run].
func (job *domainSetConversionJob) Run(_ context.Context, logger *tslog.Logger) {
	logger.Debug("Opening input domain set file", slog.String("path", job.inPath))

	data, close, err := mmap.ReadFile[string](job.inPath)
	if err != nil {
		logger.Error("Failed to open input domain set file",
			slog.String("path", job.inPath),
			tslog.Err(err),
		)
		job.failCount.Add(1)
		return
	}
	defer close()

	logger.Debug("Reading from input domain set file", slog.String("path", job.inPath))

	dsb, err := job.unmarshal(data, job.attr)
	if err != nil {
		logger.Error("Failed to unmarshal domain set from input file",
			slog.String("path", job.inPath),
			tslog.Err(err),
		)
		job.failCount.Add(1)
		return
	}

	if logger.Enabled(slog.LevelInfo) {
		domainCount, _ := dsb.DomainMatcherBuilder().Rules()
		suffixCount, _ := dsb.SuffixMatcherBuilder().Rules()
		keywordCount, _ := dsb.KeywordMatcherBuilder().Rules()
		regexpCount, _ := dsb.RegexpMatcherBuilder().Rules()
		logger.Info("Unmarshaled domain set from input file",
			slog.String("path", job.inPath),
			slog.Int("domainCount", domainCount),
			slog.Int("suffixCount", suffixCount),
			slog.Int("keywordCount", keywordCount),
			slog.Int("regexpCount", regexpCount),
		)
	}

	if job.skipRegexp {
		dsb.RegexpMatcherBuilder().Clear()
	}

	var failed bool
	if job.outTextPath != "" {
		if !marshalDomainSetFile(logger, job.outTextPath, dsb.WriteText) {
			failed = true
		}
	}
	if job.outGobPath != "" {
		if !marshalDomainSetFile(logger, job.outGobPath, dsb.WriteGob) {
			failed = true
		}
	}
	if failed {
		job.failCount.Add(1)
	}
}

func marshalDomainSetFile(logger *tslog.Logger, path string, marshal func(io.Writer) error) bool {
	logger.Debug("Creating output domain set file", slog.String("path", path))

	f, err := os.Create(path)
	if err != nil {
		logger.Error("Failed to create output domain set file",
			slog.String("path", path),
			tslog.Err(err),
		)
		return false
	}
	defer f.Close()

	logger.Debug("Writing to output domain set file", slog.String("path", path))

	if err := marshal(f); err != nil {
		logger.Error("Failed to marshal domain set to output file",
			slog.String("path", path),
			tslog.Err(err),
		)
		return false
	}

	logger.Info("Marshaled domain set to output file", slog.String("path", path))

	return true
}
