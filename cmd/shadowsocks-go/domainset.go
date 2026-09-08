package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/database64128/shadowsocks-go/bytestrings"
	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/mmap"
)

const usageDomainSet = `Manage domain set files

Usage of %s:
  %s [command]

Commands:
  convert     Convert domain set files between different formats

Run '%s [command] -h' for more information on a command.
`

func printUsageDomainSet(name string) {
	fmt.Fprintf(os.Stderr, usageDomainSet, name, name, name)
}

func runDomainSet(name string, args []string) int {
	if len(args) == 0 {
		printUsageDomainSet(name)
		return 2
	}
	switch args[0] {
	case "convert":
		return runDomainSetConvert(name+" convert", args[1:])
	case "--help", "-help", "-h":
		printUsageDomainSet(name)
		return 0
	default:
		printUsageDomainSet(name)
		return 2
	}
}

func runDomainSetConvert(name string, args []string) int {
	var (
		fs         flag.FlagSet
		inDlc      string
		inText     string
		inGob      string
		outText    string
		outGob     string
		tag        string
		skipRegexp bool
	)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Convert domain set files between different formats\n\nUsage of %s:\n", name)
		fs.PrintDefaults()
	}
	fs.Init(name, flag.ExitOnError)
	fs.StringVar(&inDlc, "inDlc", "", "`path` to input domain set file in v2fly/domain-list-community format")
	fs.StringVar(&inText, "inText", "", "`path` to input domain set file in plaintext format")
	fs.StringVar(&inGob, "inGob", "", "`path` to input domain set file in gob format")
	fs.StringVar(&outText, "outText", "", "`path` to output domain set file in plaintext format")
	fs.StringVar(&outGob, "outGob", "", "`path` to output domain set file in gob format")
	fs.StringVar(&tag, "tag", "", "with -inDlc, select rules with the specified `attribute` (without the leading '@') rather than all rules")
	fs.BoolVar(&skipRegexp, "skipRegexp", false, "skip regular expression rules")
	fs.Parse(args)

	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "Unexpected arguments: %v\nRun '%s -h' for usage.\n", fs.Args(), name)
		return 2
	}

	var (
		inCount int
		inPath  string
		inFunc  func(string) (domainset.Builder, error)
	)

	if inDlc != "" {
		inCount++
		inPath = inDlc
		inFunc = func(text string) (domainset.Builder, error) {
			return domainSetBuilderFromDlc(text, tag)
		}
	}

	if inText != "" {
		inCount++
		inPath = inText
		inFunc = domainset.BuilderFromText
	}

	if inGob != "" {
		inCount++
		inPath = inGob
		inFunc = domainset.BuilderFromGobString
	}

	if inCount != 1 {
		fmt.Fprintf(fs.Output(), "Exactly one of -inDlc, -inText, -inGob must be specified.\nRun '%s -h' for usage.\n", name)
		return 2
	}

	if outText == "" && outGob == "" {
		fmt.Fprintf(fs.Output(), "Specify output file paths with -outText and/or -outGob.\nRun '%s -h' for usage.\n", name)
		return 2
	}

	data, close, err := mmap.ReadFile[string](inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read input file:", err)
		return 1
	}
	defer close()

	dsb, err := inFunc(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse input file:", err)
		return 1
	}

	if skipRegexp {
		dsb.RegexpMatcherBuilder().Clear()
	}

	if outText != "" {
		fout, err := os.Create(outText)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to create output file:", err)
			return 1
		}
		defer fout.Close()

		err = dsb.WriteText(fout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write output file:", err)
			return 1
		}
	}

	if outGob != "" {
		fout, err := os.Create(outGob)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to create output file:", err)
			return 1
		}
		defer fout.Close()

		err = dsb.WriteGob(fout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write output file:", err)
			return 1
		}
	}

	return 0
}

func domainSetBuilderFromDlc(text, tag string) (domainset.Builder, error) {
	const (
		domainPrefix     = "full:"
		suffixPrefix     = "domain:"
		keywordPrefix    = "keyword:"
		regexpPrefix     = "regexp:"
		domainPrefixLen  = len(domainPrefix)
		suffixPrefixLen  = len(suffixPrefix)
		keywordPrefixLen = len(keywordPrefix)
		regexpPrefixLen  = len(regexpPrefix)
	)

	dsb := domainset.Builder{
		domainset.NewDomainMapMatcher(0),
		domainset.NewDomainSuffixTrieMatcherBuilder(0),
		domainset.NewKeywordLinearMatcher(0),
		domainset.NewRegexpMatcherBuilder(0),
	}

	for line := range bytestrings.NonEmptyLines(text) {
		if line[0] == '#' {
			continue
		}

		end := strings.IndexByte(line, '@')
		if end == 0 {
			return dsb, fmt.Errorf("invalid line: %q", line)
		}

		if tag == "" { // select all lines
			if end == -1 {
				end = len(line)
			} else {
				end--
			}
		} else { // select matched tag
			if end == -1 || line[end+1:] != tag { // no tag or different tag
				continue
			} else {
				end--
			}
		}

		switch {
		case strings.HasPrefix(line, domainPrefix):
			dsb.DomainMatcherBuilder().Insert(line[domainPrefixLen:end])
		case strings.HasPrefix(line, suffixPrefix):
			dsb.SuffixMatcherBuilder().Insert(line[suffixPrefixLen:end])
		case strings.HasPrefix(line, keywordPrefix):
			dsb.KeywordMatcherBuilder().Insert(line[keywordPrefixLen:end])
		case strings.HasPrefix(line, regexpPrefix):
			dsb.RegexpMatcherBuilder().Insert(line[regexpPrefixLen:end])
		default:
			return dsb, fmt.Errorf("invalid line: %q", line)
		}
	}

	return dsb, nil
}
