// Domain set converter takes a domain set file in v2fly/dlc, plaintext or gob format,
// and converts it to an optimized domain set file in plaintext or gob format.

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

var (
	inDlc   = flag.String("inDlc", "", "Path to input domain set file in v2fly/dlc format.")
	inText  = flag.String("inText", "", "Path to input domain set file in plaintext format.")
	inGob   = flag.String("inGob", "", "Path to input domain set file in gob format.")
	outText = flag.String("outText", "", "Path to output domain set file in plaintext format.")
	outGob  = flag.String("outGob", "", "Path to output domain set file in gob format.")
	tag     = flag.String("tag", "", "Select lines with the specified tag. If empty, select all lines. Only applicable to v2fly/dlc format.")
)

func main() {
	flag.Parse()

	var (
		inCount int
		inPath  string
		inFunc  func(string) (domainset.Builder, error)
	)

	if *inDlc != "" {
		inCount++
		inPath = *inDlc
		inFunc = DomainSetBuilderFromDlc
	}

	if *inText != "" {
		inCount++
		inPath = *inText
		inFunc = domainset.BuilderFromText
	}

	if *inGob != "" {
		inCount++
		inPath = *inGob
		inFunc = func(s string) (domainset.Builder, error) {
			r := strings.NewReader(s)
			return domainset.BuilderFromGob(r)
		}
	}

	if inCount != 1 {
		fmt.Fprintln(os.Stderr, "Exactly one of -inDlc, -inText, -inGob must be specified.")
		flag.Usage()
		os.Exit(1)
	}

	if *outText == "" && *outGob == "" {
		fmt.Fprintln(os.Stderr, "Specify output file paths with -outText and/or -outGob.")
		flag.Usage()
		os.Exit(1)
	}

	data, err := mmap.ReadFile[string](inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read input file:", err)
		os.Exit(1)
	}
	defer mmap.Unmap(data)

	dsb, err := inFunc(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse input file:", err)
		return
	}

	if *outText != "" {
		fout, err := os.Create(*outText)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to create output file:", err)
			return
		}
		defer fout.Close()

		err = dsb.WriteText(fout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write output file:", err)
			return
		}
	}

	if *outGob != "" {
		fout, err := os.Create(*outGob)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to create output file:", err)
			return
		}
		defer fout.Close()

		err = dsb.WriteGob(fout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write output file:", err)
			return
		}
	}
}

func DomainSetBuilderFromDlc(text string) (domainset.Builder, error) {
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
		domainset.NewDomainSuffixTrie(0),
		domainset.NewKeywordLinearMatcher(0),
		domainset.NewRegexpMatcherBuilder(0),
	}

	var line string

	for {
		line, text = bytestrings.NextNonEmptyLine(text)
		if len(line) == 0 {
			break
		}

		if line[0] == '#' {
			continue
		}

		end := strings.IndexByte(line, '@')
		if end == 0 {
			return dsb, fmt.Errorf("invalid line: %s", line)
		}

		if *tag == "" { // select all lines
			if end == -1 {
				end = len(line)
			} else {
				end--
			}
		} else { // select matched tag
			if end == -1 || line[end+1:] != *tag { // no tag or different tag
				continue
			} else {
				end--
			}
		}

		switch {
		case strings.HasPrefix(line, domainPrefix):
			dsb[0].Insert(line[domainPrefixLen:end])
		case strings.HasPrefix(line, suffixPrefix):
			dsb[1].Insert(line[suffixPrefixLen:end])
		case strings.HasPrefix(line, keywordPrefix):
			dsb[2].Insert(line[keywordPrefixLen:end])
		case strings.HasPrefix(line, regexpPrefix):
			dsb[3].Insert(line[regexpPrefixLen:end])
		default:
			return dsb, fmt.Errorf("invalid line: %s", line)
		}
	}

	return dsb, nil
}
