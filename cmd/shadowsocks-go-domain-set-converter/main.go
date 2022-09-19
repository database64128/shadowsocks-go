// Domain set converter takes a domain set file in v2fly/dlc, plaintext or gob format,
// and converts it to an optimized domain set file in plaintext or gob format.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/database64128/shadowsocks-go/domainset"
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
		inFunc  func(io.Reader) (domainset.Builder, error)
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
		inFunc = domainset.BuilderFromGob
	}

	if inCount != 1 {
		fmt.Println("Exactly one of -inDlc, -inText, -inGob must be specified.")
		flag.Usage()
		os.Exit(1)
	}

	if *outText == "" && *outGob == "" {
		fmt.Println("Specify output file paths with -outText and/or -outGob.")
		flag.Usage()
		os.Exit(1)
	}

	fin, err := os.Open(inPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer fin.Close()

	dsb, err := inFunc(fin)
	if err != nil {
		fmt.Println(err)
		return
	}

	if *outText != "" {
		fout, err := os.Create(*outText)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer fout.Close()

		err = dsb.WriteText(fout)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	if *outGob != "" {
		fout, err := os.Create(*outGob)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer fout.Close()

		err = dsb.WriteGob(fout)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func DomainSetBuilderFromDlc(r io.Reader) (domainset.Builder, error) {
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

	s := bufio.NewScanner(r)

	for s.Scan() {
		line := s.Text()

		if line == "" || strings.IndexByte(line, '#') == 0 {
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
