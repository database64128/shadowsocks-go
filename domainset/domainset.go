package domainset

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	capacityHintPrefix    = "# shadowsocks-go domain set capacity hint "
	capacityHintPrefixLen = len(capacityHintPrefix)
	capacityHintSuffix    = "DSKR"
)

const (
	domainPrefix     = "domain:"
	suffixPrefix     = "suffix:"
	keywordPrefix    = "keyword:"
	regexpPrefix     = "regexp:"
	domainPrefixLen  = len(domainPrefix)
	suffixPrefixLen  = len(suffixPrefix)
	keywordPrefixLen = len(keywordPrefix)
	regexpPrefixLen  = len(regexpPrefix)
)

var errEmptyFile = errors.New("empty file")

// Config is the configuration for a DomainSet.
type Config struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

// DomainSet creates a DomainSet from the configuration.
func (dsc Config) DomainSet() (*DomainSet, error) {
	f, err := os.Open(dsc.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to load domain set %s: %w", dsc.Name, err)
	}
	defer f.Close()

	var ds *DomainSet

	switch dsc.Type {
	case "text", "":
		ds, err = DomainSetFromText(f)
	case "gob":
		ds, err = DomainSetFromGob(f)
	default:
		err = fmt.Errorf("invalid domain set type: %s", dsc.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load domain set %s: %w", dsc.Name, err)
	}
	return ds, nil
}

func DomainSetFromText(r io.Reader) (*DomainSet, error) {
	s := bufio.NewScanner(r)
	if !s.Scan() {
		return nil, errEmptyFile
	}
	line := s.Text()

	dskr, found, err := parseCapacityHint(line)
	if err != nil {
		return nil, err
	}
	if found {
		if !s.Scan() {
			return nil, errEmptyFile
		}
		line = s.Text()
	}

	dsm := NewDomainSuffixMap(dskr[1])

	ds := DomainSet{
		Domains:  make(map[string]struct{}, dskr[0]),
		Suffixes: dsm,
		Keywords: make([]string, 0, dskr[2]),
		Regexps:  make([]*regexp.Regexp, 0, dskr[3]),
	}

	for {
		switch {
		case line == "" || strings.IndexByte(line, '#') == 0:
		case strings.HasPrefix(line, domainPrefix):
			ds.Domains[line[domainPrefixLen:]] = struct{}{}
		case strings.HasPrefix(line, suffixPrefix):
			dsm.Suffixes[line[suffixPrefixLen:]] = struct{}{}
		case strings.HasPrefix(line, keywordPrefix):
			ds.Keywords = append(ds.Keywords, line[keywordPrefixLen:])
		case strings.HasPrefix(line, regexpPrefix):
			regexp, err := regexp.Compile(line[regexpPrefixLen:])
			if err != nil {
				return nil, err
			}
			ds.Regexps = append(ds.Regexps, regexp)
		default:
			return nil, fmt.Errorf("invalid line: %s", line)
		}

		if !s.Scan() {
			break
		}
		line = s.Text()
	}

	return &ds, nil
}

func parseCapacityHint(line string) ([4]int, bool, error) {
	var dskr [4]int

	found := len(line) > capacityHintPrefixLen && line[:capacityHintPrefixLen] == capacityHintPrefix
	if found {
		h := line[capacityHintPrefixLen:]

		for i := range dskr {
			delimiterIndex := strings.IndexByte(h, ' ')
			if delimiterIndex == -1 {
				return dskr, found, fmt.Errorf("bad capacity hint: %s", line)
			}

			c, err := strconv.Atoi(h[:delimiterIndex])
			if err != nil {
				return dskr, found, fmt.Errorf("bad capacity hint: %s: %w", line, err)
			}
			if c < 0 {
				return dskr, found, fmt.Errorf("bad capacity hint: %s: capacity cannot be negative", line)
			}
			dskr[i] = c
			h = h[delimiterIndex+1:]
		}

		if h != capacityHintSuffix {
			return dskr, found, fmt.Errorf("bad capacity hint: %s: expected suffix '%s'", line, capacityHintSuffix)
		}
	}

	return dskr, found, nil
}

func DomainSetFromGob(r io.Reader) (*DomainSet, error) {
	dsb, err := BuilderFromGob(r)
	if err != nil {
		return nil, err
	}
	return dsb.DomainSet()
}

// Builder stores the content of a domain set and
// provides methods for writing in different formats.
type Builder struct {
	Domains  map[string]struct{}
	Suffixes *DomainSuffixTrie
	Keywords []string
	Regexps  []string
}

func (dsb *Builder) DomainSet() (*DomainSet, error) {
	ds := DomainSet{
		Domains:  dsb.Domains,
		Suffixes: dsb.Suffixes,
		Keywords: dsb.Keywords,
		Regexps:  make([]*regexp.Regexp, len(dsb.Regexps)),
	}

	for i, r := range dsb.Regexps {
		regexp, err := regexp.Compile(r)
		if err != nil {
			return nil, err
		}
		ds.Regexps[i] = regexp
	}

	return &ds, nil
}

func (dsb *Builder) WriteGob(w io.Writer) error {
	enc := gob.NewEncoder(w)
	return enc.Encode(dsb)
}

func (dsb *Builder) WriteText(w io.Writer) error {
	bw := bufio.NewWriter(w)
	suffixes := dsb.Suffixes.Keys()
	capacityHint := fmt.Sprintf("%s%d %d %d %d %s\n", capacityHintPrefix, len(dsb.Domains), len(suffixes), len(dsb.Keywords), len(dsb.Regexps), capacityHintSuffix)

	bw.WriteString(capacityHint)

	for d := range dsb.Domains {
		bw.WriteString(domainPrefix)
		bw.WriteString(d)
		bw.WriteByte('\n')
	}

	for _, s := range suffixes {
		bw.WriteString(suffixPrefix)
		bw.WriteString(s)
		bw.WriteByte('\n')
	}

	for _, k := range dsb.Keywords {
		bw.WriteString(keywordPrefix)
		bw.WriteString(k)
		bw.WriteByte('\n')
	}

	for _, r := range dsb.Regexps {
		bw.WriteString(regexpPrefix)
		bw.WriteString(r)
		bw.WriteByte('\n')
	}

	return bw.Flush()
}

func BuilderFromGob(r io.Reader) (*Builder, error) {
	var dsb Builder
	dec := gob.NewDecoder(r)
	if err := dec.Decode(&dsb); err != nil {
		return nil, err
	}
	return &dsb, nil
}

func BuilderFromText(r io.Reader) (*Builder, error) {
	s := bufio.NewScanner(r)
	if !s.Scan() {
		return nil, errEmptyFile
	}
	line := s.Text()

	dskr, found, err := parseCapacityHint(line)
	if err != nil {
		return nil, err
	}
	if found {
		if !s.Scan() {
			return nil, errEmptyFile
		}
		line = s.Text()
	}

	dsb := Builder{
		Domains:  make(map[string]struct{}, dskr[0]),
		Suffixes: &DomainSuffixTrie{},
		Keywords: make([]string, 0, dskr[2]),
		Regexps:  make([]string, 0, dskr[3]),
	}

	for {
		switch {
		case line == "" || strings.IndexByte(line, '#') == 0:
		case strings.HasPrefix(line, domainPrefix):
			dsb.Domains[line[domainPrefixLen:]] = struct{}{}
		case strings.HasPrefix(line, suffixPrefix):
			dsb.Suffixes.Insert(line[suffixPrefixLen:])
		case strings.HasPrefix(line, keywordPrefix):
			dsb.Keywords = append(dsb.Keywords, line[keywordPrefixLen:])
		case strings.HasPrefix(line, regexpPrefix):
			dsb.Regexps = append(dsb.Regexps, line[regexpPrefixLen:])
		default:
			return nil, fmt.Errorf("invalid line: %s", line)
		}

		if !s.Scan() {
			break
		}
		line = s.Text()
	}

	return &dsb, nil
}

// DomainSet is a set of domain rules.
type DomainSet struct {
	Domains  map[string]struct{}
	Suffixes DomainSuffixSet
	Keywords []string
	Regexps  []*regexp.Regexp
}

// Match returns whether the domain set contains the domain.
func (ds *DomainSet) Match(domain string) bool {
	if _, ok := ds.Domains[domain]; ok {
		return true
	}

	if ds.Suffixes.Match(domain) {
		return true
	}

	for _, keyword := range ds.Keywords {
		if strings.Contains(domain, keyword) {
			return true
		}
	}

	for _, regexp := range ds.Regexps {
		if regexp.MatchString(domain) {
			return true
		}
	}

	return false
}
