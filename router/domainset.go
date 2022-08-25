package router

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// DomainSetConfig is the configuration for a DomainSet.
type DomainSetConfig struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// DomainSet creates a DomainSet from the configuration.
func (dsc DomainSetConfig) DomainSet() (*DomainSet, error) {
	f, err := os.Open(dsc.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	ds := NewDomainSet()

	for s.Scan() {
		line := s.Text()

		switch {
		case line == "" || strings.IndexByte(line, '#') == 0:
			continue
		case strings.HasPrefix(line, "domain:"):
			ds.Domains[line[7:]] = struct{}{}
		case strings.HasPrefix(line, "suffix:"):
			ds.Suffixes[line[7:]] = struct{}{}
		case strings.HasPrefix(line, "keyword:"):
			ds.Keywords = append(ds.Keywords, line[8:])
		case strings.HasPrefix(line, "regexp:"):
			regexp, err := regexp.Compile(line[7:])
			if err != nil {
				return nil, err
			}
			ds.Regexps = append(ds.Regexps, regexp)
		default:
			return nil, fmt.Errorf("invalid line: %s", line)
		}
	}

	return ds, nil
}

// DomainSet is a set of domain rules.
type DomainSet struct {
	Domains  map[string]struct{}
	Suffixes map[string]struct{}
	Keywords []string
	Regexps  []*regexp.Regexp
}

func NewDomainSet() *DomainSet {
	return &DomainSet{
		Domains:  make(map[string]struct{}),
		Suffixes: make(map[string]struct{}),
	}
}

// Match returns whether the domain set contains the domain.
func (ds *DomainSet) Match(domain string) bool {
	if _, ok := ds.Domains[domain]; ok {
		return true
	}

	if ds.matchDomainSuffix(domain) {
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

func (ds *DomainSet) matchDomainSuffix(domain string) bool {
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}
		if _, ok := ds.Suffixes[domain[i+1:]]; ok {
			return true
		}
	}
	_, ok := ds.Suffixes[domain]
	return ok
}
