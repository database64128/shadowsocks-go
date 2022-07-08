package router

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/exp/slices"
)

// DomainSetConfig is the configuration for a DomainSet.
type DomainSetConfig struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// DomainSet creates a DomainSet from the configuration.
func (dsc DomainSetConfig) DomainSet() (ds DomainSet, err error) {
	f, err := os.Open(dsc.Path)
	if err != nil {
		return
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	for s.Scan() {
		line := s.Text()

		switch {
		case line == "" || strings.IndexByte(line, '#') == 0:
			continue
		case strings.HasPrefix(line, "domain:"):
			ds.Domains = append(ds.Domains, line[7:])
		case strings.HasPrefix(line, "suffix:"):
			ds.Suffixes = append(ds.Suffixes, line[7:])
		case strings.HasPrefix(line, "keyword:"):
			ds.Keywords = append(ds.Keywords, line[8:])
		case strings.HasPrefix(line, "regexp:"):
			regexp, err := regexp.Compile(line[7:])
			if err != nil {
				return ds, err
			}
			ds.Regexps = append(ds.Regexps, regexp)
		default:
			return ds, fmt.Errorf("invalid line: %s", line)
		}
	}

	return
}

// DomainSet is a set of domain rules.
type DomainSet struct {
	Domains  []string
	Suffixes []string
	Keywords []string
	Regexps  []*regexp.Regexp
}

// Match returns whether the domain set contains the domain.
func (ds DomainSet) Match(domain string) bool {
	if slices.Contains(ds.Domains, domain) {
		return true
	}

	for _, suffix := range ds.Suffixes {
		if matchDomainSuffix(domain, suffix) {
			return true
		}
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

func matchDomainSuffix(domain, suffix string) bool {
	return domain == suffix || len(domain) > len(suffix) && domain[0] == '.' && domain[1:] == suffix
}
