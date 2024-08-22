package domainset

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/database64128/shadowsocks-go/bytestrings"
	"github.com/database64128/shadowsocks-go/mmap"
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

var errEmptySet = errors.New("empty domain set")

// Config is the configuration for a DomainSet.
type Config struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

// DomainSet creates a DomainSet from the configuration.
func (dsc Config) DomainSet() (DomainSet, error) {
	data, close, err := mmap.ReadFile[string](dsc.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to load domain set %s: %w", dsc.Name, err)
	}
	defer close()

	var dsb Builder

	switch dsc.Type {
	case "text", "":
		dsb, err = BuilderFromTextFast(data)
	case "gob":
		r := strings.NewReader(data)
		dsb, err = BuilderFromGob(r)
	default:
		err = fmt.Errorf("invalid domain set type: %s", dsc.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load domain set %s: %w", dsc.Name, err)
	}

	return dsb.DomainSet()
}

// Builder stores the content of a domain set and
// provides methods for writing in different formats.
type Builder [4]MatcherBuilder

// DomainMatcherBuilder returns the domain matcher builder.
func (dsb Builder) DomainMatcherBuilder() MatcherBuilder {
	return dsb[0]
}

// SuffixMatcherBuilder returns the suffix matcher builder.
func (dsb Builder) SuffixMatcherBuilder() MatcherBuilder {
	return dsb[1]
}

// KeywordMatcherBuilder returns the keyword matcher builder.
func (dsb Builder) KeywordMatcherBuilder() MatcherBuilder {
	return dsb[2]
}

// RegexpMatcherBuilder returns the regexp matcher builder.
func (dsb Builder) RegexpMatcherBuilder() MatcherBuilder {
	return dsb[3]
}

func (dsb Builder) DomainSet() (DomainSet, error) {
	var capacity int
	for _, mb := range dsb {
		capacity += mb.MatcherCount()
	}
	ds := make(DomainSet, 0, capacity)
	var err error
	for _, mb := range dsb {
		ds, err = mb.AppendTo(ds)
		if err != nil {
			return nil, err
		}
	}
	return ds, nil
}

func (dsb Builder) WriteGob(w io.Writer) error {
	return BuilderGobFromBuilder(dsb).WriteGob(w)
}

func (dsb Builder) WriteText(w io.Writer) error {
	bw := bufio.NewWriter(w)
	domainCount, domainSeq := dsb.DomainMatcherBuilder().Rules()
	suffixCount, suffixSeq := dsb.SuffixMatcherBuilder().Rules()
	keywordCount, keywordSeq := dsb.KeywordMatcherBuilder().Rules()
	regexpCount, regexpSeq := dsb.RegexpMatcherBuilder().Rules()
	capacityHint := fmt.Sprintf("%s%d %d %d %d %s\n", capacityHintPrefix, domainCount, suffixCount, keywordCount, regexpCount, capacityHintSuffix)

	bw.WriteString(capacityHint)

	for domain := range domainSeq {
		bw.WriteString(domainPrefix)
		bw.WriteString(domain)
		bw.WriteByte('\n')
	}

	for suffix := range suffixSeq {
		bw.WriteString(suffixPrefix)
		bw.WriteString(suffix)
		bw.WriteByte('\n')
	}

	for keyword := range keywordSeq {
		bw.WriteString(keywordPrefix)
		bw.WriteString(keyword)
		bw.WriteByte('\n')
	}

	for regexp := range regexpSeq {
		bw.WriteString(regexpPrefix)
		bw.WriteString(regexp)
		bw.WriteByte('\n')
	}

	return bw.Flush()
}

func BuilderFromGob(r io.Reader) (Builder, error) {
	bg, err := BuilderGobFromReader(r)
	if err != nil {
		return Builder{}, err
	}
	return bg.Builder(), nil
}

func BuilderFromText(text string) (Builder, error) {
	return BuilderFromTextFunc(text, NewDomainMapMatcher, NewDomainSuffixTrieMatcherBuilder, NewKeywordLinearMatcher, NewRegexpMatcherBuilder)
}

func BuilderFromTextFast(text string) (Builder, error) {
	return BuilderFromTextFunc(text, NewDomainMapMatcher, NewSuffixMapMatcher, NewKeywordLinearMatcher, NewRegexpMatcherBuilder)
}

func BuilderFromTextFunc(
	text string,
	newDomainMatcherBuilderFunc,
	newSuffixMatcherBuilderFunc,
	newKeywordMatcherBuilderFunc,
	newRegexpMatcherBuilderFunc func(int) MatcherBuilder,
) (Builder, error) {
	line, text := bytestrings.NextNonEmptyLine(text)
	if len(line) == 0 {
		return Builder{}, errEmptySet
	}

	dskr, found, err := ParseCapacityHint(line)
	if err != nil {
		return Builder{}, err
	}
	if found {
		line, text = bytestrings.NextNonEmptyLine(text)
		if len(line) == 0 {
			return Builder{}, errEmptySet
		}
	}

	dsb := Builder{
		newDomainMatcherBuilderFunc(dskr[0]),
		newSuffixMatcherBuilderFunc(dskr[1]),
		newKeywordMatcherBuilderFunc(dskr[2]),
		newRegexpMatcherBuilderFunc(dskr[3]),
	}

	for {
		// domainPrefixLen == suffixPrefixLen == regexpPrefixLen == 7
		if len(line) <= 7 {
			if line[0] != '#' {
				return dsb, fmt.Errorf("invalid line: %s", line)
			}
			goto next
		}

		switch line[:7] {
		case suffixPrefix:
			dsb.SuffixMatcherBuilder().Insert(strings.Clone(line[7:]))
		case domainPrefix:
			dsb.DomainMatcherBuilder().Insert(strings.Clone(line[7:]))
		case regexpPrefix:
			dsb.RegexpMatcherBuilder().Insert(strings.Clone(line[7:]))
		default:
			switch {
			case len(line) > keywordPrefixLen && string(line[:keywordPrefixLen]) == keywordPrefix:
				dsb.KeywordMatcherBuilder().Insert(strings.Clone(line[keywordPrefixLen:]))
			case line[0] != '#':
				return dsb, fmt.Errorf("invalid line: %s", line)
			}
		}

	next:
		line, text = bytestrings.NextNonEmptyLine(text)
		if len(line) == 0 {
			break
		}
	}

	return dsb, nil
}

func ParseCapacityHint(line string) ([4]int, bool, error) {
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

// BuilderGob is the builder's gob serialization structure.
type BuilderGob struct {
	Domains  DomainMapMatcher
	Suffixes DomainSuffixTrie
	Keywords KeywordLinearMatcher
	Regexps  RegexpMatcherBuilder
}

func (bg BuilderGob) Builder() Builder {
	return Builder{&bg.Domains, &bg.Suffixes, &bg.Keywords, &bg.Regexps}
}

func (bg BuilderGob) WriteGob(w io.Writer) error {
	return gob.NewEncoder(w).Encode(bg)
}

func BuilderGobFromBuilder(dsb Builder) (bg BuilderGob) {
	switch d := dsb.DomainMatcherBuilder().(type) {
	case *DomainMapMatcher:
		bg.Domains = *d
	default:
		bg.Domains = DomainMapMatcherFromSeq(d.Rules())
	}

	switch s := dsb.SuffixMatcherBuilder().(type) {
	case *DomainSuffixTrie:
		bg.Suffixes = *s
	default:
		bg.Suffixes = DomainSuffixTrieFromSeq(s.Rules())
	}

	switch k := dsb.KeywordMatcherBuilder().(type) {
	case *KeywordLinearMatcher:
		bg.Keywords = *k
	default:
		bg.Keywords = KeywordLinearMatcherFromSeq(k.Rules())
	}

	switch r := dsb.RegexpMatcherBuilder().(type) {
	case *RegexpMatcherBuilder:
		bg.Regexps = *r
	default:
		bg.Regexps = RegexpMatcherBuilderFromSeq(r.Rules())
	}

	return bg
}

func BuilderGobFromReader(r io.Reader) (bg BuilderGob, err error) {
	err = gob.NewDecoder(r).Decode(&bg)
	return
}

// DomainSet is a set of domain matchers built from matching rules.
type DomainSet []Matcher

// Match returns whether the domain set contains the domain.
func (ds DomainSet) Match(domain string) bool {
	for _, m := range ds {
		if m.Match(domain) {
			return true
		}
	}
	return false
}
