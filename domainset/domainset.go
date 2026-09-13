package domainset

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"

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

// Config is the configuration for a [DomainSet].
type Config struct {
	// Name is the name of the domain set.
	Name string `json:"name"`

	// Type is the type of the domain set.
	//
	//	- "text": text format (default)
	//	- "gob": gob format
	Type string `json:"type,omitzero"`

	// Path is the path to the domain set file.
	Path string `json:"path"`
}

// DomainSet creates a [DomainSet] from the configuration.
func (dsc Config) DomainSet() (DomainSet, error) {
	var (
		dsb Builder
		err error
	)

	switch dsc.Type {
	case "text", "":
		// Benchmarking shows that reading the whole file and then parsing it is faster than
		// mmapping and cloning strings, with a slight increase in memory usage.

		var data []byte
		data, err = os.ReadFile(dsc.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read domain set file: %w", err)
		}
		dsb, err = BuilderFromText(unsafe.String(unsafe.SliceData(data), len(data)))

	case "gob":
		var (
			data  string
			close func() error
		)
		data, close, err = mmap.ReadFile[string](dsc.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read domain set file: %w", err)
		}
		dsb, err = BuilderFromGobString(data)
		_ = close()

	default:
		return nil, fmt.Errorf("invalid domain set type: %q", dsc.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse domain set file: %w", err)
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

// DomainSet builds the matchers and returns them as a [DomainSet].
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

// WriteGob writes the builder to the writer in gob format.
func (dsb Builder) WriteGob(w io.Writer) error {
	return BuilderGobFromBuilder(dsb).WriteGob(w)
}

// WriteText writes the builder to the writer in text format.
func (dsb Builder) WriteText(w io.Writer) error {
	domainCount, domainSeq := dsb.DomainMatcherBuilder().Rules()
	suffixCount, suffixSeq := dsb.SuffixMatcherBuilder().Rules()
	keywordCount, keywordSeq := dsb.KeywordMatcherBuilder().Rules()
	regexpCount, regexpSeq := dsb.RegexpMatcherBuilder().Rules()
	capacityHint := fmt.Sprintf("%s%d %d %d %d %s\n", capacityHintPrefix, domainCount, suffixCount, keywordCount, regexpCount, capacityHintSuffix)

	bw := bufio.NewWriterSize(w, 128*1024)
	if _, err := bw.WriteString(capacityHint); err != nil {
		return err
	}

	for domain := range domainSeq {
		if _, err := bw.WriteString(domainPrefix); err != nil {
			return err
		}
		if _, err := bw.WriteString(domain); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}

	for suffix := range suffixSeq {
		if _, err := bw.WriteString(suffixPrefix); err != nil {
			return err
		}
		if _, err := bw.WriteString(suffix); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}

	for keyword := range keywordSeq {
		if _, err := bw.WriteString(keywordPrefix); err != nil {
			return err
		}
		if _, err := bw.WriteString(keyword); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}

	for regexp := range regexpSeq {
		if _, err := bw.WriteString(regexpPrefix); err != nil {
			return err
		}
		if _, err := bw.WriteString(regexp); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}

	return bw.Flush()
}

// BuilderFromGob reads a gob-encoded builder from the reader.
func BuilderFromGob(r io.Reader) (Builder, error) {
	bg, err := BuilderGobFromReader(r)
	if err != nil {
		return Builder{}, err
	}
	return bg.Builder(), nil
}

// BuilderFromGobString reads a gob-encoded builder from the string.
func BuilderFromGobString(s string) (Builder, error) {
	r := strings.NewReader(s)
	return BuilderFromGob(r)
}

// TextLineError represents a text format deserialization error.
type TextLineError struct {
	Line int
	Err  error
}

func (e TextLineError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

func (e TextLineError) Unwrap() error {
	return e.Err
}

var ErrInvalidRuleLine = errors.New("invalid rule line")

func newInvalidRuleLineError(line string) error {
	return fmt.Errorf("%w: %q", ErrInvalidRuleLine, line)
}

// BuilderFromText parses the text for domain set rules, inserts them into appropriate
// matcher builders, and returns the resulting domain set builder.
//
// The rule strings are not cloned. They reference the same memory as the input text.
func BuilderFromText(text string) (Builder, error) {
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
		NewDomainMapMatcher(dskr[0]),
		NewDomainSuffixTrieMatcherBuilder(dskr[1]),
		NewKeywordLinearMatcher(dskr[2]),
		NewRegexpMatcherBuilder(dskr[3]),
	}

	for {
		// domainPrefixLen == suffixPrefixLen == regexpPrefixLen == 7
		if len(line) > 7 {
			switch line[:7] {
			case suffixPrefix:
				dsb.SuffixMatcherBuilder().Insert(line[suffixPrefixLen:])
				goto next
			case domainPrefix:
				dsb.DomainMatcherBuilder().Insert(line[domainPrefixLen:])
				goto next
			case regexpPrefix:
				dsb.RegexpMatcherBuilder().Insert(line[regexpPrefixLen:])
				goto next
			case keywordPrefix[:7]:
				if len(line) <= keywordPrefixLen || line[7] != keywordPrefix[7] {
					return dsb, fmt.Errorf("invalid line: %q", line)
				}
				dsb.KeywordMatcherBuilder().Insert(line[keywordPrefixLen:])
				goto next
			}
		}

		if line[0] != '#' {
			return dsb, fmt.Errorf("invalid line: %q", line)
		}

	next:
		line, text = bytestrings.NextNonEmptyLine(text)
		if len(line) == 0 {
			break
		}
	}

	return dsb, nil
}

// ParseCapacityHint parses the capacity hint from the line.
func ParseCapacityHint(line string) (dskr [4]int, found bool, err error) {
	found = len(line) > capacityHintPrefixLen && line[:capacityHintPrefixLen] == capacityHintPrefix
	if found {
		h := line[capacityHintPrefixLen:]

		for i := range dskr {
			delimiterIndex := strings.IndexByte(h, ' ')
			if delimiterIndex == -1 {
				return dskr, found, fmt.Errorf("bad capacity hint %q", line)
			}

			c, err := strconv.Atoi(h[:delimiterIndex])
			if err != nil {
				return dskr, found, fmt.Errorf("bad capacity hint %q: %w", line, err)
			}
			if c < 0 {
				return dskr, found, fmt.Errorf("bad capacity hint %q: capacity cannot be negative", line)
			}
			dskr[i] = c
			h = h[delimiterIndex+1:]
		}

		if h != capacityHintSuffix {
			return dskr, found, fmt.Errorf("bad capacity hint %q: expected suffix %q", line, capacityHintSuffix)
		}
	}

	return dskr, found, nil
}

// BuilderFromDLC parses text in v2fly/domain-list-community exported plaintext format for domain set rules,
// inserts them into appropriate matcher builders, and returns the resulting domain set builder.
//
// The rule strings are not cloned. They reference the same memory as the input text.
func BuilderFromDLC(text, wantAttr string) (Builder, error) {
	const (
		domainPrefix     = "full:"
		suffixPrefix     = "domain:"
		keywordPrefix    = "keyword:"
		regexpPrefix     = "regexp:"
		domainPrefixLen  = len(domainPrefix)
		suffixPrefixLen  = len(suffixPrefix)
		keywordPrefixLen = len(keywordPrefix)
		regexpPrefixLen  = len(regexpPrefix)
		minPrefixLen     = min(domainPrefixLen, suffixPrefixLen, keywordPrefixLen, regexpPrefixLen)
	)

	dsb := Builder{
		NewDomainMapMatcher(0),
		NewDomainSuffixTrieMatcherBuilder(0),
		NewKeywordLinearMatcher(0),
		NewRegexpMatcherBuilder(0),
	}

	var lineNum int
	for line := range strings.Lines(text) {
		lineNum++
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		rule, attrs, hasAttrs := strings.CutLast(line, ":@")
		if wantAttr != "" {
			if !hasAttrs {
				continue
			}
			var found bool
			for attr := range strings.SplitSeq(attrs, ",@") {
				if attr == wantAttr {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// As of Go 1.27, some of the bounds checks below cannot be eliminated,
		// because the string equality comparisons call into Go runtime assembly
		// routines, which invalidate the earlier length guards.
		//
		// We could work around this by switching to handwritten byte-by-byte
		// comparisons, but this function is not in any hot path, so we opt for
		// better readability and hope for future compiler improvements to address this.

		if len(rule) > minPrefixLen {
			switch rule[:minPrefixLen] {
			case domainPrefix[:minPrefixLen]:
				if len(rule) > domainPrefixLen && rule[minPrefixLen:domainPrefixLen] == domainPrefix[minPrefixLen:] {
					dsb.DomainMatcherBuilder().Insert(rule[domainPrefixLen:])
					continue
				}
			case suffixPrefix[:minPrefixLen]:
				if len(rule) > suffixPrefixLen && rule[minPrefixLen:suffixPrefixLen] == suffixPrefix[minPrefixLen:] {
					dsb.SuffixMatcherBuilder().Insert(rule[suffixPrefixLen:])
					continue
				}
			case keywordPrefix[:minPrefixLen]:
				if len(rule) > keywordPrefixLen && rule[minPrefixLen:keywordPrefixLen] == keywordPrefix[minPrefixLen:] {
					dsb.KeywordMatcherBuilder().Insert(rule[keywordPrefixLen:])
					continue
				}
			case regexpPrefix[:minPrefixLen]:
				if len(rule) > regexpPrefixLen && rule[minPrefixLen:regexpPrefixLen] == regexpPrefix[minPrefixLen:] {
					dsb.RegexpMatcherBuilder().Insert(rule[regexpPrefixLen:])
					continue
				}
			}
		}

		return dsb, TextLineError{Line: lineNum, Err: newInvalidRuleLineError(line)}
	}

	return dsb, nil
}

// BuilderGob is a gob-encoded representation of a [Builder].
type BuilderGob struct {
	Domains  DomainMapMatcher
	Suffixes DomainSuffixTrie
	Keywords KeywordLinearMatcher
	Regexps  RegexpMatcherBuilder
}

// Builder returns a [Builder] from the gob representation.
func (bg BuilderGob) Builder() Builder {
	return Builder{&bg.Domains, &bg.Suffixes, &bg.Keywords, &bg.Regexps}
}

// WriteGob writes the gob representation to the writer.
func (bg BuilderGob) WriteGob(w io.Writer) error {
	return gob.NewEncoder(w).Encode(bg)
}

// BuilderGobFromBuilder converts a [Builder] to its gob representation.
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

// BuilderGobFromReader reads a gob representation from the reader.
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
