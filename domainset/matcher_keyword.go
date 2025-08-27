package domainset

import (
	"iter"
	"slices"
	"strings"
)

// KeywordLinearMatcher matches keyword rules by iterating over the keywords.
type KeywordLinearMatcher []string

// NewKeywordLinearMatcher creates a [KeywordLinearMatcher] with the specified initial capacity.
func NewKeywordLinearMatcher(capacity int) MatcherBuilder {
	klm := make(KeywordLinearMatcher, 0, capacity)
	return &klm
}

// KeywordLinearMatcherFromSeq creates a [KeywordLinearMatcher] from a sequence of keyword rules.
func KeywordLinearMatcherFromSeq(keywordCount int, keywordSeq iter.Seq[string]) KeywordLinearMatcher {
	klm := make(KeywordLinearMatcher, 0, keywordCount)
	return slices.AppendSeq(klm, keywordSeq)
}

// Match implements the Matcher Match method.
func (klm KeywordLinearMatcher) Match(domain string) bool {
	for _, keyword := range klm {
		if strings.Contains(domain, keyword) {
			return true
		}
	}
	return false
}

// Insert implements [MatcherBuilder.Insert].
func (klmp *KeywordLinearMatcher) Insert(rule string) {
	*klmp = append(*klmp, rule)
}

// Clear implements [MatcherBuilder.Clear].
func (klmp *KeywordLinearMatcher) Clear() {
	*klmp = (*klmp)[:0]
}

// Rules implements [MatcherBuilder.Rules].
func (klm KeywordLinearMatcher) Rules() (int, iter.Seq[string]) {
	return len(klm), slices.Values(klm)
}

// MatcherCount implements [MatcherBuilder.MatcherCount].
func (klm KeywordLinearMatcher) MatcherCount() int {
	if len(klm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements [MatcherBuilder.AppendTo].
func (klmp *KeywordLinearMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	klm := *klmp
	if len(klm) == 0 {
		return matchers, nil
	}
	return append(matchers, klmp), nil
}
