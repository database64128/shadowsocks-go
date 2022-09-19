package domainset

import "strings"

// KeywordLinearMatcher matches keyword rules by iterating over the keywords.
type KeywordLinearMatcher []string

// NewKeywordLinearMatcher creates a [KeywordLinearMatcher] with the specified initial capacity.
func NewKeywordLinearMatcher(capacity int) MatcherBuilder {
	klm := make(KeywordLinearMatcher, 0, capacity)
	return &klm
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

// Insert implements the MatcherBuilder Insert method.
func (klmp *KeywordLinearMatcher) Insert(rule string) {
	*klmp = append(*klmp, rule)
}

// Rules implements the MatcherBuilder Rules method.
func (klm KeywordLinearMatcher) Rules() []string {
	return klm
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (klm KeywordLinearMatcher) MatcherCount() int {
	if len(klm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (klm KeywordLinearMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	if len(klm) == 0 {
		return matchers, nil
	}
	return append(matchers, klm), nil
}
