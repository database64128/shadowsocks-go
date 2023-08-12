package domainset

import "github.com/database64128/shadowsocks-go/maphelper"

// MaxLinearSuffixes is the maximum number of suffix rules under which a linear matcher can outperform a trie matcher.
const MaxLinearSuffixes = 4

// SuffixLinearMatcher matches suffix rules by iterating over the suffixes.
// It is faster than [SuffixTrieMatcher] when the number of rules is
// no greater than [MaxLinearSuffixes].
type SuffixLinearMatcher []string

// NewSuffixLinearMatcher creates a [SuffixLinearMatcher] with the specified initial capacity.
func NewSuffixLinearMatcher(capacity int) MatcherBuilder {
	slm := make(SuffixLinearMatcher, 0, capacity)
	return &slm
}

// Match implements the Matcher Match method.
func (slm SuffixLinearMatcher) Match(domain string) bool {
	for _, suffix := range slm {
		if matchDomainSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// Insert implements the MatcherBuilder Insert method.
func (slmp *SuffixLinearMatcher) Insert(rule string) {
	*slmp = append(*slmp, rule)
}

// Rules implements the MatcherBuilder Rules method.
func (slm SuffixLinearMatcher) Rules() []string {
	return slm
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (slm SuffixLinearMatcher) MatcherCount() int {
	if len(slm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (slmp *SuffixLinearMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	slm := *slmp

	if len(slm) == 0 {
		return matchers, nil
	}

	if len(slm) > MaxLinearSuffixes {
		return append(matchers, DomainSuffixTrieFromSlice(slm)), nil
	}

	return append(matchers, slmp), nil
}

func matchDomainSuffix(domain, suffix string) bool {
	return domain == suffix || len(domain) > len(suffix) && domain[len(domain)-len(suffix)-1] == '.' && domain[len(domain)-len(suffix):] == suffix
}

// SuffixMapMatcher matches suffix rules using a single map.
type SuffixMapMatcher map[string]struct{}

// NewSuffixMapMatcher creates a [SuffixMapMatcher] with the specified initial capacity.
func NewSuffixMapMatcher(capacity int) MatcherBuilder {
	smm := make(SuffixMapMatcher, capacity)
	return &smm
}

// SuffixMapMatcherFromSlice creates a [SuffixMapMatcher] from a slice of suffix rules.
func SuffixMapMatcherFromSlice(suffixes []string) SuffixMapMatcher {
	smm := make(SuffixMapMatcher, len(suffixes))
	for _, suffix := range suffixes {
		smm.Insert(suffix)
	}
	return smm
}

// Match implements the Matcher Match method.
func (smm SuffixMapMatcher) Match(domain string) bool {
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}
		if _, ok := smm[domain[i+1:]]; ok {
			return true
		}
	}
	_, ok := smm[domain]
	return ok
}

// Insert implements the MatcherBuilder Insert method.
func (smm SuffixMapMatcher) Insert(rule string) {
	smm[rule] = struct{}{}
}

// Rules implements the MatcherBuilder Rules method.
func (smm SuffixMapMatcher) Rules() []string {
	return maphelper.Keys(smm)
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (smm SuffixMapMatcher) MatcherCount() int {
	if len(smm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (smmp *SuffixMapMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	smm := *smmp

	if len(smm) == 0 {
		return matchers, nil
	}

	if len(smm) <= MaxLinearSuffixes {
		slm := SuffixLinearMatcher(maphelper.Keys(smm))
		return slm.AppendTo(matchers)
	}

	return append(matchers, smmp), nil
}
