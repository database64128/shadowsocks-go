package domainset

import (
	"iter"
	"maps"
	"slices"
)

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

// SuffixLinearMatcherFromSeq creates a [SuffixLinearMatcher] from a sequence of suffix rules.
func SuffixLinearMatcherFromSeq(suffixCount int, suffixSeq iter.Seq[string]) SuffixLinearMatcher {
	slm := make(SuffixLinearMatcher, 0, suffixCount)
	return slices.AppendSeq(slm, suffixSeq)
}

// Match implements [Matcher.Match].
func (slm SuffixLinearMatcher) Match(domain string) bool {
	for _, suffix := range slm {
		if matchDomainSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// Insert implements [MatcherBuilder.Insert].
func (slmp *SuffixLinearMatcher) Insert(rule string) {
	*slmp = append(*slmp, rule)
}

// Clear implements [MatcherBuilder.Clear].
func (slmp *SuffixLinearMatcher) Clear() {
	*slmp = (*slmp)[:0]
}

// Rules implements [MatcherBuilder.Rules].
func (slm SuffixLinearMatcher) Rules() (int, iter.Seq[string]) {
	return len(slm), slices.Values(slm)
}

// MatcherCount implements [MatcherBuilder.MatcherCount].
func (slm SuffixLinearMatcher) MatcherCount() int {
	if len(slm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements [MatcherBuilder.AppendTo].
func (slmp *SuffixLinearMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	slm := *slmp

	if len(slm) == 0 {
		return matchers, nil
	}

	if len(slm) > MaxLinearSuffixes {
		dst := DomainSuffixTrieFromSlice(slm)
		return dst.AppendTo(matchers)
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

// SuffixMapMatcherFromSeq creates a [SuffixMapMatcher] from a sequence of suffix rules.
func SuffixMapMatcherFromSeq(suffixCount int, suffixSeq iter.Seq[string]) SuffixMapMatcher {
	smm := make(SuffixMapMatcher, suffixCount)
	for suffix := range suffixSeq {
		smm.Insert(suffix)
	}
	return smm
}

// Match implements [Matcher.Match].
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

// Insert implements [MatcherBuilder.Insert].
func (smm SuffixMapMatcher) Insert(rule string) {
	smm[rule] = struct{}{}
}

// Clear implements [MatcherBuilder.Clear].
func (smm SuffixMapMatcher) Clear() {
	clear(smm)
}

// Rules implements [MatcherBuilder.Rules].
func (smm SuffixMapMatcher) Rules() (int, iter.Seq[string]) {
	return len(smm), maps.Keys(smm)
}

// MatcherCount implements [MatcherBuilder.MatcherCount].
func (smm SuffixMapMatcher) MatcherCount() int {
	if len(smm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements [MatcherBuilder.AppendTo].
func (smmp *SuffixMapMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	smm := *smmp

	if len(smm) == 0 {
		return matchers, nil
	}

	// With 16 suffix rules, a linear matcher is still mostly faster than a map matcher.
	// But a linear matcher will migrate to a trie matcher when the number of rules exceeds 4.
	// So we only migrate to a linear matcher when the number of rules does not exceed 4.
	if len(smm) <= MaxLinearSuffixes {
		slm := SuffixLinearMatcherFromSeq(smm.Rules())
		return slm.AppendTo(matchers)
	}

	return append(matchers, smmp), nil
}
