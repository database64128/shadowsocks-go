package domainset

import (
	"regexp"

	"github.com/database64128/shadowsocks-go/slicehelper"
)

// RegexpMatcher adapts [regexp.Regexp] to the [Matcher] interface.
type RegexpMatcher regexp.Regexp

// Match implements the Matcher Match method.
func (rlmp *RegexpMatcher) Match(domain string) bool {
	return (*regexp.Regexp)(rlmp).MatchString(domain)
}

// RegexpMatcherBuilder stores regular expressions for building [RegexpMatcher] instances.
type RegexpMatcherBuilder []string

// NewRegexpMatcherBuilder creates a new [RegexpMatcherBuilder] with the specified initial capacity.
func NewRegexpMatcherBuilder(capacity int) MatcherBuilder {
	rmb := make(RegexpMatcherBuilder, 0, capacity)
	return &rmb
}

// Insert implements the MatcherBuilder Insert method.
func (rmbp *RegexpMatcherBuilder) Insert(rule string) {
	*rmbp = append(*rmbp, rule)
}

// Rules implements the MatcherBuilder Rules method.
func (rmb RegexpMatcherBuilder) Rules() []string {
	return rmb
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (rmb RegexpMatcherBuilder) MatcherCount() int {
	return len(rmb)
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (rmb RegexpMatcherBuilder) AppendTo(matchers []Matcher) ([]Matcher, error) {
	if len(rmb) == 0 {
		return matchers, nil
	}

	head, tail := slicehelper.Extend(matchers, len(rmb))

	for i, r := range rmb {
		re, err := regexp.Compile(r)
		if err != nil {
			return matchers, err
		}
		tail[i] = (*RegexpMatcher)(re)
	}

	return head, nil
}
