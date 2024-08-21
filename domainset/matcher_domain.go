package domainset

import (
	"iter"
	"maps"
	"slices"

	"github.com/database64128/shadowsocks-go/maphelper"
)

// MaxLinearDomains is the maximum number of domain rules under which a linear matcher can outperform a map matcher.
const MaxLinearDomains = 16

// DomainLinearMatcher matches domain rules using linear search.
// It is faster than [DomainMapMatcher] when the number of rules is
// no greater than [MaxLinearDomains].
type DomainLinearMatcher []string

// NewDomainLinearMatcher creates a [DomainLinearMatcher] with the specified initial capacity.
func NewDomainLinearMatcher(capacity int) MatcherBuilder {
	dlm := make(DomainLinearMatcher, 0, capacity)
	return &dlm
}

// Match implements the Matcher Match method.
func (dlm DomainLinearMatcher) Match(domain string) bool {
	return slices.Contains(dlm, domain)
}

// Insert implements the MatcherBuilder Insert method.
func (dlmp *DomainLinearMatcher) Insert(rule string) {
	*dlmp = append(*dlmp, rule)
}

// Rules implements the MatcherBuilder Rules method.
func (dlm DomainLinearMatcher) Rules() (int, iter.Seq[string]) {
	return len(dlm), slices.Values(dlm)
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (dlm DomainLinearMatcher) MatcherCount() int {
	if len(dlm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (dlmp *DomainLinearMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	dlm := *dlmp

	if len(dlm) == 0 {
		return matchers, nil
	}

	if len(dlm) > MaxLinearDomains {
		dmm := DomainMapMatcherFromSlice(dlm)
		return dmm.AppendTo(matchers)
	}

	return append(matchers, dlmp), nil
}

// DomainBinarySearchMatcher matches domain rules using binary search.
type DomainBinarySearchMatcher []string

// NewDomainBinarySearchMatcher creates a [DomainBinarySearchMatcher] with the specified initial capacity.
func NewDomainBinarySearchMatcher(capacity int) MatcherBuilder {
	dbsm := make(DomainBinarySearchMatcher, 0, capacity)
	return &dbsm
}

// DomainBinarySearchMatcherFromSlice creates a [DomainBinarySearchMatcher] from a slice of domain rules.
func DomainBinarySearchMatcherFromSlice(domains []string) DomainBinarySearchMatcher {
	slices.Sort(domains)
	return domains
}

// Match implements the Matcher Match method.
func (dbsm DomainBinarySearchMatcher) Match(domain string) bool {
	_, found := slices.BinarySearch(dbsm, domain)
	return found
}

// Insert implements the MatcherBuilder Insert method.
func (dbsmp *DomainBinarySearchMatcher) Insert(rule string) {
	index, found := slices.BinarySearch(*dbsmp, rule)
	if !found {
		*dbsmp = slices.Insert(*dbsmp, index, rule)
	}
}

// Rules implements the MatcherBuilder Rules method.
func (dbsm DomainBinarySearchMatcher) Rules() (int, iter.Seq[string]) {
	return len(dbsm), slices.Values(dbsm)
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (dbsm DomainBinarySearchMatcher) MatcherCount() int {
	if len(dbsm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (dbsmp *DomainBinarySearchMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	dbsm := *dbsmp

	if len(dbsm) == 0 {
		return matchers, nil
	}

	return append(matchers, dbsmp), nil
}

// DomainMapMatcher matches domain rules using a map.
// It is faster than [DomainLinearMatcher] when the number of rules is
// greater than [MaxLinearDomains].
type DomainMapMatcher map[string]struct{}

// NewDomainMapMatcher creates a [DomainMapMatcher] with the specified initial capacity.
func NewDomainMapMatcher(capacity int) MatcherBuilder {
	dmm := make(DomainMapMatcher, capacity)
	return &dmm
}

// DomainMapMatcherFromSlice creates a [DomainMapMatcher] from a slice of domain rules.
func DomainMapMatcherFromSlice(domains []string) DomainMapMatcher {
	dmm := make(DomainMapMatcher, len(domains))
	for _, domain := range domains {
		dmm.Insert(domain)
	}
	return dmm
}

// DomainMapMatcherFromSeq creates a [DomainMapMatcher] from a sequence of domain rules.
func DomainMapMatcherFromSeq(domainCount int, domainSeq iter.Seq[string]) DomainMapMatcher {
	dmm := make(DomainMapMatcher, domainCount)
	for domain := range domainSeq {
		dmm.Insert(domain)
	}
	return dmm
}

// Match implements the Matcher Match method.
func (dmm DomainMapMatcher) Match(domain string) bool {
	_, ok := dmm[domain]
	return ok
}

// Insert implements the MatcherBuilder Insert method.
func (dmm DomainMapMatcher) Insert(rule string) {
	dmm[rule] = struct{}{}
}

// Rules implements the MatcherBuilder Rules method.
func (dmm DomainMapMatcher) Rules() (int, iter.Seq[string]) {
	return len(dmm), maps.Keys(dmm)
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (dmm DomainMapMatcher) MatcherCount() int {
	if len(dmm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (dmmp *DomainMapMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	dmm := *dmmp

	if len(dmm) == 0 {
		return matchers, nil
	}

	if len(dmm) <= MaxLinearDomains {
		dlm := DomainLinearMatcher(maphelper.Keys(dmm))
		return dlm.AppendTo(matchers)
	}

	return append(matchers, dmm), nil
}
