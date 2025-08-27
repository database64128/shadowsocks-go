package domainset

import (
	"iter"
	"maps"
	"slices"
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

// DomainLinearMatcherFromSeq creates a [DomainLinearMatcher] from a sequence of domain rules.
func DomainLinearMatcherFromSeq(domainCount int, domainSeq iter.Seq[string]) DomainLinearMatcher {
	dlm := make(DomainLinearMatcher, 0, domainCount)
	return slices.AppendSeq(dlm, domainSeq)
}

// Match implements [Matcher.Match].
func (dlm DomainLinearMatcher) Match(domain string) bool {
	return slices.Contains(dlm, domain)
}

// Insert implements [MatcherBuilder.Insert].
func (dlmp *DomainLinearMatcher) Insert(rule string) {
	*dlmp = append(*dlmp, rule)
}

// Clear implements [MatcherBuilder.Clear].
func (dlmp *DomainLinearMatcher) Clear() {
	*dlmp = (*dlmp)[:0]
}

// Rules implements [MatcherBuilder.Rules].
func (dlm DomainLinearMatcher) Rules() (int, iter.Seq[string]) {
	return len(dlm), slices.Values(dlm)
}

// MatcherCount implements [MatcherBuilder.MatcherCount].
func (dlm DomainLinearMatcher) MatcherCount() int {
	if len(dlm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements [MatcherBuilder.AppendTo].
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
type DomainBinarySearchMatcher struct {
	domains []string
}

// NewDomainBinarySearchMatcher creates a [DomainBinarySearchMatcher] with the specified initial capacity.
func NewDomainBinarySearchMatcher(capacity int) MatcherBuilder {
	domains := make([]string, 0, capacity)
	return &DomainBinarySearchMatcher{domains}
}

// DomainBinarySearchMatcherFromSlice creates a [DomainBinarySearchMatcher] from a slice of domain rules.
func DomainBinarySearchMatcherFromSlice(domains []string) DomainBinarySearchMatcher {
	dbsm := DomainBinarySearchMatcher{
		domains: make([]string, 0, len(domains)),
	}
	for _, domain := range domains {
		dbsm.Insert(domain)
	}
	return dbsm
}

// DomainBinarySearchMatcherFromSeq creates a [DomainBinarySearchMatcher] from a sequence of domain rules.
func DomainBinarySearchMatcherFromSeq(domainCount int, domainSeq iter.Seq[string]) DomainBinarySearchMatcher {
	dbsm := DomainBinarySearchMatcher{
		domains: make([]string, 0, domainCount),
	}
	for domain := range domainSeq {
		dbsm.Insert(domain)
	}
	return dbsm
}

// Match implements [Matcher.Match].
func (dbsm DomainBinarySearchMatcher) Match(domain string) bool {
	_, found := slices.BinarySearch(dbsm.domains, domain)
	return found
}

// Insert implements [MatcherBuilder.Insert].
func (dbsm *DomainBinarySearchMatcher) Insert(rule string) {
	index, found := slices.BinarySearch(dbsm.domains, rule)
	if !found {
		dbsm.domains = slices.Insert(dbsm.domains, index, rule)
	}
}

// Clear implements [MatcherBuilder.Clear].
func (dbsm *DomainBinarySearchMatcher) Clear() {
	dbsm.domains = dbsm.domains[:0]
}

// Rules implements [MatcherBuilder.Rules].
func (dbsm DomainBinarySearchMatcher) Rules() (int, iter.Seq[string]) {
	return len(dbsm.domains), slices.Values(dbsm.domains)
}

// MatcherCount implements [MatcherBuilder.MatcherCount].
func (dbsm DomainBinarySearchMatcher) MatcherCount() int {
	if len(dbsm.domains) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements [MatcherBuilder.AppendTo].
func (dbsm *DomainBinarySearchMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	if len(dbsm.domains) == 0 {
		return matchers, nil
	}
	return append(matchers, dbsm), nil
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

// Match implements [Matcher.Match].
func (dmm DomainMapMatcher) Match(domain string) bool {
	_, ok := dmm[domain]
	return ok
}

// Insert implements [MatcherBuilder.Insert].
func (dmm DomainMapMatcher) Insert(rule string) {
	dmm[rule] = struct{}{}
}

// Clear implements [MatcherBuilder.Clear].
func (dmm DomainMapMatcher) Clear() {
	clear(dmm)
}

// Rules implements [MatcherBuilder.Rules].
func (dmm DomainMapMatcher) Rules() (int, iter.Seq[string]) {
	return len(dmm), maps.Keys(dmm)
}

// MatcherCount implements [MatcherBuilder.MatcherCount].
func (dmm DomainMapMatcher) MatcherCount() int {
	if len(dmm) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements [MatcherBuilder.AppendTo].
func (dmmp *DomainMapMatcher) AppendTo(matchers []Matcher) ([]Matcher, error) {
	dmm := *dmmp

	if len(dmm) == 0 {
		return matchers, nil
	}

	if len(dmm) <= MaxLinearDomains {
		dlm := DomainLinearMatcherFromSeq(dmm.Rules())
		return dlm.AppendTo(matchers)
	}

	return append(matchers, dmmp), nil
}
