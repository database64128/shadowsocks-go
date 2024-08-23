package domainset

import (
	"slices"
	"testing"
)

func testMatcher(t *testing.T, m Matcher, domain string, expectedResult bool) {
	t.Helper()
	if m.Match(domain) != expectedResult {
		t.Errorf("%s should return %v", domain, expectedResult)
	}
}

func testMatcherBuilderRules(t *testing.T, mb MatcherBuilder, expectedRules []string) {
	t.Helper()

	ruleCount, ruleSeq := mb.Rules()
	rules := slices.AppendSeq(make([]string, 0, ruleCount), ruleSeq)
	slices.Sort(rules)

	sortedExpectedRules := slices.Clone(expectedRules)
	slices.Sort(sortedExpectedRules)

	if !slices.Equal(rules, sortedExpectedRules) {
		t.Errorf("Expected rules %v, got %v", sortedExpectedRules, rules)
	}
}
