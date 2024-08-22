package domainset

import "testing"

func testMatcher(t *testing.T, m Matcher, domain string, expectedResult bool) {
	t.Helper()
	if m.Match(domain) != expectedResult {
		t.Errorf("%s should return %v", domain, expectedResult)
	}
}
