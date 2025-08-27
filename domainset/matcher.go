package domainset

import "iter"

// Matcher provides functionality for matching domain names against a set of rules.
type Matcher interface {
	// Match returns whether the domain is matched by the matcher.
	Match(domain string) bool
}

// MatcherBuilder provides methods for building a [Matcher].
type MatcherBuilder interface {
	// Insert inserts the rule string to the matcher.
	//
	// The rule string must not include the rule identifier.
	// For example, if the rule line is "suffix:google.com",
	// the rule string should be "google.com".
	Insert(rule string)

	// Clear removes all rules from the matcher.
	Clear()

	// Rules returns the number of rules and an iterator over them.
	Rules() (int, iter.Seq[string])

	// MatcherCount returns the number of matchers that would be appended
	// to the matcher slice by calling [AppendTo].
	MatcherCount() int

	// AppendTo builds the matcher, appends the matcher to the matcher slice,
	// and returns the updated slice or an error.
	AppendTo(matchers []Matcher) ([]Matcher, error)
}
