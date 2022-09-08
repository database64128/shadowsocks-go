package domainset

type DomainSuffixSet interface {
	Match(domain string) bool
}

type EmptyDomainSuffixSet struct{}

func (EmptyDomainSuffixSet) Match(string) bool {
	return false
}

var DefaultEmptyDomainSuffixSet = EmptyDomainSuffixSet{}
