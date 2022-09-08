package domainset

type DomainSuffixMap struct {
	Suffixes map[string]struct{}
}

func NewDomainSuffixMap(capacity int) *DomainSuffixMap {
	return &DomainSuffixMap{
		Suffixes: make(map[string]struct{}, capacity),
	}
}

func (dsm *DomainSuffixMap) Match(domain string) bool {
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}
		if _, ok := dsm.Suffixes[domain[i+1:]]; ok {
			return true
		}
	}
	_, ok := dsm.Suffixes[domain]
	return ok
}
