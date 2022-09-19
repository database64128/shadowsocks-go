package domainset

// DomainSuffixTrie is a trie of domain parts segmented by '.'.
type DomainSuffixTrie struct {
	Included bool
	Children map[string]*DomainSuffixTrie
}

// Insert inserts a domain suffix to the trie.
// Insertion purges the leaf node's children.
// If say, we insert "www.google.com" and then "google.com",
// The children of node "google" will be purged.
func (dst *DomainSuffixTrie) Insert(domain string) {
	cdst := dst

	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}

		part := domain[i+1:]
		domain = domain[:i]
		if cdst.Children == nil {
			var ndst DomainSuffixTrie
			cdst.Children = map[string]*DomainSuffixTrie{
				part: &ndst,
			}
			cdst = &ndst
		} else {
			ndst, ok := cdst.Children[part]
			switch {
			case !ok:
				ndst = &DomainSuffixTrie{}
				cdst.Children[part] = ndst
				cdst = ndst
			case ndst.Included:
				return
			default:
				cdst = ndst
			}
		}
	}

	if cdst.Children == nil {
		cdst.Children = map[string]*DomainSuffixTrie{
			domain: {
				Included: true,
			},
		}
	} else {
		ndst, ok := cdst.Children[domain]
		if !ok {
			cdst.Children[domain] = &DomainSuffixTrie{
				Included: true,
			}
		} else {
			ndst.Included = true
			ndst.Children = nil
		}
	}
}

// Match implements the Matcher Match method.
func (dst *DomainSuffixTrie) Match(domain string) bool {
	cdst := dst

	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}

		if cdst.Children == nil {
			return false
		}

		ndst, ok := cdst.Children[domain[i+1:]]
		if !ok {
			return false
		}
		if ndst.Included {
			return true
		}
		cdst = ndst
		domain = domain[:i]
	}

	ndst, ok := cdst.Children[domain]
	if !ok {
		return false
	}
	return ndst.Included
}

// Keys returns the keys of the trie.
func (dst *DomainSuffixTrie) Keys() (keys []string) {
	for s, c := range dst.Children {
		keys = c.keys(s, keys)
	}
	return
}

func (dst *DomainSuffixTrie) keys(suffix string, keys []string) []string {
	if dst.Included {
		keys = append(keys, suffix)
	}
	for s, c := range dst.Children {
		keys = c.keys(s+"."+suffix, keys)
	}
	return keys
}

// Rules implements the MatcherBuilder Rules method.
func (dst *DomainSuffixTrie) Rules() []string {
	return dst.Keys()
}

// MatcherCount implements the MatcherBuilder MatcherCount method.
func (dst *DomainSuffixTrie) MatcherCount() int {
	if dst.Children == nil {
		return 0
	}
	return 1
}

// AppendTo implements the MatcherBuilder AppendTo method.
func (dst *DomainSuffixTrie) AppendTo(matchers []Matcher) ([]Matcher, error) {
	if dst.Children == nil {
		return matchers, nil
	}
	return append(matchers, dst), nil
}

func NewDomainSuffixTrie(capacity int) MatcherBuilder {
	return &DomainSuffixTrie{}
}

func DomainSuffixTrieFromSlice(suffixes []string) *DomainSuffixTrie {
	var dst DomainSuffixTrie
	for _, s := range suffixes {
		dst.Insert(s)
	}
	return &dst
}
