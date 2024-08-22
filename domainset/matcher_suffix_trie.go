package domainset

import (
	"iter"
)

// DomainSuffixTrie is a trie of domain parts segmented by '.'.
type DomainSuffixTrie struct {
	// Children maps the next domain part to its child node.
	//
	// If Children is nil, the node is a leaf node.
	Children map[string]DomainSuffixTrie
}

// Insert inserts a domain suffix to the trie.
// Insertion purges the leaf node's children.
// If say, we insert "www.google.com" and then "google.com",
// The children of node "google" will be purged.
//
// Insert implements [MatcherBuilder.Insert].
func (dst DomainSuffixTrie) Insert(domain string) {
	cdst := dst

	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}

		part := domain[i+1:]

		ndst, ok := cdst.Children[part]
		switch {
		case !ok:
			// Insert the part as a non-leaf child node.
			ndst = DomainSuffixTrie{
				Children: make(map[string]DomainSuffixTrie, 1),
			}
			cdst.Children[part] = ndst
		case ndst.Children == nil:
			// Reached a leaf node halfway through, which means a shorter suffix
			// is already present. No need to insert further.
			return
		}

		// Move to the next child node.
		cdst = ndst

		// Strip the current part from the domain.
		domain = domain[:i]
	}

	// Make the final (from right to left) part a leaf node.
	cdst.Children[domain] = DomainSuffixTrie{}
}

// Match returns true if the domain matches any suffix in the trie.
//
// Match implements [Matcher.Match].
func (dst DomainSuffixTrie) Match(domain string) bool {
	cdst := dst

	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] != '.' {
			continue
		}

		part := domain[i+1:]

		ndst, ok := cdst.Children[part]
		if !ok {
			return false
		}
		if ndst.Children == nil {
			return true
		}

		cdst = ndst
		domain = domain[:i]
	}

	ndst, ok := cdst.Children[domain]
	if !ok {
		return false
	}
	return ndst.Children == nil
}

// KeySlice returns the keys in the trie as a slice.
func (dst DomainSuffixTrie) KeySlice() (keys []string) {
	for s, c := range dst.Children {
		keys = c.keySlice(s, keys)
	}
	return
}

func (dst DomainSuffixTrie) keySlice(suffix string, keys []string) []string {
	if dst.Children == nil {
		return append(keys, suffix)
	}
	for s, c := range dst.Children {
		keys = c.keySlice(s+"."+suffix, keys)
	}
	return keys
}

// KeyCount returns the number of keys in the trie.
func (dst DomainSuffixTrie) KeyCount() int {
	if dst.Children == nil {
		return 1
	}
	var count int
	for _, c := range dst.Children {
		count += c.KeyCount()
	}
	return count
}

// Keys returns an iterator over the keys in the trie.
func (dst DomainSuffixTrie) Keys() iter.Seq[string] {
	return func(yield func(string) bool) {
		for s, c := range dst.Children {
			if !c.keys(s, yield) {
				return
			}
		}
	}
}

func (dst DomainSuffixTrie) keys(suffix string, yield func(string) bool) bool {
	if dst.Children == nil {
		return yield(suffix)
	}
	for s, c := range dst.Children {
		if !c.keys(s+"."+suffix, yield) {
			return false
		}
	}
	return true
}

// Rules implements [MatcherBuilder.Rules].
func (dst DomainSuffixTrie) Rules() (int, iter.Seq[string]) {
	return dst.KeyCount(), dst.Keys()
}

// MatcherCount implements [MatcherBuilder.MatcherCount].
func (dst DomainSuffixTrie) MatcherCount() int {
	if len(dst.Children) == 0 {
		return 0
	}
	return 1
}

// AppendTo implements [MatcherBuilder.AppendTo].
func (dst *DomainSuffixTrie) AppendTo(matchers []Matcher) ([]Matcher, error) {
	if len(dst.Children) == 0 {
		return matchers, nil
	}
	return append(matchers, dst), nil
}

// NewDomainSuffixTrie returns a new [DomainSuffixTrie].
func NewDomainSuffixTrie() DomainSuffixTrie {
	return DomainSuffixTrie{
		Children: make(map[string]DomainSuffixTrie),
	}
}

// NewDomainSuffixTrieMatcherBuilder returns a new [*DomainSuffixTrie] as a [MatcherBuilder].
func NewDomainSuffixTrieMatcherBuilder(_ int) MatcherBuilder {
	dst := NewDomainSuffixTrie()
	return &dst
}

// DomainSuffixTrieFromSlice creates a [DomainSuffixTrie] from a slice of suffix rules.
func DomainSuffixTrieFromSlice(suffixes []string) DomainSuffixTrie {
	dst := NewDomainSuffixTrie()
	for _, s := range suffixes {
		dst.Insert(s)
	}
	return dst
}

// DomainSuffixTrieFromSeq creates a [DomainSuffixTrie] from a sequence of suffix rules.
func DomainSuffixTrieFromSeq(_ int, suffixSeq iter.Seq[string]) DomainSuffixTrie {
	dst := NewDomainSuffixTrie()
	for suffix := range suffixSeq {
		dst.Insert(suffix)
	}
	return dst
}
