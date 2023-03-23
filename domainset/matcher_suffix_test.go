package domainset

import (
	"fmt"
	"testing"
)

const (
	shortDomain  = "localhost"
	mediumDomain = "mirror.pkgbuild.com"
	longDomain   = "cant.come.up.with.a.long.domain.name"
)

var testSuffixes = [...]string{
	"example.com",
	"github.com",
	"cube64128.xyz",
	"api.ipify.org",
	"api6.ipify.org",
	"archlinux.org",
	"cloudflare.com",
	"localdomain",
}

func testSuffixMatcher(t *testing.T, m Matcher) {
	testMatcher(t, m, "com", false)
	testMatcher(t, m, "example.com", true)
	testMatcher(t, m, "www.example.com", true)
	testMatcher(t, m, "gobyexample.com", false)
	testMatcher(t, m, "example.org", false)
	testMatcher(t, m, "github.com", true)
	testMatcher(t, m, "api.github.com", true)
	testMatcher(t, m, "raw.githubusercontent.com", false)
	testMatcher(t, m, "github.blog", false)
	testMatcher(t, m, "cube64128.xyz", true)
	testMatcher(t, m, "www.cube64128.xyz", true)
	testMatcher(t, m, "notcube64128.xyz", false)
	testMatcher(t, m, "org", false)
	testMatcher(t, m, "ipify.org", false)
	testMatcher(t, m, "api.ipify.org", true)
	testMatcher(t, m, "api6.ipify.org", true)
	testMatcher(t, m, "api64.ipify.org", false)
	testMatcher(t, m, "www.ipify.org", false)
	testMatcher(t, m, "archlinux.org", true)
	testMatcher(t, m, "aur.archlinux.org", true)
	testMatcher(t, m, "cloudflare", false)
	testMatcher(t, m, "cloudflare.com", true)
	testMatcher(t, m, "dash.cloudflare.com", true)
	testMatcher(t, m, "api.cloudflare.com", true)
	testMatcher(t, m, "localdomain", true)
	testMatcher(t, m, "www.localdomain", true)
}

func TestSuffixLinearMatcher(t *testing.T) {
	slm := SuffixLinearMatcher(testSuffixes[:])
	testSuffixMatcher(t, &slm)
}

func TestSuffixMapMatcher(t *testing.T) {
	smm := SuffixMapMatcherFromSlice(testSuffixes[:])
	testSuffixMatcher(t, &smm)
}

func TestSuffixTrieMatcher(t *testing.T) {
	stm := DomainSuffixTrieFromSlice(testSuffixes[:])
	testSuffixMatcher(t, stm)
}

func benchmarkSuffixMatcher(b *testing.B, count int, name string, m Matcher) {
	b.Run(fmt.Sprintf("%d/%s/Hit", count, name), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match(testSuffixes[i%count])
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss/Short", count, name), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match(shortDomain)
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss/Medium", count, name), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match(mediumDomain)
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss/Long", count, name), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m.Match(longDomain)
		}
	})
}

func BenchmarkSuffixMatchers(b *testing.B) {
	for i := len(testSuffixes) / 2; i <= len(testSuffixes); i += 2 {
		slm := SuffixLinearMatcher(testSuffixes[:i])
		smm := SuffixMapMatcherFromSlice(testSuffixes[:i])
		stm := DomainSuffixTrieFromSlice(testSuffixes[:i])
		benchmarkSuffixMatcher(b, i, "Linear", &slm)
		benchmarkSuffixMatcher(b, i, "Map", &smm)
		benchmarkSuffixMatcher(b, i, "Trie", stm)
	}
}
