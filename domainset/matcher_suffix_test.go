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
	"github.io",
	"cube64128.xyz",
	"api.ipify.org",
	"api6.ipify.org",
	"archlinux.org",
	"cloudflare.com",
	"www.google.com",
	"www.youtube.com",
	"music.youtube.com",
	"news.ycombinator.com",
	"lwn.net",
	"lore.kernel.org",
	"pkg.go.dev",
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
	testMatcher(t, m, "blog", false)
	testMatcher(t, m, "github.blog", false)
	testMatcher(t, m, "io", false)
	testMatcher(t, m, "github.io", true)
	testMatcher(t, m, "database64128.github.io", true)
	testMatcher(t, m, "xyz", false)
	testMatcher(t, m, "cube64128.xyz", true)
	testMatcher(t, m, "www.cube64128.xyz", true)
	testMatcher(t, m, "nonexistent.cube64128.xyz", true)
	testMatcher(t, m, "notcube64128.xyz", false)
	testMatcher(t, m, "org", false)
	testMatcher(t, m, "ipify.org", false)
	testMatcher(t, m, "api.ipify.org", true)
	testMatcher(t, m, "api6.ipify.org", true)
	testMatcher(t, m, "api64.ipify.org", false)
	testMatcher(t, m, "www.ipify.org", false)
	testMatcher(t, m, "archlinux.org", true)
	testMatcher(t, m, "aur.archlinux.org", true)
	testMatcher(t, m, "bugs.archlinux.org", true)
	testMatcher(t, m, "wiki.archlinux.org", true)
	testMatcher(t, m, "cloudflare", false)
	testMatcher(t, m, "cloudflare.com", true)
	testMatcher(t, m, "dash.cloudflare.com", true)
	testMatcher(t, m, "api.cloudflare.com", true)
	testMatcher(t, m, "google.com", false)
	testMatcher(t, m, "googlesource.com", false)
	testMatcher(t, m, "www.google.com", true)
	testMatcher(t, m, "accounts.google.com", false)
	testMatcher(t, m, "amervice.google.com", false)
	testMatcher(t, m, "youtube.com", false)
	testMatcher(t, m, "www.youtube.com", true)
	testMatcher(t, m, "m.youtube.com", false)
	testMatcher(t, m, "music.youtube.com", true)
	testMatcher(t, m, "be", false)
	testMatcher(t, m, "youtu.be", false)
	testMatcher(t, m, "ycombinator.com", false)
	testMatcher(t, m, "news.ycombinator.com", true)
	testMatcher(t, m, "net", false)
	testMatcher(t, m, "lwn.net", true)
	testMatcher(t, m, "static.lwn.net", true)
	testMatcher(t, m, "kernel.org", false)
	testMatcher(t, m, "lore.kernel.org", true)
	testMatcher(t, m, "archive.kernel.org", false)
	testMatcher(t, m, "dev", false)
	testMatcher(t, m, "go.dev", false)
	testMatcher(t, m, "pkg.go.dev", true)
	testMatcher(t, m, "localdomain", true)
	testMatcher(t, m, "www.localdomain", true)
}

func TestSuffixLinearMatcher(t *testing.T) {
	slm := SuffixLinearMatcher(testSuffixes[:])

	t.Run("Match", func(t *testing.T) {
		testSuffixMatcher(t, &slm)
	})

	t.Run("Rules", func(t *testing.T) {
		testMatcherBuilderRules(t, &slm, testSuffixes[:])
	})
}

func TestSuffixMapMatcher(t *testing.T) {
	smm := SuffixMapMatcherFromSlice(testSuffixes[:])

	t.Run("Match", func(t *testing.T) {
		testSuffixMatcher(t, &smm)
	})

	t.Run("Rules", func(t *testing.T) {
		testMatcherBuilderRules(t, &smm, testSuffixes[:])
	})
}

func TestSuffixTrieMatcher(t *testing.T) {
	stm := DomainSuffixTrieFromSlice(testSuffixes[:])

	t.Run("Match", func(t *testing.T) {
		testSuffixMatcher(t, &stm)
	})

	t.Run("Rules", func(t *testing.T) {
		testMatcherBuilderRules(t, &stm, testSuffixes[:])
	})
}

func benchmarkSuffixMatcher(b *testing.B, count int, name string, m Matcher) {
	b.Run(fmt.Sprintf("%d/%s/Hit", count, name), func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			if !m.Match(testSuffixes[i%count]) {
				b.Fatal("unexpected miss")
			}
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss/Short", count, name), func(b *testing.B) {
		for b.Loop() {
			if m.Match(shortDomain) {
				b.Fatal("unexpected hit")
			}
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss/Medium", count, name), func(b *testing.B) {
		for b.Loop() {
			if m.Match(mediumDomain) {
				b.Fatal("unexpected hit")
			}
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss/Long", count, name), func(b *testing.B) {
		for b.Loop() {
			if m.Match(longDomain) {
				b.Fatal("unexpected hit")
			}
		}
	})
}

func BenchmarkSuffixMatchers(b *testing.B) {
	for i := 4; i <= len(testSuffixes); i += 4 {
		slm := SuffixLinearMatcher(testSuffixes[:i])
		smm := SuffixMapMatcherFromSlice(testSuffixes[:i])
		stm := DomainSuffixTrieFromSlice(testSuffixes[:i])
		benchmarkSuffixMatcher(b, i, "Linear", &slm)
		benchmarkSuffixMatcher(b, i, "Map", &smm)
		benchmarkSuffixMatcher(b, i, "Trie", stm)
	}
}
