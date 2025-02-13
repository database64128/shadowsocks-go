package domainset

import (
	"fmt"
	"testing"
)

const testMissDomain = "gitlab.archlinux.org"

var testDomains = [...]string{
	"example.com",
	"github.com",
	"cube64128.xyz",
	"www.cube64128.xyz",
	"api.ipify.org",
	"api6.ipify.org",
	"archlinux.org",
	"aur.archlinux.org",
	"wiki.archlinux.org",
	"dash.cloudflare.com",
	"api.cloudflare.com",
	"google.com",
	"www.google.com",
	"youtube.com",
	"www.youtube.com",
	"music.youtube.com",
	"youtu.be",
	"news.ycombinator.com",
	"lwn.net",
	"kernel.org",
	"lore.kernel.org",
	"go.dev",
	"pkg.go.dev",
	"localdomain",
}

func testDomainMatcher(t *testing.T, m Matcher) {
	testMatcher(t, m, "com", false)
	testMatcher(t, m, "example.com", true)
	testMatcher(t, m, "www.example.com", false)
	testMatcher(t, m, "gobyexample.com", false)
	testMatcher(t, m, "example.org", false)
	testMatcher(t, m, "github.com", true)
	testMatcher(t, m, "api.github.com", false)
	testMatcher(t, m, "raw.githubusercontent.com", false)
	testMatcher(t, m, "blog", false)
	testMatcher(t, m, "github.blog", false)
	testMatcher(t, m, "io", false)
	testMatcher(t, m, "github.io", false)
	testMatcher(t, m, "database64128.github.io", false)
	testMatcher(t, m, "xyz", false)
	testMatcher(t, m, "cube64128.xyz", true)
	testMatcher(t, m, "www.cube64128.xyz", true)
	testMatcher(t, m, "nonexistent.cube64128.xyz", false)
	testMatcher(t, m, "notcube64128.xyz", false)
	testMatcher(t, m, "org", false)
	testMatcher(t, m, "ipify.org", false)
	testMatcher(t, m, "api.ipify.org", true)
	testMatcher(t, m, "api6.ipify.org", true)
	testMatcher(t, m, "api64.ipify.org", false)
	testMatcher(t, m, "www.ipify.org", false)
	testMatcher(t, m, "archlinux.org", true)
	testMatcher(t, m, "aur.archlinux.org", true)
	testMatcher(t, m, "bugs.archlinux.org", false)
	testMatcher(t, m, "wiki.archlinux.org", true)
	testMatcher(t, m, "cloudflare", false)
	testMatcher(t, m, "cloudflare.com", false)
	testMatcher(t, m, "dash.cloudflare.com", true)
	testMatcher(t, m, "api.cloudflare.com", true)
	testMatcher(t, m, "google.com", true)
	testMatcher(t, m, "googlesource.com", false)
	testMatcher(t, m, "www.google.com", true)
	testMatcher(t, m, "accounts.google.com", false)
	testMatcher(t, m, "amervice.google.com", false)
	testMatcher(t, m, "youtube.com", true)
	testMatcher(t, m, "www.youtube.com", true)
	testMatcher(t, m, "m.youtube.com", false)
	testMatcher(t, m, "music.youtube.com", true)
	testMatcher(t, m, "be", false)
	testMatcher(t, m, "youtu.be", true)
	testMatcher(t, m, "ycombinator.com", false)
	testMatcher(t, m, "news.ycombinator.com", true)
	testMatcher(t, m, "net", false)
	testMatcher(t, m, "lwn.net", true)
	testMatcher(t, m, "static.lwn.net", false)
	testMatcher(t, m, "kernel.org", true)
	testMatcher(t, m, "lore.kernel.org", true)
	testMatcher(t, m, "archive.kernel.org", false)
	testMatcher(t, m, "dev", false)
	testMatcher(t, m, "go.dev", true)
	testMatcher(t, m, "pkg.go.dev", true)
	testMatcher(t, m, "localdomain", true)
	testMatcher(t, m, "www.localdomain", false)
}

func TestDomainLinearMatcher(t *testing.T) {
	dlm := DomainLinearMatcher(testDomains[:])

	t.Run("Match", func(t *testing.T) {
		testDomainMatcher(t, &dlm)
	})

	t.Run("Rules", func(t *testing.T) {
		testMatcherBuilderRules(t, &dlm, testDomains[:])
	})
}

func TestDomainBinarySearchMatcher(t *testing.T) {
	dbsm := DomainBinarySearchMatcherFromSlice(testDomains[:])

	t.Run("Match", func(t *testing.T) {
		testDomainMatcher(t, &dbsm)
	})

	t.Run("Rules", func(t *testing.T) {
		testMatcherBuilderRules(t, &dbsm, testDomains[:])
	})
}

func TestDomainMapMatcher(t *testing.T) {
	dmm := DomainMapMatcherFromSlice(testDomains[:])

	t.Run("Match", func(t *testing.T) {
		testDomainMatcher(t, &dmm)
	})

	t.Run("Rules", func(t *testing.T) {
		testMatcherBuilderRules(t, &dmm, testDomains[:])
	})
}

func benchmarkDomainMatcher(b *testing.B, count int, name string, m Matcher) {
	b.Run(fmt.Sprintf("%d/%s/Hit", count, name), func(b *testing.B) {
		var i int
		for b.Loop() {
			if !m.Match(testDomains[i%count]) {
				b.Fatal("unexpected miss")
			}
			i++
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss", count, name), func(b *testing.B) {
		for b.Loop() {
			if m.Match(testMissDomain) {
				b.Fatal("unexpected hit")
			}
		}
	})
}

func BenchmarkDomainMatchers(b *testing.B) {
	for i := 4; i <= len(testDomains); i += 4 {
		dlm := DomainLinearMatcher(testDomains[:i])
		dbsm := DomainBinarySearchMatcherFromSlice(testDomains[:i])
		dmm := DomainMapMatcherFromSlice(testDomains[:i])
		benchmarkDomainMatcher(b, i, "DomainLinearMatcher", &dlm)
		benchmarkDomainMatcher(b, i, "DomainBinarySearchMatcher", &dbsm)
		benchmarkDomainMatcher(b, i, "DomainMapMatcher", &dmm)
	}
}
