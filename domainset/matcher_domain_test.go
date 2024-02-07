package domainset

import (
	"fmt"
	"testing"
)

const testMissDomain = "aur.archlinux.org"

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
	testMatcher(t, m, "github.blog", false)
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
	testMatcher(t, m, "www.google.com", true)
	testMatcher(t, m, "amervice.google.com", false)
	testMatcher(t, m, "youtube.com", true)
	testMatcher(t, m, "www.youtube.com", true)
	testMatcher(t, m, "m.youtube.com", false)
	testMatcher(t, m, "localdomain", true)
	testMatcher(t, m, "www.localdomain", false)
}

func TestDomainLinearMatcher(t *testing.T) {
	dlm := DomainLinearMatcher(testDomains[:])
	testDomainMatcher(t, &dlm)
}

func TestDomainBinarySearchMatcher(t *testing.T) {
	dbsm := DomainBinarySearchMatcherFromSlice(testDomains[:])
	testDomainMatcher(t, &dbsm)
}

func TestDomainMapMatcher(t *testing.T) {
	dmm := DomainMapMatcherFromSlice(testDomains[:])
	testDomainMatcher(t, &dmm)
}

func benchmarkDomainMatcher(b *testing.B, count int, name string, m Matcher) {
	b.Run(fmt.Sprintf("%d/%s/Hit", count, name), func(b *testing.B) {
		for i := range b.N {
			m.Match(testDomains[i%count])
		}
	})
	b.Run(fmt.Sprintf("%d/%s/Miss", count, name), func(b *testing.B) {
		for range b.N {
			m.Match(testMissDomain)
		}
	})
}

func BenchmarkDomainMatchers(b *testing.B) {
	for i := len(testDomains) / 4; i <= len(testDomains); i += 3 {
		dlm := DomainLinearMatcher(testDomains[:i])
		dbsm := DomainBinarySearchMatcherFromSlice(testDomains[:i])
		dmm := DomainMapMatcherFromSlice(testDomains[:i])
		benchmarkDomainMatcher(b, i, "DomainLinearMatcher", &dlm)
		benchmarkDomainMatcher(b, i, "DomainBinarySearchMatcher", &dbsm)
		benchmarkDomainMatcher(b, i, "DomainMapMatcher", &dmm)
	}
}
