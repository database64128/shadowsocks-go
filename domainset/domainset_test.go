package domainset

import (
	"bytes"
	"testing"
)

const testDomainSetText = `# shadowsocks-go domain set capacity hint 1 6 1 1 DSKR
domain:www.example.net
suffix:example.com
suffix:github.com
suffix:cube64128.xyz
suffix:api.ipify.org
suffix:api6.ipify.org
suffix:archlinux.org
keyword:dev
regexp:^adservice\.google\.([a-z]{2}|com?)(\.[a-z]{2})?$
`

var testDomainSetBuilder = mustDomainSetBuilderFromText(testDomainSetText)

func mustDomainSetBuilderFromText(s string) *Builder {
	r := bytes.NewReader([]byte(s))
	dsb, err := BuilderFromText(r)
	if err != nil {
		panic(err)
	}
	return dsb
}

func testMatch(t *testing.T, ds *DomainSet, domain string, expectedResult bool) {
	if ds.Match(domain) != expectedResult {
		t.Errorf("%s should return %v", domain, expectedResult)
	}
}

func testDomainSet(t *testing.T, ds *DomainSet) {
	testMatch(t, ds, "net", false)
	testMatch(t, ds, "example.net", false)
	testMatch(t, ds, "www.example.net", true)
	testMatch(t, ds, "wwww.example.net", false)
	testMatch(t, ds, "test.www.example.net", false)
	testMatch(t, ds, "com", false)
	testMatch(t, ds, "example.com", true)
	testMatch(t, ds, "www.example.com", true)
	testMatch(t, ds, "gobyexample.com", false)
	testMatch(t, ds, "example.org", false)
	testMatch(t, ds, "github.com", true)
	testMatch(t, ds, "api.github.com", true)
	testMatch(t, ds, "raw.githubusercontent.com", false)
	testMatch(t, ds, "github.blog", false)
	testMatch(t, ds, "cube64128.xyz", true)
	testMatch(t, ds, "www.cube64128.xyz", true)
	testMatch(t, ds, "notcube64128.xyz", false)
	testMatch(t, ds, "org", false)
	testMatch(t, ds, "ipify.org", false)
	testMatch(t, ds, "api.ipify.org", true)
	testMatch(t, ds, "api6.ipify.org", true)
	testMatch(t, ds, "api64.ipify.org", false)
	testMatch(t, ds, "www.ipify.org", false)
	testMatch(t, ds, "archlinux.org", true)
	testMatch(t, ds, "aur.archlinux.org", true)
	testMatch(t, ds, "wikipedia.org", false)
	testMatch(t, ds, "dev", true)
	testMatch(t, ds, "go.dev", true)
	testMatch(t, ds, "drewdevault.com", true)
	testMatch(t, ds, "developer.mozilla.org", true)
	testMatch(t, ds, "adservice.google.com", true)
}

func TestDomainSetFromText(t *testing.T) {
	r := bytes.NewReader([]byte(testDomainSetText))
	ds, err := DomainSetFromText(r)
	if err != nil {
		t.Fatal(err)
	}
	testDomainSet(t, ds)
}

func TestDomainSetFromGob(t *testing.T) {
	var buf bytes.Buffer
	if err := testDomainSetBuilder.WriteGob(&buf); err != nil {
		t.Fatal(err)
	}
	ds, err := DomainSetFromGob(&buf)
	if err != nil {
		t.Fatal(err)
	}
	testDomainSet(t, ds)
}

func TestBuilderWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := testDomainSetBuilder.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	ds, err := DomainSetFromText(&buf)
	if err != nil {
		t.Fatal(err)
	}
	testDomainSet(t, ds)
}
