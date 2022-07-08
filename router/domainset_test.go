package router

import (
	"os"
	"testing"
)

const testDomainSet = `
# Test comment.
domain:www.example.net
suffix:example.com
keyword:org
regexp:^adservice\.google\.([a-z]{2}|com?)(\.[a-z]{2})?$
`

func testMatch(t *testing.T, ds DomainSet, domain string, expectedResult bool) {
	if ds.Match(domain) != expectedResult {
		t.Errorf("%s should return %v", domain, expectedResult)
	}
}

func TestDomainSet(t *testing.T) {
	f, err := os.CreateTemp("", "router_domainset_test")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	defer os.Remove(name)

	_, err = f.WriteString(testDomainSet)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Created temporary domain set file: %s", name)

	dsc := DomainSetConfig{
		Name: "test",
		Path: name,
	}

	ds, err := dsc.DomainSet()
	if err != nil {
		t.Fatal(err)
	}

	testMatch(t, ds, "example.net", false)
	testMatch(t, ds, "www.example.net", true)
	testMatch(t, ds, "example.com", true)
	testMatch(t, ds, "www.example.com", true)
	testMatch(t, ds, "gobyexample.com", false)
	testMatch(t, ds, "example.org", true)
	testMatch(t, ds, "adservice.google.com", true)
}
