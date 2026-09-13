package domainset

import (
	"bytes"
	"errors"
	"strings"
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

func mustDomainSetBuilderFromText(s string) Builder {
	dsb, err := BuilderFromText(s)
	if err != nil {
		panic(err)
	}
	return dsb
}

func testMatch(t *testing.T, ds DomainSet, domain string, expectedResult bool) {
	t.Helper()
	if ds.Match(domain) != expectedResult {
		t.Errorf("%s should return %v", domain, expectedResult)
	}
}

func testDomainSet(t *testing.T, ds DomainSet) {
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
	dsb, err := BuilderFromText(testDomainSetText)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := dsb.DomainSet()
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
	dsb, err := BuilderFromGob(&buf)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := dsb.DomainSet()
	if err != nil {
		t.Fatal(err)
	}
	testDomainSet(t, ds)
}

func TestBuilderWriteText(t *testing.T) {
	var sb strings.Builder
	if err := testDomainSetBuilder.WriteText(&sb); err != nil {
		t.Fatal(err)
	}
	dsb, err := BuilderFromText(sb.String())
	if err != nil {
		t.Fatal(err)
	}
	ds, err := dsb.DomainSet()
	if err != nil {
		t.Fatal(err)
	}
	testDomainSet(t, ds)
}

func TestBuilderFromDLC(t *testing.T) {
	for _, c := range [...]struct {
		name      string
		text      string
		attr      string
		wantRules builderWantRules
	}{
		{
			name: "Empty",
		},
		{
			name: "NoFilter",
			text: "# comment\ndomain:google.com\ndomain:cloudflare.com\nfull:www.example.com\nfull:www.example.net\nkeyword:ads\nkeyword:spam\n" +
				`regexp:^adservice\.google\.([a-z]{2}|com?)(\.[a-z]{2})?$:@ads` + "\n" + `regexp:.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$`,
			attr: "",
			wantRules: builderWantRules{
				{"www.example.com", "www.example.net"},
				{"google.com", "cloudflare.com"},
				{"ads", "spam"},
				{`^adservice\.google\.([a-z]{2}|com?)(\.[a-z]{2})?$`, `.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$`},
			},
		},
		{
			name: "FilterAttr",
			text: "\n# comment\n\ndomain:adservice.google.com:@ads\r\ndomain:cloudflare.com\nfull:www.example.com\r\n\r\nfull:googleadservices.com:@ads\nkeyword:ads\nkeyword:spam\n" +
				`regexp:^adservice\.google\.([a-z]{2}|com?)(\.[a-z]{2})?$:@ads` + "\n" + `regexp:.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$` + "\r\n# the end\n",
			attr: "ads",
			wantRules: builderWantRules{
				{"googleadservices.com"},
				{"adservice.google.com"},
				{},
				{`^adservice\.google\.([a-z]{2}|com?)(\.[a-z]{2})?$`},
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			dsb, err := BuilderFromDLC(c.text, c.attr)
			if err != nil {
				t.Fatalf("BuilderFromDLC(c.text, c.attr) failed: %v", err)
			}
			c.wantRules.checkBuilderRules(t, dsb)
		})
	}
}

type builderWantRules [4][]string

func (w builderWantRules) checkBuilderRules(t *testing.T, dsb Builder) {
	t.Helper()
	for i, wantRules := range w {
		testMatcherBuilderRules(t, dsb[i], wantRules)
	}
}

func TestBuilderFromDLCError(t *testing.T) {
	for _, c := range [...]struct {
		name     string
		text     string
		wantLine int
		wantErr  error
	}{
		{
			name:     "NoType",
			text:     "www.google.com\n",
			wantLine: 1,
			wantErr:  ErrInvalidRuleLine,
		},
		{
			name:     "TypeOnly",
			text:     "# comment\nkeyword:\n",
			wantLine: 2,
			wantErr:  ErrInvalidRuleLine,
		},
		{
			name:     "TypeAttrOnly",
			text:     "\n# comment\nfull:@attr1,@attr2\r\n",
			wantLine: 3,
			wantErr:  ErrInvalidRuleLine,
		},
		{
			name:     "DomainAttrOnly",
			text:     "\r\n\n# comment\r\nwww.google.com:@faang,@alphabet\n",
			wantLine: 4,
			wantErr:  ErrInvalidRuleLine,
		},
		{
			name:     "BadType",
			text:     "\n\r\n\nsuffix:google.com\r\n# comment",
			wantLine: 4,
			wantErr:  ErrInvalidRuleLine,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := BuilderFromDLC(c.text, "")
			e, ok := errors.AsType[TextLineError](err)
			if !ok {
				t.Errorf("error = %v, want %T", err, e)
				return
			}
			if e.Line != c.wantLine {
				t.Errorf("e.Line = %d, want %d", e.Line, c.wantLine)
			}
			if !errors.Is(e.Err, c.wantErr) {
				t.Errorf("e.Err = %v, want %v", e.Err, c.wantErr)
			}
		})
	}
}
