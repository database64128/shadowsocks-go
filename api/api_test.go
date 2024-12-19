package api

import "testing"

func TestJoinPatternPath(t *testing.T) {
	for _, c := range []struct {
		elem []string
		want string
	}{
		{[]string{}, ""},
		{[]string{""}, ""},
		{[]string{"a"}, "a"},
		{[]string{"/"}, "/"},
		{[]string{"/a"}, "/a"},
		{[]string{"a/"}, "a/"},
		{[]string{"/a/"}, "/a/"},
		{[]string{"", "b"}, "b"},
		{[]string{"", "/b"}, "/b"},
		{[]string{"", "b/"}, "b/"},
		{[]string{"", "/b/"}, "/b/"},
		{[]string{"a", "b"}, "a/b"},
		{[]string{"a", "/b"}, "a/b"},
		{[]string{"a", "b/"}, "a/b/"},
		{[]string{"a", "/b/"}, "a/b/"},
		{[]string{"/", "b"}, "/b"},
		{[]string{"/", "/b"}, "/b"},
		{[]string{"/", "b/"}, "/b/"},
		{[]string{"/", "/b/"}, "/b/"},
		{[]string{"/a", "b"}, "/a/b"},
		{[]string{"/a", "/b"}, "/a/b"},
		{[]string{"/a", "b/"}, "/a/b/"},
		{[]string{"/a", "/b/"}, "/a/b/"},
		{[]string{"a/", "b"}, "a/b"},
		{[]string{"a/", "/b"}, "a/b"},
		{[]string{"a/", "b/"}, "a/b/"},
		{[]string{"a/", "/b/"}, "a/b/"},
		{[]string{"/a/", "b"}, "/a/b"},
		{[]string{"/a/", "/b"}, "/a/b"},
		{[]string{"/a/", "b/"}, "/a/b/"},
		{[]string{"/a/", "/b/"}, "/a/b/"},
	} {
		if got := joinPatternPath(c.elem...); got != c.want {
			t.Errorf("joinPatternPath(%#v) = %q; want %q", c.elem, got, c.want)
		}
	}
}
