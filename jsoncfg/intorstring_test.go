package jsoncfg_test

import (
	"bytes"
	"encoding/json/v2"
	"testing"

	"github.com/database64128/shadowsocks-go/jsoncfg"
)

func TestIntOrStringFromInt(t *testing.T) {
	const i = ^0
	v := jsoncfg.IntOrStringFromInt(i)

	if got := v.Kind(); got != jsoncfg.IntOrStringKindInt {
		t.Errorf("IntOrStringFromInt(%d).Kind() = %v, want %v", i, got, jsoncfg.IntOrStringKindInt)
	}
	if !v.IsValid() {
		t.Errorf("IntOrStringFromInt(%d).IsValid() = false, want true", i)
	}
	if !v.IsInt() {
		t.Errorf("IntOrStringFromInt(%d).IsInt() = false, want true", i)
	}
	if v.IsString() {
		t.Errorf("IntOrStringFromInt(%d).IsString() = true, want false", i)
	}
	if got := v.Int(); got != i {
		t.Errorf("IntOrStringFromInt(%d).Int() = %d, want %d", i, got, i)
	}
	mustPanic(t, func() { _ = v.String() }, "v.String()")

	want, err := json.Marshal(i)
	if err != nil {
		t.Fatalf("json.Marshal(%d) failed: %v", i, err)
	}
	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(IntOrStringFromInt(%d)) failed: %v", i, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("json.Marshal(IntOrStringFromInt(%d)) = %s, want %s", i, got, want)
	}
}

func TestIntOrStringFromString(t *testing.T) {
	const s = "Hello, 世界\n"
	v := jsoncfg.IntOrStringFromString(s)

	if got := v.Kind(); got != jsoncfg.IntOrStringKindString {
		t.Errorf("IntOrStringFromString(%q).Kind() = %v, want %v", s, got, jsoncfg.IntOrStringKindString)
	}
	if !v.IsValid() {
		t.Errorf("IntOrStringFromString(%q).IsValid() = false, want true", s)
	}
	if v.IsInt() {
		t.Errorf("IntOrStringFromString(%q).IsInt() = true, want false", s)
	}
	if !v.IsString() {
		t.Errorf("IntOrStringFromString(%q).IsString() = false, want true", s)
	}
	mustPanic(t, func() { _ = v.Int() }, "v.Int()")
	if got := v.String(); got != s {
		t.Errorf("IntOrStringFromString(%q).String() = %q, want %q", s, got, s)
	}

	want, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal(%q) failed: %v", s, err)
	}
	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(IntOrStringFromString(%q)) failed: %v", s, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("json.Marshal(IntOrStringFromString(%q)) = %s, want %s", s, got, want)
	}
}

func TestIntOrStringZeroValue(t *testing.T) {
	var v jsoncfg.IntOrString

	if got := v.Kind(); got != jsoncfg.IntOrStringKindInvalid {
		t.Errorf("IntOrString{}.Kind() = %v, want %v", got, jsoncfg.IntOrStringKindInvalid)
	}
	if v.IsValid() {
		t.Errorf("IntOrString{}.IsValid() = true, want false")
	}
	if v.IsInt() {
		t.Errorf("IntOrString{}.IsInt() = true, want false")
	}
	if v.IsString() {
		t.Errorf("IntOrString{}.IsString() = true, want false")
	}
	mustPanic(t, func() { _ = v.Int() }, "v.Int()")
	mustPanic(t, func() { _ = v.String() }, "v.String()")

	if got, err := json.Marshal(v); err != nil || string(got) != "null" {
		t.Errorf("json.Marshal(IntOrString{}) = %s, %v, want null, nil", got, err)
	}
}

func mustPanic(t *testing.T, f func(), name string) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("%s did not panic", name)
}

func TestIntOrStringEquals(t *testing.T) {
	v0 := jsoncfg.IntOrString{}
	vi1 := jsoncfg.IntOrStringFromInt(1)
	vi2 := jsoncfg.IntOrStringFromInt(2)
	vs1 := jsoncfg.IntOrStringFromString("Hello")
	vs2 := jsoncfg.IntOrStringFromString("World")

	for _, c := range [...]struct {
		a, b     jsoncfg.IntOrString
		expected bool
	}{
		{v0, v0, true},
		{v0, vi1, false},
		{v0, vi2, false},
		{v0, vs1, false},
		{v0, vs2, false},
		{vi1, v0, false},
		{vi1, vi1, true},
		{vi1, vi2, false},
		{vi1, vs1, false},
		{vi1, vs2, false},
		{vi2, v0, false},
		{vi2, vi1, false},
		{vi2, vi2, true},
		{vi2, vs1, false},
		{vi2, vs2, false},
		{vs1, v0, false},
		{vs1, vi1, false},
		{vs1, vi2, false},
		{vs1, vs1, true},
		{vs1, vs2, false},
		{vs2, v0, false},
		{vs2, vi1, false},
		{vs2, vi2, false},
		{vs2, vs1, false},
		{vs2, vs2, true},
	} {
		if got := c.a.Equals(c.b); got != c.expected {
			t.Errorf("%#v.Equals(%#v) = %v, want %v", c.a, c.b, got, c.expected)
		}
	}
}

func TestIntOrStringUnmarshalJSON(t *testing.T) {
	for _, c := range [...]struct {
		name      string
		input     string
		expectErr bool
		expected  jsoncfg.IntOrString
	}{
		{
			name:     "int",
			input:    "-1",
			expected: jsoncfg.IntOrStringFromInt(-1),
		},
		{
			name:     "string",
			input:    `"Hello, 世界\n"`,
			expected: jsoncfg.IntOrStringFromString("Hello, 世界\n"),
		},
		{
			name:      "badstring",
			input:     `"\"`,
			expectErr: true,
		},
		{
			name:      "float",
			input:     "3.14",
			expectErr: true,
		},
		{
			name:  "null",
			input: "null",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var v jsoncfg.IntOrString
			if err := json.Unmarshal([]byte(c.input), &v); (err != nil) != c.expectErr {
				t.Fatalf("json.Unmarshal(%q) failed: %v", c.input, err)
			}
			if !v.Equals(c.expected) {
				t.Errorf("json.Unmarshal(%q) = %#v, want %#v", c.input, v, c.expected)
			}
		})
	}
}
