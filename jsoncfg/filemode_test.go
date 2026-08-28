package jsoncfg_test

import (
	"io/fs"
	"testing"

	"github.com/database64128/shadowsocks-go/jsoncfg"
)

func TestFileMode(t *testing.T) {
	for _, c := range [...]struct {
		name         string
		input        string
		expectErr    bool
		expected     fs.FileMode
		expectedText string
	}{
		{
			name:         "0644",
			input:        "0644",
			expected:     0644,
			expectedText: "644",
		},
		{
			name:         "755",
			input:        "755",
			expected:     0755,
			expectedText: "755",
		},
		{
			name:      "invalid",
			input:     "invalid",
			expectErr: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var mode jsoncfg.FileMode
			if err := mode.UnmarshalText([]byte(c.input)); err != nil {
				if !c.expectErr {
					t.Fatalf("UnmarshalText(%q) = %v", c.input, err)
				}
				return
			}

			if mode.Value() != c.expected {
				t.Errorf("UnmarshalText(%q) = %o, want %o", c.input, mode, c.expected)
			}

			text, err := mode.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() = %v", err)
			}
			if string(text) != c.expectedText {
				t.Errorf("MarshalText() = %q, want %q", text, c.expectedText)
			}
		})
	}
}
