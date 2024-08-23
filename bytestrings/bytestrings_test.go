package bytestrings

import (
	"slices"
	"testing"
)

const multiline = "\n1\r\n2\n\n3\r\n\r\n4"

func TestNextNonEmptyLine(t *testing.T) {
	line, text := NextNonEmptyLine(multiline)
	if line != "1" {
		t.Fatalf("Expected line '1', got '%s'", line)
	}
	if text != multiline[4:] {
		t.Fatalf("Expected text '%s', got '%s'", multiline[4:], text)
	}

	line, text = NextNonEmptyLine(text)
	if line != "2" {
		t.Fatalf("Expected line '2', got '%s'", line)
	}
	if text != multiline[6:] {
		t.Fatalf("Expected text '%s', got '%s'", multiline[6:], text)
	}

	line, text = NextNonEmptyLine(text)
	if line != "3" {
		t.Fatalf("Expected line '3', got '%s'", line)
	}
	if text != multiline[10:] {
		t.Fatalf("Expected text '%s', got '%s'", multiline[10:], text)
	}

	line, text = NextNonEmptyLine(text)
	if line != "4" {
		t.Fatalf("Expected line '4', got '%s'", line)
	}
	if text != multiline[13:] {
		t.Fatalf("Expected text '%s', got '%s'", multiline[13:], text)
	}
}

func TestNonEmptyLines(t *testing.T) {
	expectedLines := []string{"1", "2", "3", "4"}
	lines := slices.AppendSeq(make([]string, 0, len(expectedLines)), NonEmptyLines(multiline))
	if !slices.Equal(lines, expectedLines) {
		t.Errorf("Expected lines %v, got %v", expectedLines, lines)
	}
}
