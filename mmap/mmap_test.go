package mmap

import (
	"os"
	"testing"
)

func TestReadFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mmap_ReadFile_test")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	defer os.Remove(name)

	_, err = f.WriteString(name)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Created temporary test file: %s", name)

	data, err := ReadFile[string](name)
	if err != nil {
		t.Fatal(err)
	}
	if data != name {
		t.Errorf("Expected file content %s, got %s", name, data)
	}

	if err = Unmap(data); err != nil {
		t.Fatal(err)
	}
}
