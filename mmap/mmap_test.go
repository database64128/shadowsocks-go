package mmap

import (
	"bytes"
	"os"
	"testing"
)

func TestReadFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mmap_ReadFile_test")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()

	_, err = f.WriteString(name)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Created temporary test file: %q", name)

	data, close, err := ReadFile[string](name)
	if err != nil {
		t.Fatal(err)
	}
	if data != name {
		t.Errorf("Expected file content %q, got %q", name, data)
	}

	if err = close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadCustomFile(t *testing.T) {
	name, ok := os.LookupEnv("SSGO_MMAP_TEST_FILE")
	if !ok {
		t.Skip("SSGO_MMAP_TEST_FILE is not set")
	}

	expectedData, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	data, close, err := ReadFile[[]byte](name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, expectedData) {
		t.Errorf("data = %v, want %v", data, expectedData)
	}

	if err = close(); err != nil {
		t.Fatal(err)
	}
}
