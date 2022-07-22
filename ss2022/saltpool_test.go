package ss2022

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestSaltPoolAddDuplicateSalts(t *testing.T) {
	const retention = 100 * time.Millisecond
	var salt [32]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		t.Fatal(err)
	}

	pool := NewSaltPool[[32]byte](retention)

	// Add fresh salt.
	ok := pool.Add(salt)
	if !ok {
		t.Fatal("Failed to add fresh salt.")
	}

	// Add the same salt again.
	ok = pool.Add(salt)
	if ok {
		t.Fatal("Accepted repeated salt.")
	}

	// Wait until salt expires.
	time.Sleep(2 * retention)

	// Add the expired salt.
	ok = pool.Add(salt)
	if !ok {
		t.Fatal("Failed to add expired salt.")
	}
}
