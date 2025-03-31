package ss2022

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestSaltPoolAddDuplicateSalts(t *testing.T) {
	const retention = 100 * time.Millisecond
	var salt [32]byte
	rand.Read(salt[:])

	pool := NewSaltPool[[32]byte](retention)
	now := time.Now()

	// Check fresh salt.
	if !pool.Check(salt) {
		t.Fatal("Denied fresh salt.")
	}

	// Add fresh salt.
	if !pool.Add(now, salt) {
		t.Fatal("Denied fresh salt.")
	}

	// Check the same salt again.
	if pool.Check(salt) {
		t.Fatal("Accepted duplicate salt.")
	}

	// Add the same salt again.
	if pool.Add(now, salt) {
		t.Fatal("Accepted duplicate salt.")
	}

	// Advance time to let the salt expire.
	now = now.Add(2 * retention)

	// Add the expired salt.
	if !pool.Add(now, salt) {
		t.Fatal("Denied expired salt.")
	}
}
