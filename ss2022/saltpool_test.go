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

	// Check fresh salt.
	if !pool.Check(salt) {
		t.Fatal("Denied fresh salt.")
	}

	// Add fresh salt.
	pool.Add(salt)

	// Check the same salt again.
	if pool.Check(salt) {
		t.Fatal("Accepted duplicate salt.")
	}

	// Wait until salt expires.
	time.Sleep(2 * retention)

	// Check the expired salt.
	if !pool.Check(salt) {
		t.Fatal("Denied expired salt.")
	}
}
