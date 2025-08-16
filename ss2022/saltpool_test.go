package ss2022_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/database64128/shadowsocks-go/ss2022"
)

func TestSaltPool(t *testing.T) {
	var pool ss2022.SaltPool
	now := time.Now()
	b := make([]byte, 64)
	rand.Read(b)
	salt0 := [32]byte(b)
	salt1 := [32]byte(b[32:])

	// Clear empty pool.
	pool.Clear()

	// Check salt0 and salt1.
	if pool.Contains(salt0) {
		t.Fatal("pool.Contains(salt0) = true, want false")
	}
	if pool.TryContains(salt1) {
		t.Fatal("pool.TryContains(salt1) = true, want false")
	}

	// Add salt0.
	if !pool.Add(now, salt0) {
		t.Fatal("pool.Add(now, salt0) = false, want true")
	}
	if pool.Add(now, salt0) {
		t.Fatal("pool.Add(now, salt0) = true, want false")
	}

	// Advance some time.
	now = now.Add(ss2022.ReplayWindowDuration / 2)

	// Add salt1.
	if !pool.Add(now, salt1) {
		t.Fatal("pool.Add(now, salt1) = false, want true")
	}
	if pool.Add(now, salt1) {
		t.Fatal("pool.Add(now, salt1) = true, want false")
	}

	// Check salt0 and salt1.
	if !pool.Contains(salt0) {
		t.Fatal("pool.Contains(salt0) = false, want true")
	}
	if !pool.Contains(salt1) {
		t.Fatal("pool.Contains(salt1) = false, want true")
	}

	// Advance some time to let salt0 expire.
	now = now.Add(ss2022.ReplayWindowDuration / 2)

	// Add salt0 and salt1.
	if !pool.Add(now, salt0) {
		t.Fatal("pool.Add(now, salt0) = false, want true")
	}
	if pool.Add(now, salt1) {
		t.Fatal("pool.Add(now, salt1) = true, want false")
	}

	// Advance some time to let both expire.
	now = now.Add(ss2022.ReplayWindowDuration)

	// Add salt0 and salt1.
	if !pool.Add(now, salt0) {
		t.Fatal("pool.Add(now, salt0) = false, want true")
	}
	if !pool.Add(now, salt1) {
		t.Fatal("pool.Add(now, salt1) = false, want true")
	}

	// Clear the pool.
	pool.Clear()

	// Check salt0 and salt1 again.
	if pool.TryContains(salt0) {
		t.Fatal("pool.TryContains(salt0) = true, want false")
	}
	if pool.TryContains(salt1) {
		t.Fatal("pool.TryContains(salt1) = true, want false")
	}
}
