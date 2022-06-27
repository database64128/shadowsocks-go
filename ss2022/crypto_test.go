package ss2022

import (
	"crypto/rand"
	"errors"
	"testing"
)

func TestNewCipherConfigUnknownMethod(t *testing.T) {
	_, err := NewCipherConfig("2022-blake3-chacha20-poly1305", nil, nil)
	if !errors.Is(err, ErrUnknownMethod) {
		t.Errorf("Expected %s, got %s.", ErrUnknownMethod, err)
	}
}

func TestNewCipherConfigBadPSKLength(t *testing.T) {
	_, err := NewRandomCipherConfig("2022-blake3-aes-128-gcm", 32, 1)
	if !errors.Is(err, ErrBadPSKLength) {
		t.Errorf("Expected %s, got %s.", ErrBadPSKLength, err)
	}

	_, err = NewRandomCipherConfig("2022-blake3-aes-256-gcm", 16, 1)
	if !errors.Is(err, ErrBadPSKLength) {
		t.Errorf("Expected %s, got %s.", ErrBadPSKLength, err)
	}
}

func testNewCipherConfigEIHBehavior(t *testing.T, method string, keySize, eihCount int) {
	cipherConfig, err := NewRandomCipherConfig(method, keySize, eihCount)
	if err != nil {
		t.Fatal(err)
	}

	salt := make([]byte, keySize)
	_, err = rand.Read(salt)
	if err != nil {
		t.Fatal(err)
	}

	eihCiphers := cipherConfig.NewTCPIdentityHeaderClientCiphers(salt)
	if len(eihCiphers) != eihCount {
		t.Errorf("Expected TCP identity header client cipher count %d, got %d.", eihCount, len(eihCiphers))
	}

	eihCipher := cipherConfig.NewTCPIdentityHeaderServerCipher(salt)
	if eihCount == 0 && eihCipher != nil || eihCount != 0 && eihCipher == nil {
		t.Error("Incorrect TCP identity header server cipher nil-ness.")
	}

	eihCiphers = cipherConfig.NewUDPIdentityHeaderClientCiphers()
	if len(eihCiphers) != eihCount {
		t.Errorf("Expected UDP identity header client cipher count %d, got %d.", eihCount, len(eihCiphers))
	}

	eihCipher = cipherConfig.NewUDPIdentityHeaderServerCipher()
	if eihCount == 0 && eihCipher != nil || eihCount != 0 && eihCipher == nil {
		t.Error("Incorrect UDP identity header server cipher nil-ness.")
	}

	hashes := cipherConfig.ClientPSKHashes()
	if len(hashes) != eihCount {
		t.Errorf("Expected client PSK hash count %d, got %d.", eihCount, len(hashes))
	}

	uPSKMap := cipherConfig.ServerPSKHashMap()
	if len(uPSKMap) != eihCount {
		t.Errorf("Expected server uPSK map key-value count %d, got %d.", eihCount, len(uPSKMap))
	}
}

func TestNewCipherConfigEIHBehavior(t *testing.T) {
	testNewCipherConfigEIHBehavior(t, "2022-blake3-aes-128-gcm", 16, 0)
	testNewCipherConfigEIHBehavior(t, "2022-blake3-aes-128-gcm", 16, 7)
	testNewCipherConfigEIHBehavior(t, "2022-blake3-aes-256-gcm", 32, 0)
	testNewCipherConfigEIHBehavior(t, "2022-blake3-aes-256-gcm", 32, 7)
}
