package ss2022

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/test"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func testShadowStreamReadWriter(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig, clientInitialPayload []byte) {
	pl, pr := test.NewDuplexPipe()

	saltPool := NewSaltPool[string](ReplayWindowDuration)

	clientTargetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                    *ShadowStreamClientReadWriter
		s                    *ShadowStreamServerReadWriter
		serverTargetAddr     socks5.Addr
		serverInitialPayload []byte
		cerr, serr           error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, cerr = NewShadowStreamClientReadWriter(pl, clientCipherConfig, clientCipherConfig.ClientPSKHashes(), clientTargetAddr, clientInitialPayload)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serverInitialPayload, serr = NewShadowStreamServerReadWriter(pr, serverCipherConfig, saltPool, serverCipherConfig.ServerPSKHashMap())
		ctrlCh <- struct{}{}
	}()

	<-ctrlCh
	<-ctrlCh
	if cerr != nil {
		t.Fatal(cerr)
	}
	if serr != nil {
		t.Fatal(serr)
	}

	if !bytes.Equal(clientTargetAddr, serverTargetAddr) {
		t.Errorf("Target address mismatch: c: %s, s: %s", clientTargetAddr, serverTargetAddr)
	}
	if !bytes.Equal(clientInitialPayload, serverInitialPayload) {
		t.Errorf("Initial payload mismatch: c: %v, s: %v", clientInitialPayload, serverInitialPayload)
	}

	zerocopy.ReadWriterTestFunc(t, c, s)
}

func TestShadowStreamReadWriterNoEIH(t *testing.T) {
	cipherConfig128, err := NewRandomCipherConfig("2022-blake3-aes-128-gcm", 16, 0)
	if err != nil {
		t.Fatal(err)
	}
	cipherConfig256, err := NewRandomCipherConfig("2022-blake3-aes-256-gcm", 32, 0)
	if err != nil {
		t.Fatal(err)
	}

	initialPayload := make([]byte, 1024)
	_, err = rand.Read(initialPayload)
	if err != nil {
		t.Fatal(err)
	}

	testShadowStreamReadWriter(t, cipherConfig128, cipherConfig128, nil)
	testShadowStreamReadWriter(t, cipherConfig128, cipherConfig128, initialPayload)
	testShadowStreamReadWriter(t, cipherConfig256, cipherConfig256, nil)
	testShadowStreamReadWriter(t, cipherConfig256, cipherConfig256, initialPayload)
}

func TestShadowStreamReadWriterWithEIH(t *testing.T) {
	serverCipherConfig128, err := NewRandomCipherConfig("2022-blake3-aes-128-gcm", 16, 7)
	if err != nil {
		t.Fatal(err)
	}
	serverCipherConfig256, err := NewRandomCipherConfig("2022-blake3-aes-256-gcm", 32, 7)
	if err != nil {
		t.Fatal(err)
	}

	clientCipherConfig128 := CipherConfig{
		PSK:  serverCipherConfig128.PSKs[0],
		PSKs: [][]byte{serverCipherConfig128.PSK},
	}
	clientCipherConfig256 := CipherConfig{
		PSK:  serverCipherConfig256.PSKs[0],
		PSKs: [][]byte{serverCipherConfig256.PSK},
	}

	initialPayload := make([]byte, 1024)
	_, err = rand.Read(initialPayload)
	if err != nil {
		t.Fatal(err)
	}

	testShadowStreamReadWriter(t, &clientCipherConfig128, serverCipherConfig128, nil)
	testShadowStreamReadWriter(t, &clientCipherConfig128, serverCipherConfig128, initialPayload)
	testShadowStreamReadWriter(t, &clientCipherConfig256, serverCipherConfig256, nil)
	testShadowStreamReadWriter(t, &clientCipherConfig256, serverCipherConfig256, initialPayload)
}
