package ss2022

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func testShadowStreamReadWriter(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig, clientInitialPayload, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) {
	pl, pr := pipe.NewDuplexPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	saltPool := NewSaltPool[string](ReplayWindowDuration)
	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                    *ShadowStreamClientReadWriter
		s                    *ShadowStreamServerReadWriter
		serverTargetAddr     conn.Addr
		serverInitialPayload []byte
		cerr, serr           error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, _, cerr = NewShadowStreamClientReadWriter(&plo, clientCipherConfig, clientCipherConfig.ClientPSKHashes(), clientTargetAddr, clientInitialPayload, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serverInitialPayload, serr = NewShadowStreamServerReadWriter(pr, serverCipherConfig, saltPool, serverCipherConfig.ServerPSKHashMap(), unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
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

	if clientTargetAddr != serverTargetAddr {
		t.Errorf("Target address mismatch: c: %s, s: %s", clientTargetAddr, serverTargetAddr)
	}
	if !bytes.Equal(clientInitialPayload, serverInitialPayload) {
		t.Errorf("Initial payload mismatch: c: %v, s: %v", clientInitialPayload, serverInitialPayload)
	}

	zerocopy.ReadWriterTestFunc(t, c, s)
}

func testShadowStreamReadWriterReplay(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig) {
	pl, pr := pipe.NewDuplexPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	saltPool := NewSaltPool[string](ReplayWindowDuration)
	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var cerr, serr error
	ctrlCh := make(chan struct{})

	// Start client.
	go func() {
		_, _, cerr = NewShadowStreamClientReadWriter(&plo, clientCipherConfig, clientCipherConfig.ClientPSKHashes(), clientTargetAddr, nil, nil, nil)
		ctrlCh <- struct{}{}
	}()

	// Hijack client request and save it in b.
	b := make([]byte, 1440)
	n, err := pr.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	sendFunc := func() {
		_, err = pl.Write(b[:n])
		if err != nil {
			t.Error(err)
		}
	}

	// Ensure client success.
	<-ctrlCh
	if cerr != nil {
		t.Fatal(cerr)
	}

	// Actually send the request.
	go sendFunc()

	// Start server.
	_, _, _, serr = NewShadowStreamServerReadWriter(pr, serverCipherConfig, saltPool, serverCipherConfig.ServerPSKHashMap(), nil, nil)
	if serr != nil {
		t.Fatal(serr)
	}

	// Send it again.
	go sendFunc()

	// Start server from replay.
	_, _, _, serr = NewShadowStreamServerReadWriter(pr, serverCipherConfig, saltPool, serverCipherConfig.ServerPSKHashMap(), nil, nil)
	if serr != ErrRepeatedSalt {
		t.Errorf("Expected ErrRepeatedSalt, got %v", serr)
	}
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
	unsafeRequestStreamPrefix := make([]byte, 64)
	unsafeResponseStreamPrefix := make([]byte, 64)

	if _, err = rand.Read(initialPayload); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(unsafeRequestStreamPrefix); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(unsafeResponseStreamPrefix); err != nil {
		t.Fatal(err)
	}

	testShadowStreamReadWriter(t, cipherConfig128, cipherConfig128, nil, nil, nil)
	testShadowStreamReadWriter(t, cipherConfig128, cipherConfig128, initialPayload, nil, nil)
	testShadowStreamReadWriter(t, cipherConfig128, cipherConfig128, nil, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
	testShadowStreamReadWriter(t, cipherConfig256, cipherConfig256, nil, nil, nil)
	testShadowStreamReadWriter(t, cipherConfig256, cipherConfig256, initialPayload, nil, nil)
	testShadowStreamReadWriter(t, cipherConfig256, cipherConfig256, nil, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)

	testShadowStreamReadWriterReplay(t, cipherConfig128, cipherConfig128)
	testShadowStreamReadWriterReplay(t, cipherConfig256, cipherConfig256)
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
	unsafeRequestStreamPrefix := make([]byte, 64)
	unsafeResponseStreamPrefix := make([]byte, 64)

	if _, err = rand.Read(initialPayload); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(unsafeRequestStreamPrefix); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(unsafeResponseStreamPrefix); err != nil {
		t.Fatal(err)
	}

	testShadowStreamReadWriter(t, &clientCipherConfig128, serverCipherConfig128, nil, nil, nil)
	testShadowStreamReadWriter(t, &clientCipherConfig128, serverCipherConfig128, initialPayload, nil, nil)
	testShadowStreamReadWriter(t, &clientCipherConfig128, serverCipherConfig128, nil, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
	testShadowStreamReadWriter(t, &clientCipherConfig256, serverCipherConfig256, nil, nil, nil)
	testShadowStreamReadWriter(t, &clientCipherConfig256, serverCipherConfig256, initialPayload, nil, nil)
	testShadowStreamReadWriter(t, &clientCipherConfig256, serverCipherConfig256, nil, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)

	testShadowStreamReadWriterReplay(t, &clientCipherConfig128, serverCipherConfig128)
	testShadowStreamReadWriterReplay(t, &clientCipherConfig256, serverCipherConfig256)
}
