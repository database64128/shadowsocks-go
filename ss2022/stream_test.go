package ss2022

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func testShadowStreamReadWriter(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig, clientInitialPayload, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) {
	pl, pr := pipe.NewDuplexPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	c := TCPClient{
		rwo:                        &plo,
		cipherConfig:               clientCipherConfig,
		eihPSKHashes:               clientCipherConfig.ClientPSKHashes(),
		unsafeRequestStreamPrefix:  unsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
	s := NewTCPServer(serverCipherConfig, serverCipherConfig.ServerPSKHashMap(), unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)

	var (
		crw                  zerocopy.ReadWriter
		srw                  zerocopy.ReadWriter
		serverTargetAddr     conn.Addr
		serverInitialPayload []byte
		cerr, serr           error
	)

	ctrlCh := make(chan struct{})

	go func() {
		_, crw, cerr = c.Dial(clientTargetAddr, clientInitialPayload)
		ctrlCh <- struct{}{}
	}()

	go func() {
		srw, serverTargetAddr, serverInitialPayload, serr = s.Accept(pr)
		if serr == nil && len(serverInitialPayload) < len(clientInitialPayload) {
			// Read excess payload.
			b := make([]byte, len(clientInitialPayload))
			copy(b, serverInitialPayload)
			scrw := zerocopy.NewCopyReadWriter(srw)
			_, serr = io.ReadFull(scrw, b[len(serverInitialPayload):])
			serverInitialPayload = b
		}
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

	if !clientTargetAddr.Equals(serverTargetAddr) {
		t.Errorf("Target address mismatch: c: %s, s: %s", clientTargetAddr, serverTargetAddr)
	}
	if !bytes.Equal(clientInitialPayload, serverInitialPayload) {
		t.Errorf("Initial payload mismatch: c: %v, s: %v", clientInitialPayload, serverInitialPayload)
	}

	zerocopy.ReadWriterTestFunc(t, crw, srw)
}

func testShadowStreamReadWriterReplay(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig) {
	pl, pr := pipe.NewDuplexPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	c := TCPClient{
		rwo:          &plo,
		cipherConfig: clientCipherConfig,
		eihPSKHashes: clientCipherConfig.ClientPSKHashes(),
	}
	s := NewTCPServer(serverCipherConfig, serverCipherConfig.ServerPSKHashMap(), nil, nil)

	var cerr, serr error
	ctrlCh := make(chan struct{})

	// Start client.
	go func() {
		_, _, cerr = c.Dial(clientTargetAddr, nil)
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
	_, _, _, serr = s.Accept(pr)
	if serr != nil {
		t.Fatal(serr)
	}

	// Send it again.
	go sendFunc()

	// Start server from replay.
	_, _, _, serr = s.Accept(pr)
	if serr != ErrRepeatedSalt {
		t.Errorf("Expected ErrRepeatedSalt, got %v", serr)
	}
}

func testShadowStreamReadWriterWithCipher(t *testing.T, clientCipherConfig, serverCipherConfig *CipherConfig) {
	smallInitialPayload := make([]byte, 1024)
	largeInitialPayload := make([]byte, 128*1024)
	unsafeRequestStreamPrefix := make([]byte, 64)
	unsafeResponseStreamPrefix := make([]byte, 64)

	if _, err := rand.Read(smallInitialPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(largeInitialPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(unsafeRequestStreamPrefix); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(unsafeResponseStreamPrefix); err != nil {
		t.Fatal(err)
	}

	t.Run("NoInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, clientCipherConfig, serverCipherConfig, nil, nil, nil)
	})
	t.Run("SmallInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, clientCipherConfig, serverCipherConfig, smallInitialPayload, nil, nil)
	})
	t.Run("LargeInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, clientCipherConfig, serverCipherConfig, largeInitialPayload, nil, nil)
	})
	t.Run("UnsafeStreamPrefix", func(t *testing.T) {
		testShadowStreamReadWriter(t, clientCipherConfig, serverCipherConfig, nil, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
	})

	t.Run("Replay", func(t *testing.T) {
		testShadowStreamReadWriterReplay(t, clientCipherConfig, serverCipherConfig)
	})
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

	t.Run("128", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, cipherConfig128, cipherConfig128)
	})
	t.Run("256", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, cipherConfig256, cipherConfig256)
	})
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

	t.Run("128", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, &clientCipherConfig128, serverCipherConfig128)
	})
	t.Run("256", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, &clientCipherConfig256, serverCipherConfig256)
	})
}
