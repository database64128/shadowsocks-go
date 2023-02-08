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

func testShadowStreamReadWriter(t *testing.T, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, uPSKMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig, clientInitialPayload, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) {
	pl, pr := pipe.NewDuplexPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	c := TCPClient{
		rwo:                        &plo,
		cipherConfig:               clientCipherConfig,
		unsafeRequestStreamPrefix:  unsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
	s := NewTCPServer(userCipherConfig, identityCipherConfig, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
	s.ReplaceUPSKMap(uPSKMap)

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
		srw, serverTargetAddr, serverInitialPayload, _, serr = s.Accept(pr)
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

func testShadowStreamReadWriterReplay(t *testing.T, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, uPSKMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig) {
	pl, pr := pipe.NewDuplexPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	c := TCPClient{
		rwo:          &plo,
		cipherConfig: clientCipherConfig,
	}
	s := NewTCPServer(userCipherConfig, identityCipherConfig, nil, nil)
	s.ReplaceUPSKMap(uPSKMap)

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
	_, _, _, _, serr = s.Accept(pr)
	if serr != nil {
		t.Fatal(serr)
	}

	// Send it again.
	go sendFunc()

	// Start server from replay.
	_, _, _, _, serr = s.Accept(pr)
	if serr != ErrRepeatedSalt {
		t.Errorf("Expected ErrRepeatedSalt, got %v", serr)
	}
}

func testShadowStreamReadWriterWithCipher(t *testing.T, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, uPSKMap map[[IdentityHeaderLength]byte]*ServerUserCipherConfig) {
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
		testShadowStreamReadWriter(t, clientCipherConfig, userCipherConfig, identityCipherConfig, uPSKMap, nil, nil, nil)
	})
	t.Run("SmallInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, clientCipherConfig, userCipherConfig, identityCipherConfig, uPSKMap, smallInitialPayload, nil, nil)
	})
	t.Run("LargeInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, clientCipherConfig, userCipherConfig, identityCipherConfig, uPSKMap, largeInitialPayload, nil, nil)
	})
	t.Run("UnsafeStreamPrefix", func(t *testing.T) {
		testShadowStreamReadWriter(t, clientCipherConfig, userCipherConfig, identityCipherConfig, uPSKMap, nil, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
	})

	t.Run("Replay", func(t *testing.T) {
		testShadowStreamReadWriterReplay(t, clientCipherConfig, userCipherConfig, identityCipherConfig, uPSKMap)
	})
}

func TestShadowStreamReadWriterNoEIH(t *testing.T) {
	clientCipherConfig128, userCipherConfig128, err := newRandomCipherConfigTupleNoEIH("2022-blake3-aes-128-gcm", false)
	if err != nil {
		t.Fatal(err)
	}
	clientCipherConfig256, userCipherConfig256, err := newRandomCipherConfigTupleNoEIH("2022-blake3-aes-256-gcm", false)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("128", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, clientCipherConfig128, userCipherConfig128, ServerIdentityCipherConfig{}, nil)
	})
	t.Run("256", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, clientCipherConfig256, userCipherConfig256, ServerIdentityCipherConfig{}, nil)
	})
}

func TestShadowStreamReadWriterWithEIH(t *testing.T) {
	clientCipherConfig128, identityCipherConfig128, uPSKMap128, err := newRandomCipherConfigTupleWithEIH("2022-blake3-aes-128-gcm", false)
	if err != nil {
		t.Fatal(err)
	}
	clientCipherConfig256, identityCipherConfig256, uPSKMap256, err := newRandomCipherConfigTupleWithEIH("2022-blake3-aes-256-gcm", false)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("128", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, clientCipherConfig128, UserCipherConfig{}, identityCipherConfig128, uPSKMap128)
	})
	t.Run("256", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, clientCipherConfig256, UserCipherConfig{}, identityCipherConfig256, uPSKMap256)
	})
}
