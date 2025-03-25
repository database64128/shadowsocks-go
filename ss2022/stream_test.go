package ss2022

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func testShadowStreamReadWriter(t *testing.T, allowSegmentedFixedLengthHeader bool, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap, clientInitialPayload, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte) {
	pl, pr := netio.NewPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	clientTargetAddr := conn.AddrFromIPAndPort(netip.IPv6Unspecified(), 53)
	c := TCPClient{
		rwo:                        &plo,
		readOnceOrFull:             readOnceOrFullFunc(allowSegmentedFixedLengthHeader),
		cipherConfig:               clientCipherConfig,
		unsafeRequestStreamPrefix:  unsafeRequestStreamPrefix,
		unsafeResponseStreamPrefix: unsafeResponseStreamPrefix,
	}
	s := NewTCPServer(allowSegmentedFixedLengthHeader, userCipherConfig, identityCipherConfig, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
	s.ReplaceUserLookupMap(userLookupMap)

	var (
		crw                  zerocopy.ReadWriter
		srw                  zerocopy.ReadWriter
		serverTargetAddr     conn.Addr
		serverInitialPayload []byte
		cerr, serr           error
	)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		_, crw, cerr = c.Dial(t.Context(), clientTargetAddr, clientInitialPayload)
		wg.Done()
	}()

	go func() {
		srw, serverTargetAddr, serverInitialPayload, _, serr = s.Accept(pr)
		if serr == nil && len(serverInitialPayload) < len(clientInitialPayload) {
			// Read excess payload.
			b := make([]byte, len(clientInitialPayload))
			copy(b, serverInitialPayload)
			scr := zerocopy.NewCopyReader(srw)
			_, serr = io.ReadFull(scr, b[len(serverInitialPayload):])
			serverInitialPayload = b
		}
		wg.Done()
	}()

	wg.Wait()
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

func testShadowStreamReadWriterReplay(t *testing.T, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap) {
	pl, pr := netio.NewPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}
	clientTargetAddr := conn.AddrFromIPAndPort(netip.IPv6Unspecified(), 53)
	c := TCPClient{
		rwo:            &plo,
		readOnceOrFull: readOnceExpectFull,
		cipherConfig:   clientCipherConfig,
	}
	s := NewTCPServer(false, userCipherConfig, identityCipherConfig, nil, nil)
	s.ReplaceUserLookupMap(userLookupMap)

	var (
		wg   sync.WaitGroup
		cerr error
	)

	// Start client.
	wg.Add(1)
	go func() {
		_, _, cerr = c.Dial(t.Context(), clientTargetAddr, nil)
		wg.Done()
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
	wg.Wait()
	if cerr != nil {
		t.Fatal(cerr)
	}

	// Actually send the request.
	go sendFunc()

	// Start server.
	_, _, _, _, serr := s.Accept(pr)
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

func testShadowStreamReadWriterWithCipher(t *testing.T, clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap) {
	smallInitialPayload := make([]byte, 1024)
	largeInitialPayload := make([]byte, 128*1024)
	unsafeRequestStreamPrefix := make([]byte, 64)
	unsafeResponseStreamPrefix := make([]byte, 64)

	rand.Read(smallInitialPayload)
	rand.Read(largeInitialPayload)
	rand.Read(unsafeRequestStreamPrefix)
	rand.Read(unsafeResponseStreamPrefix)

	t.Run("NoInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, false, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, nil, nil, nil)
	})
	t.Run("SmallInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, false, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, smallInitialPayload, nil, nil)
	})
	t.Run("LargeInitialPayload", func(t *testing.T) {
		testShadowStreamReadWriter(t, false, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, largeInitialPayload, nil, nil)
	})
	t.Run("UnsafeStreamPrefix", func(t *testing.T) {
		testShadowStreamReadWriter(t, false, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, nil, unsafeRequestStreamPrefix, unsafeResponseStreamPrefix)
	})
	t.Run("AllowSegmentedFixedLengthHeader", func(t *testing.T) {
		testShadowStreamReadWriter(t, true, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap, nil, nil, nil)
	})

	t.Run("Replay", func(t *testing.T) {
		testShadowStreamReadWriterReplay(t, clientCipherConfig, userCipherConfig, identityCipherConfig, userLookupMap)
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
	clientCipherConfig128, identityCipherConfig128, userLookupMap128, err := newRandomCipherConfigTupleWithEIH("2022-blake3-aes-128-gcm", false)
	if err != nil {
		t.Fatal(err)
	}
	clientCipherConfig256, identityCipherConfig256, userLookupMap256, err := newRandomCipherConfigTupleWithEIH("2022-blake3-aes-256-gcm", false)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("128", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, clientCipherConfig128, UserCipherConfig{}, identityCipherConfig128, userLookupMap128)
	})
	t.Run("256", func(t *testing.T) {
		testShadowStreamReadWriterWithCipher(t, clientCipherConfig256, UserCipherConfig{}, identityCipherConfig256, userLookupMap256)
	})
}
