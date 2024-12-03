package direct

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/netip"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func TestDirectStreamReadWriter(t *testing.T) {
	pl, pr := pipe.NewDuplexPipe()

	l := DirectStreamReadWriter{
		rw: pl,
	}
	r := DirectStreamReadWriter{
		rw: pr,
	}

	zerocopy.ReadWriterTestFunc(t, &l, &r)
}

func testShadowsocksNoneStreamReadWriter(t *testing.T, ctx context.Context, clientInitialPayload []byte) {
	pl, pr := pipe.NewDuplexPipe()
	plo := zerocopy.SimpleDirectReadWriteCloserOpener{DirectReadWriteCloser: pl}

	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))
	serverInitialPayload := make([]byte, len(clientInitialPayload))

	var (
		wg               sync.WaitGroup
		c                *DirectStreamReadWriter
		s                *DirectStreamReadWriter
		serverTargetAddr conn.Addr
		nr               int
		cerr, serr       error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		c, _, cerr = NewShadowsocksNoneStreamClientReadWriter(ctx, &plo, clientTargetAddr, clientInitialPayload)
	}()

	go func() {
		defer wg.Done()
		s, serverTargetAddr, serr = NewShadowsocksNoneStreamServerReadWriter(pr)
		if serr != nil {
			return
		}
		if len(serverInitialPayload) > 0 {
			nr, serr = s.ReadZeroCopy(serverInitialPayload, 0, len(serverInitialPayload))
		}
	}()

	wg.Wait()

	if cerr != nil {
		t.Fatal(cerr)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	if nr != len(serverInitialPayload) {
		t.Fatalf("Expected server initial payload bytes %d, got %d", len(serverInitialPayload), nr)
	}
	if !clientTargetAddr.Equals(serverTargetAddr) {
		t.Errorf("Target address mismatch: c: %q, s: %q", clientTargetAddr, serverTargetAddr)
	}
	if !bytes.Equal(clientInitialPayload, serverInitialPayload) {
		t.Error("Initial payload mismatch")
	}

	zerocopy.ReadWriterTestFunc(t, c, s)
}

func TestShadowsocksNoneStreamReadWriter(t *testing.T) {
	ctx := context.Background()
	initialPayload := make([]byte, 1024)
	_, err := rand.Read(initialPayload)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("NoInitialPayload", func(t *testing.T) {
		testShadowsocksNoneStreamReadWriter(t, ctx, nil)
	})

	t.Run("WithInitialPayload", func(t *testing.T) {
		testShadowsocksNoneStreamReadWriter(t, ctx, initialPayload)
	})
}

func TestSocks5StreamReadWriter(t *testing.T) {
	b := make([]byte, 255+255)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	userInfo255 := socks5.UserInfo{
		Username: string(b[:255]),
		Password: string(b[255:]),
	}

	for _, c := range []struct {
		name                     string
		clientAuthMsg            []byte
		serverUserInfoByUsername map[string]socks5.UserInfo
		expectedUsername         string
	}{
		{
			name:                     "NoAuth",
			clientAuthMsg:            nil,
			serverUserInfoByUsername: nil,
			expectedUsername:         "",
		},
		{
			name:          "UserPassAuth/1",
			clientAuthMsg: []byte{socks5.UsernamePasswordAuthVersion, 1, 'h', 1, 'w'},
			serverUserInfoByUsername: map[string]socks5.UserInfo{
				"h": {
					Username: "h",
					Password: "w",
				},
			},
			expectedUsername: "h",
		},
		{
			name:          "UserPassAuth/5",
			clientAuthMsg: []byte{socks5.UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			serverUserInfoByUsername: map[string]socks5.UserInfo{
				"hello": {
					Username: "hello",
					Password: "world",
				},
			},
			expectedUsername: "hello",
		},
		{
			name:          "UserPassAuth/255",
			clientAuthMsg: userInfo255.AppendAuthMsg(nil),
			serverUserInfoByUsername: map[string]socks5.UserInfo{
				userInfo255.Username: userInfo255,
			},
			expectedUsername: userInfo255.Username,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			testSocks5StreamReadWriter(t, c.clientAuthMsg, c.serverUserInfoByUsername, c.expectedUsername)
		})
	}
}

func testSocks5StreamReadWriter(t *testing.T, clientAuthMsg []byte, serverUserInfoByUsername map[string]socks5.UserInfo, expectedUsername string) {
	pl, pr := pipe.NewDuplexPipe()

	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		wg               sync.WaitGroup
		c                *DirectStreamReadWriter
		s                *DirectStreamReadWriter
		serverTargetAddr conn.Addr
		username         string
		cerr, serr       error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		if len(clientAuthMsg) == 0 {
			c, cerr = NewSocks5StreamClientReadWriter(pl, clientTargetAddr)
		} else {
			c, cerr = NewSocks5AuthStreamClientReadWriter(pl, clientAuthMsg, clientTargetAddr)
		}
	}()

	go func() {
		defer wg.Done()
		if serverUserInfoByUsername == nil {
			s, serverTargetAddr, serr = NewSocks5StreamServerReadWriter(pr, true, false)
		} else {
			s, serverTargetAddr, username, serr = NewSocks5AuthStreamServerReadWriter(pr, serverUserInfoByUsername, true, false)
		}
	}()

	wg.Wait()

	if cerr != nil {
		t.Fatal(cerr)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	if !clientTargetAddr.Equals(serverTargetAddr) {
		t.Errorf("Target address mismatch: c: %q, s: %q", clientTargetAddr, serverTargetAddr)
	}
	if username != expectedUsername {
		t.Errorf("username = %q, want %q", username, expectedUsername)
	}

	zerocopy.ReadWriterTestFunc(t, c, s)
}
