package direct

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/pipe"
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
		c                *DirectStreamReadWriter
		s                *DirectStreamReadWriter
		serverTargetAddr conn.Addr
		nr               int
		cerr, serr       error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, _, cerr = NewShadowsocksNoneStreamClientReadWriter(ctx, &plo, clientTargetAddr, clientInitialPayload)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serr = NewShadowsocksNoneStreamServerReadWriter(pr)
		if len(serverInitialPayload) > 0 && serr == nil {
			nr, serr = s.ReadZeroCopy(serverInitialPayload, 0, len(serverInitialPayload))
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

	if nr != len(serverInitialPayload) {
		t.Fatalf("Expected server initial payload bytes %d, got %d", len(serverInitialPayload), nr)
	}
	if !clientTargetAddr.Equals(serverTargetAddr) {
		t.Errorf("Target address mismatch: c: %s, s: %s", clientTargetAddr, serverTargetAddr)
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

	testShadowsocksNoneStreamReadWriter(t, ctx, nil)
	testShadowsocksNoneStreamReadWriter(t, ctx, initialPayload)
}

func TestSocks5StreamReadWriter(t *testing.T) {
	pl, pr := pipe.NewDuplexPipe()

	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                *DirectStreamReadWriter
		s                *DirectStreamReadWriter
		serverTargetAddr conn.Addr
		cerr, serr       error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, cerr = NewSocks5StreamClientReadWriter(pl, clientTargetAddr)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serr = NewSocks5StreamServerReadWriter(pr, true, false)
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

	zerocopy.ReadWriterTestFunc(t, c, s)
}
