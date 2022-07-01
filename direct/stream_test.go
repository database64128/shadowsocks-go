package direct

import (
	"bytes"
	"net/netip"
	"testing"

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

func TestShadowsocksNoneStreamReadWriter(t *testing.T) {
	pl, pr := pipe.NewDuplexPipe()

	clientTargetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                *DirectStreamReadWriter
		s                *DirectStreamReadWriter
		serverTargetAddr socks5.Addr
		cerr, serr       error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, cerr = NewShadowsocksNoneStreamClientReadWriter(pl, clientTargetAddr)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serr = NewShadowsocksNoneStreamServerReadWriter(pr)
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

	zerocopy.ReadWriterTestFunc(t, c, s)
}

func TestSocks5StreamReadWriter(t *testing.T) {
	pl, pr := pipe.NewDuplexPipe()

	clientTargetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                *DirectStreamReadWriter
		s                *DirectStreamReadWriter
		serverTargetAddr socks5.Addr
		cerr, serr       error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, cerr = NewSocks5StreamClientReadWriter(pl, clientTargetAddr)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serr = NewSocks5StreamServerReadWriter(pr, true, false, nil)
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

	zerocopy.ReadWriterTestFunc(t, c, s)
}
