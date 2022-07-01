package http

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/pipe"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

func TestHttpStreamReadWriter(t *testing.T) {
	logger, err := logging.NewProductionConsole(false, "debug")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Sync()

	pl, pr := pipe.NewDuplexPipe()

	clientTargetAddr := socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		c                *direct.DirectStreamReadWriter
		s                *direct.DirectStreamReadWriter
		serverTargetAddr socks5.Addr
		cerr, serr       error
	)

	ctrlCh := make(chan struct{})

	go func() {
		c, cerr = NewHttpStreamClientReadWriter(pl, clientTargetAddr)
		ctrlCh <- struct{}{}
	}()

	go func() {
		s, serverTargetAddr, serr = NewHttpStreamServerReadWriter(pr, logger)
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
