package httpproxy

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestHttpStreamReadWriter(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	for _, c := range []struct {
		name                  string
		expectedUsername      string
		clientProxyAuthHeader string
		serverUsernameByToken map[string]string
	}{
		{
			name:                  "NoAuth",
			expectedUsername:      "",
			clientProxyAuthHeader: "",
			serverUsernameByToken: nil,
		},
		{
			name:                  "BasicAuth",
			expectedUsername:      "hello",
			clientProxyAuthHeader: "\r\nProxy-Authorization: basic aGVsbG86d29ybGQ=",
			serverUsernameByToken: map[string]string{"aGVsbG86d29ybGQ=": "hello"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			testHttpStreamReadWriter(t, c.expectedUsername, c.clientProxyAuthHeader, c.serverUsernameByToken, logger)
		})
	}

	t.Run("BasicAuth/BadCredentials", func(t *testing.T) {
		testHttpStreamReadWriterBasicAuthBadCredentials(t, logger)
	})
}

func testHttpStreamReadWriter(t *testing.T, expectedUsername, clientProxyAuthHeader string, serverUsernameByToken map[string]string, logger *zap.Logger) {
	pl, pr := netio.NewPipe()

	clientTargetAddr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80)

	var (
		wg               sync.WaitGroup
		clientConn       netio.Conn
		serverConn       netio.Conn
		serverTargetAddr conn.Addr
		username         string
		cerr, serr       error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		clientConn, cerr = ClientConnect(pl, clientTargetAddr, clientProxyAuthHeader)
	}()

	go func() {
		defer wg.Done()
		var serverPendingConn netio.PendingConn
		serverPendingConn, serverTargetAddr, username, serr = ServerHandle(pr, logger, serverUsernameByToken)
		if serr == nil {
			serverConn, serr = serverPendingConn.Proceed()
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

	zerocopy.ReadWriterTestFunc(t, direct.NewDirectStreamReadWriter(clientConn), direct.NewDirectStreamReadWriter(serverConn))
}

func testHttpStreamReadWriterBasicAuthBadCredentials(t *testing.T, logger *zap.Logger) {
	pl, pr := netio.NewPipe()

	clientTargetAddr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80)
	clientProxyAuthHeaders := [...]string{
		"",
		"\r\nProxy-Authorization: Basic aGVsbG86d29ybGQ=",
		"\r\nProxy-Authorization: Basic dGVzdDoxMjPCow==",
		"\r\nProxy-Authorization: Basic aGVsbG86d29ybGQ=",
		"\r\nProxy-Authorization: Bas1c QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
		"\r\nProxy-Authorization: Digest",
	}
	clientErrors := make([]error, len(clientProxyAuthHeaders))

	var (
		wg   sync.WaitGroup
		serr error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		for i, clientProxyAuthHeader := range clientProxyAuthHeaders {
			_, clientErrors[i] = ClientConnect(pl, clientTargetAddr, clientProxyAuthHeader)
		}
		_ = pl.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		var serverPendingConn netio.PendingConn
		serverPendingConn, _, _, serr = ServerHandle(pr, logger, map[string]string{"QWxhZGRpbjpvcGVuIHNlc2FtZQ==": "Aladdin"})
		if serr == nil {
			_, serr = serverPendingConn.Proceed()
		}
	}()

	wg.Wait()

	for i, err := range clientErrors {
		var respErr ConnectNonSuccessfulResponseError
		if !errors.As(err, &respErr) {
			t.Fatalf("clientErrors[%d] = %v, want %T", i, err, respErr)
		}
		if respErr.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("clientErrors[%d].StatusCode = %d, want %d", i, respErr.StatusCode, http.StatusProxyAuthRequired)
		}
	}

	var authErr FailedAuthAttemptsError
	if !errors.As(serr, &authErr) {
		t.Fatalf("serr = %v, want %T", serr, authErr)
	}
	if authErr.Attempts != len(clientProxyAuthHeaders) {
		t.Errorf("authErr.Attempts = %d, want %d", authErr.Attempts, len(clientProxyAuthHeaders))
	}
}

func TestHttpStreamClientReadWriterServerSpeaksFirst(t *testing.T) {
	pl, pr := netio.NewPipe()

	clientTargetAddr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 80)
	clientTargetAddrString := clientTargetAddr.String()
	expectedRequest := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: shadowsocks-go/"+shadowsocks.Version+"\r\n\r\n", clientTargetAddrString, clientTargetAddrString)

	var (
		wg         sync.WaitGroup
		clientConn netio.Conn
		clientErr  error
	)

	// Start client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientConn, clientErr = ClientConnect(pl, clientTargetAddr, "")
	}()

	// Read and verify client request.
	b := make([]byte, 1024)
	n, err := pr.Read(b)
	if err != nil {
		t.Fatalf("Failed to read client request: %s", err)
	}
	b = b[:n]

	if string(b) != expectedRequest {
		t.Errorf("request = %q, want %q", b, expectedRequest)
	}

	const serverPayload = "I'd like to speak first!"

	// Write server response with payload.
	if _, err := pr.Write([]byte("HTTP/1.1 200 OK\r\n\r\n" + serverPayload)); err != nil {
		t.Fatalf("Failed to write server response: %s", err)
	}

	wg.Wait()
	if clientErr != nil {
		t.Fatal(clientErr)
	}

	// Read from client and verify.
	b = b[:1024]
	n, err = clientConn.Read(b)
	if err != nil {
		t.Fatalf("Failed to read from client: %s", err)
	}
	b = b[:n]

	if string(b) != serverPayload {
		t.Errorf("payload = %q, want %q", b, serverPayload)
	}

	const clientPayload = "Hear! Hear!"

	// Write client payload.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, clientErr = clientConn.Write([]byte(clientPayload))
		_ = clientConn.CloseWrite()
	}()

	// Read from server and verify.
	b = b[:1024]
	n, err = pr.Read(b)
	if err != nil {
		t.Fatalf("Failed to read from server: %s", err)
	}
	b = b[:n]

	if string(b) != clientPayload {
		t.Errorf("payload = %q, want %q", b, clientPayload)
	}

	wg.Wait()
}

func testHostHeaderToDomainPort(t *testing.T, host, expectedDomain string, expectedPort uint16) {
	addr, err := hostHeaderToAddr(host)
	if err != nil {
		t.Errorf("Failed to parse %s: %s", host, err)
	}
	if domain := addr.Domain(); domain != expectedDomain {
		t.Errorf("Expected domain %s, got %s", expectedDomain, domain)
	}
	if port := addr.Port(); port != expectedPort {
		t.Errorf("Expected port %d, got %d", expectedPort, port)
	}
}

func testHostHeaderToIPPort(t *testing.T, host string, expectedAddrPort netip.AddrPort) {
	addr, err := hostHeaderToAddr(host)
	if err != nil {
		t.Errorf("Failed to parse %s: %s", host, err)
	}
	if addrPort := addr.IPPort(); addrPort != expectedAddrPort {
		t.Errorf("Expected addrPort %s, got %s", expectedAddrPort, addrPort)
	}
}

func testHostHeaderToError(t *testing.T, host string, expectedErr error) {
	_, err := hostHeaderToAddr(host)
	if err != expectedErr {
		t.Errorf("Expected error %s, got %s", expectedErr, err)
	}
}

func TestHostHeaderToAddr(t *testing.T) {
	testHostHeaderToDomainPort(t, "example.com", "example.com", 80)
	testHostHeaderToDomainPort(t, "example.com:443", "example.com", 443)

	addr4 := netip.AddrFrom4([4]byte{1, 1, 1, 1})
	testHostHeaderToIPPort(t, "1.1.1.1", netip.AddrPortFrom(addr4, 80))
	testHostHeaderToIPPort(t, "1.1.1.1:443", netip.AddrPortFrom(addr4, 443))

	addr6 := netip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 14: 0x11, 15: 0x11})
	testHostHeaderToIPPort(t, "[2606:4700:4700::1111]", netip.AddrPortFrom(addr6, 80))
	testHostHeaderToIPPort(t, "[2606:4700:4700::1111]:443", netip.AddrPortFrom(addr6, 443))

	testHostHeaderToError(t, "", errEmptyHostHeader)
}

func TestRemoveConnectionSpecificFields(t *testing.T) {
	header := http.Header{
		"Connection":                []string{"keep-alive, upgrade, drop-this"},
		"Proxy-Connection":          []string{"Keep-Alive"},
		"Keep-Alive":                []string{"timeout=5, max=1000"},
		"Upgrade":                   []string{"websocket"},
		"Drop-This":                 []string{"Drop me!"},
		"Keep-This":                 []string{"Keep me!"},
		"Te":                        []string{"trailers"},
		"Transfer-Encoding":         []string{"chunked"},
		"Proxy-Authenticate":        []string{"#challenge"},
		"Proxy-Authorization":       []string{"credentials"},
		"Proxy-Authentication-Info": []string{"#auth-param"},
	}

	expectedHeader := http.Header{
		"Upgrade":   []string{"websocket"},
		"Keep-This": []string{"Keep me!"},
	}

	trailer := http.Header{
		"Drop-This": []string{"Drop me!"},
		"Keep-This": []string{"Keep me!"},
	}

	expectedTrailer := http.Header{
		"Keep-This": []string{"Keep me!"},
	}

	removeConnectionSpecificFields(header, trailer)

	if !maps.EqualFunc(header, expectedHeader, slices.Equal) {
		t.Errorf("header = %v, expected %v", header, expectedHeader)
	}

	if !maps.EqualFunc(trailer, expectedTrailer, slices.Equal) {
		t.Errorf("trailer = %v, expected %v", trailer, expectedTrailer)
	}
}
