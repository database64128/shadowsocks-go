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
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"go.uber.org/zap/zaptest"
)

func TestStreamClientServer(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name                  string
		clientUsername        string
		clientPassword        string
		clientUseBasicAuth    bool
		serverEnableBasicAuth bool
		serverUsers           []ServerUserCredentials
	}{
		{
			name:                  "NoAuth",
			clientUsername:        "",
			clientPassword:        "",
			clientUseBasicAuth:    false,
			serverEnableBasicAuth: false,
			serverUsers:           nil,
		},
		{
			name:                  "BasicAuth",
			clientUsername:        "hello",
			clientPassword:        "world",
			clientUseBasicAuth:    true,
			serverEnableBasicAuth: true,
			serverUsers: []ServerUserCredentials{
				{
					Username: "hello",
					Password: "world",
				},
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 8080)

			newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
				clientConfig := ClientConfig{
					Name:         "test",
					InnerClient:  psc,
					Addr:         addr,
					Username:     c.clientUsername,
					Password:     c.clientPassword,
					UseBasicAuth: c.clientUseBasicAuth,
				}
				client, err := clientConfig.NewProxyClient()
				if err != nil {
					t.Fatalf("Failed to create client: %v", err)
				}
				return client
			}

			serverConfig := ServerConfig{
				Users:           c.serverUsers,
				EnableBasicAuth: c.serverEnableBasicAuth,
			}
			server, err := serverConfig.NewProxyServer()
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			t.Run("Proceed", func(t *testing.T) {
				t.Parallel()
				netiotest.TestPreambleStreamClientServerProceed(
					t,
					newClient,
					server,
					addr,
					c.clientUsername,
				)
			})

			t.Run("Abort", func(t *testing.T) {
				t.Parallel()
				netiotest.TestStreamClientServerAbort(
					t,
					newClient,
					server,
					func(t *testing.T, dialResult conn.DialResult, err error) {
						e, ok := errors.AsType[ConnectNonSuccessfulResponseError](err)
						if !ok {
							t.Errorf("err = %v, want %T", err, e)
							return
						}
						if e.StatusCode != http.StatusBadGateway {
							t.Errorf("e.StatusCode = %d, want %d", e.StatusCode, http.StatusBadGateway)
						}
					},
				)
			})
		})
	}
}

func TestStreamClientServerBasicAuthBadCredentials(t *testing.T) {
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

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

	wg.Go(func() {
		for i, clientProxyAuthHeader := range clientProxyAuthHeaders {
			_, clientErrors[i] = ClientConnect(pl, clientTargetAddr, clientProxyAuthHeader)
		}
		_ = pl.CloseWrite()
	})

	wg.Go(func() {
		_, _, _, serr = ServerHandle(pr, logger, map[string]string{"QWxhZGRpbjpvcGVuIHNlc2FtZQ==": "Aladdin"})
	})

	wg.Wait()

	for i, err := range clientErrors {
		respErr, ok := errors.AsType[ConnectNonSuccessfulResponseError](err)
		if !ok {
			t.Fatalf("clientErrors[%d] = %v, want %T", i, err, respErr)
		}
		if respErr.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("clientErrors[%d].StatusCode = %d, want %d", i, respErr.StatusCode, http.StatusProxyAuthRequired)
		}
	}

	authErr, ok := errors.AsType[FailedAuthAttemptsError](serr)
	if !ok {
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
	wg.Go(func() {
		clientConn, clientErr = ClientConnect(pl, clientTargetAddr, "")
	})

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
	wg.Go(func() {
		_, clientErr = clientConn.Write([]byte(clientPayload))
		_ = clientConn.CloseWrite()
	})

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

func TestHostHeaderToAddr(t *testing.T) {
	addr4 := netip.AddrFrom4([4]byte{1, 1, 1, 1})
	addr6 := netip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 14: 0x11, 15: 0x11})

	for _, c := range []struct {
		name         string
		host         string
		expectedAddr conn.Addr
		expectedErr  error
	}{
		{"Domain", "example.com", conn.MustAddrFromDomainPort("example.com", 80), nil},
		{"DomainPort", "example.com:443", conn.MustAddrFromDomainPort("example.com", 443), nil},
		{"IPv4", "1.1.1.1", conn.AddrFromIPAndPort(addr4, 80), nil},
		{"IPv4Port", "1.1.1.1:443", conn.AddrFromIPAndPort(addr4, 443), nil},
		{"IPv6", "[2606:4700:4700::1111]", conn.AddrFromIPAndPort(addr6, 80), nil},
		{"IPv6Port", "[2606:4700:4700::1111]:443", conn.AddrFromIPAndPort(addr6, 443), nil},
		{"Empty", "", conn.Addr{}, errEmptyHostHeader},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, err := hostHeaderToAddr(c.host)
			if !addr.Equals(c.expectedAddr) {
				t.Errorf("addr = %v, want %v", addr, c.expectedAddr)
			}
			if !errors.Is(err, c.expectedErr) {
				t.Errorf("err = %v, want %v", err, c.expectedErr)
			}
		})
	}
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
		t.Errorf("header = %v, want %v", header, expectedHeader)
	}

	if !maps.EqualFunc(trailer, expectedTrailer, slices.Equal) {
		t.Errorf("trailer = %v, want %v", trailer, expectedTrailer)
	}
}
