package ss2022

import (
	"crypto/rand"
	"io"
	"net/netip"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"go.uber.org/zap/zaptest"
)

func testStreamClientServer(
	t *testing.T,
	allowSegmentedFixedLengthHeader bool,
	clientCipherConfig *ClientCipherConfig,
	userCipherConfig UserCipherConfig,
	identityCipherConfig ServerIdentityCipherConfig,
	userLookupMap UserLookupMap,
	unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte,
	username string,
) {
	addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 20220)

	newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
		clientConfig := StreamClientConfig{
			Name:                            "test",
			InnerClient:                     psc,
			Addr:                            addr,
			AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
			CipherConfig:                    clientCipherConfig,
			UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
			UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
		}
		return clientConfig.NewStreamClient()
	}

	serverConfig := StreamServerConfig{
		AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
		UserCipherConfig:                userCipherConfig,
		IdentityCipherConfig:            identityCipherConfig,
		UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
		UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
	}
	server := serverConfig.NewStreamServer()
	server.ReplaceUserLookupMap(userLookupMap)

	netiotest.TestWrapConnStreamClientServerProceed(
		t,
		newClient,
		server,
		addr,
		username,
	)
}

func testStreamClientServerReplay(
	t *testing.T,
	allowSegmentedFixedLengthHeader bool,
	clientCipherConfig *ClientCipherConfig,
	userCipherConfig UserCipherConfig,
	identityCipherConfig ServerIdentityCipherConfig,
	userLookupMap UserLookupMap,
	unsafeRequestStreamPrefix, unsafeResponseStreamPrefix []byte,
) {
	ctx := t.Context()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	psc, ch := netiotest.NewPipeStreamClient(netio.StreamDialerInfo{
		Name:                 "test",
		NativeInitialPayload: true,
	})

	reqCh := make(chan []byte)

	serverConfig := StreamServerConfig{
		AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
		UserCipherConfig:                userCipherConfig,
		IdentityCipherConfig:            identityCipherConfig,
		UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
		UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
	}
	server := serverConfig.NewStreamServer()
	server.ReplaceUserLookupMap(userLookupMap)

	go func() {
		defer psc.Close()

		// 1. Hijack client request and send it to reqCh.
		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			req, err := io.ReadAll(pc)
			if err != nil {
				t.Errorf("io.ReadAll failed: %v", err)
			}
			_ = pc.Close()
			reqCh <- req
		}

		// 2. Server sees it for the first time.
		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			if _, err := server.HandleStream(pc, logger); err != nil {
				t.Errorf("server.HandleStream failed: %v", err)
			}
			_ = pc.Close()
		}

		// 3. Server sees it again.
		select {
		case <-ctx.Done():
			t.Error("DialStream not called")
			return

		case pc := <-ch:
			if _, err := server.HandleStream(pc, logger); err != ErrRepeatedSalt {
				t.Errorf("server.HandleStream = %v, want %v", err, ErrRepeatedSalt)
			}
			_ = pc.Close()
		}
	}()

	serverAddr := conn.AddrFromIPAndPort(netip.IPv6Unspecified(), 20220)
	clientTargetAddr := conn.AddrFromIPAndPort(netip.IPv6Unspecified(), 53)

	clientConfig := StreamClientConfig{
		Name:                            "test",
		InnerClient:                     psc,
		Addr:                            serverAddr,
		AllowSegmentedFixedLengthHeader: allowSegmentedFixedLengthHeader,
		CipherConfig:                    clientCipherConfig,
		UnsafeRequestStreamPrefix:       unsafeRequestStreamPrefix,
		UnsafeResponseStreamPrefix:      unsafeResponseStreamPrefix,
	}
	client := clientConfig.NewStreamClient()

	// Let the client send the request.
	clientConn, err := client.DialStream(ctx, clientTargetAddr, nil)
	if err != nil {
		t.Fatalf("client.DialStream failed: %v", err)
	}
	if err = clientConn.CloseWrite(); err != nil {
		t.Fatalf("clientConn.CloseWrite failed: %v", err)
	}

	// Receive the hijacked request.
	req := <-reqCh

	// Send it twice.
	for range 2 {
		clientConn, err := psc.DialStream(ctx, clientTargetAddr, req)
		if err == nil {
			_ = clientConn.Close()
		}
	}

	// This also synchronizes the exit of the server goroutine.
	if _, ok := <-ch; ok {
		t.Error("DialStream called more than expected")
	}
}

func TestStreamClientServer(t *testing.T) {
	t.Parallel()
	for _, method := range methodCases {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			for _, udpCase := range [...]struct {
				name      string
				enableUDP bool
			}{
				{"EnableUDP", true},
				{"DisableUDP", false},
			} {
				t.Run(udpCase.name, func(t *testing.T) {
					t.Parallel()
					for _, cipherCase := range cipherCases {
						t.Run(cipherCase.name, func(t *testing.T) {
							t.Parallel()

							clientCipherConfig,
								userCipherConfig,
								identityCipherConfig,
								userLookupMap,
								username,
								err := cipherCase.newCipherConfig(method, udpCase.enableUDP)
							if err != nil {
								t.Fatal(err)
							}

							for _, readOnceOrFullCase := range [...]struct {
								name                            string
								allowSegmentedFixedLengthHeader bool
							}{
								{"ReadOnceExpectFull", false},
								{"ReadFull", true},
							} {
								t.Run(readOnceOrFullCase.name, func(t *testing.T) {
									t.Parallel()
									for _, unsafeStreamPrefixCase := range [...]struct {
										name     string
										generate func() (request, response []byte)
									}{
										{
											name: "NoPrefix",
											generate: func() (request, response []byte) {
												return nil, nil
											},
										},
										{
											name: "ShortPrefix",
											generate: func() (request, response []byte) {
												return []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
													[]byte("HTTP/1.1 200 OK\r\n\r\n")
											},
										},
										{
											name: "GiganticPrefix",
											generate: func() (request, response []byte) {
												b := make([]byte, 1<<21)
												rand.Read(b)
												return b[:1<<20], b[1<<20:]
											},
										},
									} {
										t.Run(unsafeStreamPrefixCase.name, func(t *testing.T) {
											t.Parallel()
											unsafeRequestStreamPrefix, unsafeResponseStreamPrefix := unsafeStreamPrefixCase.generate()
											t.Run("Proceed", func(t *testing.T) {
												t.Parallel()
												testStreamClientServer(
													t,
													readOnceOrFullCase.allowSegmentedFixedLengthHeader,
													clientCipherConfig,
													userCipherConfig,
													identityCipherConfig,
													userLookupMap,
													unsafeRequestStreamPrefix,
													unsafeResponseStreamPrefix,
													username,
												)
											})
											t.Run("Replay", func(t *testing.T) {
												t.Parallel()
												testStreamClientServerReplay(
													t,
													readOnceOrFullCase.allowSegmentedFixedLengthHeader,
													clientCipherConfig,
													userCipherConfig,
													identityCipherConfig,
													userLookupMap,
													unsafeRequestStreamPrefix,
													unsafeResponseStreamPrefix,
												)
											})
										})
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkStreamClientServer(b *testing.B) {
	for _, method := range methodCases {
		b.Run(method, func(b *testing.B) {
			clientCipherConfig,
				userCipherConfig,
				identityCipherConfig,
				userLookupMap,
				_,
				err := cipherCases[0].newCipherConfig(method, false)
			if err != nil {
				b.Fatal(err)
			}

			addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 20220)

			newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
				clientConfig := StreamClientConfig{
					Name:         "test",
					InnerClient:  psc,
					Addr:         addr,
					CipherConfig: clientCipherConfig,
				}
				return clientConfig.NewStreamClient()
			}

			serverConfig := StreamServerConfig{
				UserCipherConfig:     userCipherConfig,
				IdentityCipherConfig: identityCipherConfig,
			}
			server := serverConfig.NewStreamServer()
			server.ReplaceUserLookupMap(userLookupMap)

			netiotest.BenchmarkStreamClientServer(b, newClient, server, streamMaxPayloadSize)
		})
	}
}
