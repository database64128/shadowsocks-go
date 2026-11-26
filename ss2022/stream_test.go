package ss2022

import (
	"crypto/rand"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"github.com/database64128/shadowsocks-go/tslog"
	"github.com/database64128/shadowsocks-go/tslogtest"
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

	newClient := func(t *testing.T, psc *netiotest.PipeStreamClient) netio.StreamClient {
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
	logger := tslogtest.NewLogger(t)

	psc, ch := netiotest.NewPipeStreamClient(false)

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

	var wg sync.WaitGroup
	wg.Go(func() {
		var dialCount int
		for pc := range ch {
			dialCount++
			switch dialCount {
			case 1: // Hijack client request and send it to reqCh.
				req, err := io.ReadAll(pc)
				if err != nil {
					t.Errorf("io.ReadAll failed: %v", err)
				}
				select {
				case <-ctx.Done():
				case reqCh <- req:
				}

			case 2: // Server sees it for the first time.
				if _, err := server.HandleStream(pc, logger); err != nil {
					t.Errorf("server.HandleStream failed: %v", err)
				}

			case 3: // Server sees it again.
				if _, err := server.HandleStream(pc, logger); err != ErrRepeatedSalt {
					t.Errorf("server.HandleStream = %v, want %v", err, ErrRepeatedSalt)
				}
			}
			_ = pc.Close()
		}
		if dialCount != 3 {
			t.Errorf("dialCount = %d, want 3", dialCount)
		}
	})
	t.Cleanup(func() {
		_ = psc.Close()
		wg.Wait()
	})

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

			newClient := func(b *testing.B, psc *netiotest.PipeStreamClient) netio.StreamClient {
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

func BenchmarkStreamClientDialServerHandleStream(b *testing.B) {
	for _, method := range methodCases {
		b.Run(method, func(b *testing.B) {
			for _, cipherCase := range cipherCases {
				b.Run(cipherCase.name, func(b *testing.B) {
					clientCipherConfig,
						userCipherConfig,
						identityCipherConfig,
						userLookupMap,
						_,
						err := cipherCase.newCipherConfig(method, false)
					if err != nil {
						b.Fatal(err)
					}

					addr := conn.AddrFromIPAndPort(netip.IPv6Loopback(), 20220)

					newClient := func(b *testing.B, psc *netiotest.PipeStreamClient) netio.StreamClient {
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

					netiotest.BenchmarkStreamClientDialServerHandle(b, newClient, newStreamServerClearSaltPool(server))
				})
			}
		})
	}
}

// streamServerClearSaltPool wraps a [StreamServer] and clears the salt pool after handling a stream connection.
// This is useful in benchmarks where the salt pool significantly affects the results.
type streamServerClearSaltPool struct {
	*StreamServer
}

func newStreamServerClearSaltPool(server *StreamServer) *streamServerClearSaltPool {
	return &streamServerClearSaltPool{
		StreamServer: server,
	}
}

// HandleStream implements [netio.StreamServer.HandleStream].
func (s *streamServerClearSaltPool) HandleStream(rawRW netio.Conn, logger *tslog.Logger) (req netio.ConnRequest, err error) {
	req, err = s.StreamServer.HandleStream(rawRW, logger)
	s.saltPool.Clear()
	return req, err
}
