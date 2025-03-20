package socks5

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/netiotest"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestStreamClientError(t *testing.T) {
	for _, c := range []struct {
		name             string
		clientAuthMsg    []byte
		expectedRequests [][]byte
		serverMsgs       [][]byte
		checkClientErr   func(*testing.T, error)
	}{
		{
			name:          "UnsupportedVersion/4",
			clientAuthMsg: nil,
			expectedRequests: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
			},
			serverMsgs: [][]byte{
				{4, 1},
			},
			checkClientErr: func(t *testing.T, err error) {
				var e UnsupportedVersionError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != 4 {
					t.Errorf("e = %d, want 4", e)
				}
			},
		},
		{
			name:          "UnsupportedAuthMethod",
			clientAuthMsg: nil,
			expectedRequests: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
			},
			serverMsgs: [][]byte{
				{Version, MethodNoAcceptable},
			},
			checkClientErr: func(t *testing.T, err error) {
				var e UnsupportedAuthMethodError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != MethodNoAcceptable {
					t.Errorf("e = %d, want %d", e, MethodNoAcceptable)
				}
			},
		},
		{
			name:          "UnsupportedUsernamePasswordAuthVersion",
			clientAuthMsg: []byte{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			expectedRequests: [][]byte{
				{Version, 1, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			},
			serverMsgs: [][]byte{
				{Version, MethodUsernamePassword},
				{4, 1},
			},
			checkClientErr: func(t *testing.T, err error) {
				var e UnsupportedUsernamePasswordAuthVersionError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != 4 {
					t.Errorf("e = %d, want 4", e)
				}
			},
		},
		{
			name:          "IncorrectUsernamePassword",
			clientAuthMsg: []byte{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			expectedRequests: [][]byte{
				{Version, 1, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			},
			serverMsgs: [][]byte{
				{Version, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 1},
			},
			checkClientErr: func(t *testing.T, err error) {
				if err != ErrIncorrectUsernamePassword {
					t.Errorf("err = %v, want %v", err, ErrIncorrectUsernamePassword)
				}
			},
		},
		{
			name:          "ReplyError",
			clientAuthMsg: nil,
			expectedRequests: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
				{Version, CmdConnect, 0, AtypIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53},
			},
			serverMsgs: [][]byte{
				{Version, MethodNoAuthenticationRequired},
				{Version, ReplyConnectionRefused, 0, AtypIPv4, 0, 0, 0, 0, 0, 0},
			},
			checkClientErr: func(t *testing.T, err error) {
				var e ReplyError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != ReplyConnectionRefused {
					t.Errorf("e.Reply = %d, want %d", e, ReplyConnectionRefused)
				}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			testStreamClientError(t, c.clientAuthMsg, c.expectedRequests, c.serverMsgs, c.checkClientErr)
		})
	}
}

func testStreamClientError(
	t *testing.T,
	clientAuthMsg []byte,
	expectedRequests [][]byte,
	serverMsgs [][]byte,
	checkClientErr func(*testing.T, error),
) {
	pl, pr := netio.NewPipe()

	clientTargetAddr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 53))

	var (
		wg         sync.WaitGroup
		cerr, serr error
	)

	wg.Add(3)

	go func() {
		defer func() {
			_ = pl.Close()
			wg.Done()
		}()

		if len(clientAuthMsg) == 0 {
			cerr = ClientConnect(pl, clientTargetAddr)
		} else {
			cerr = ClientConnectUsernamePassword(pl, clientAuthMsg, clientTargetAddr)
		}
	}()

	go func() {
		defer func() {
			_ = pr.CloseRead()
			wg.Done()
		}()

		b := make([]byte, 1024)

		for _, expectedReq := range expectedRequests {
			n, err := pr.Read(b)
			if err != nil {
				t.Errorf("Failed to read request: %v", err)
				return
			}

			req := b[:n]
			if !bytes.Equal(req, expectedReq) {
				t.Errorf("req = %v, want %v", req, expectedReq)
			}
		}
	}()

	go func() {
		defer func() {
			_ = pr.CloseWrite()
			wg.Done()
		}()

		for _, msg := range serverMsgs {
			if _, serr = pr.Write(msg); serr != nil {
				return
			}
		}
	}()

	wg.Wait()

	if serr != nil {
		t.Fatalf("serr = %v", serr)
	}
	checkClientErr(t, cerr)
}

func TestStreamServerError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	for _, c := range []struct {
		name                     string
		clientMsgs               [][]byte
		expectedResponses        [][]byte
		serverUserInfoByUsername map[string]UserInfo
		serverEnableTCP          bool
		serverEnableUDP          bool
		checkServerErr           func(*testing.T, error)
	}{
		{
			name: "UnsupportedVersion/4",
			clientMsgs: [][]byte{
				{4, 1, MethodNoAuthenticationRequired},
			},
			expectedResponses:        nil,
			serverUserInfoByUsername: nil,
			serverEnableTCP:          true,
			serverEnableUDP:          false,
			checkServerErr: func(t *testing.T, err error) {
				var e UnsupportedVersionError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != 4 {
					t.Errorf("e = %d, want 4", e)
				}
			},
		},
		{
			name: "ZeroNMETHODS",
			clientMsgs: [][]byte{
				{Version, 0, MethodNoAuthenticationRequired},
			},
			expectedResponses:        nil,
			serverUserInfoByUsername: nil,
			serverEnableTCP:          true,
			serverEnableUDP:          false,
			checkServerErr: func(t *testing.T, err error) {
				if err != errZeroNMETHODS {
					t.Errorf("err = %v, want %v", err, errZeroNMETHODS)
				}
			},
		},
		{
			name: "NoAcceptableAuthMethod/RejectClientNoAuth",
			clientMsgs: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
			},
			expectedResponses: [][]byte{
				{Version, MethodNoAcceptable},
			},
			serverUserInfoByUsername: map[string]UserInfo{
				"hello": {
					Username: "hello",
					Password: "world",
				},
			},
			serverEnableTCP: true,
			serverEnableUDP: false,
			checkServerErr: func(t *testing.T, err error) {
				if err != ErrNoAcceptableAuthMethod {
					t.Errorf("err = %v, want %v", err, ErrNoAcceptableAuthMethod)
				}
			},
		},
		{
			name: "NoAcceptableAuthMethod/RejectClientUsernamePassword",
			clientMsgs: [][]byte{
				{Version, 1, MethodUsernamePassword},
			},
			expectedResponses: [][]byte{
				{Version, MethodNoAcceptable},
			},
			serverUserInfoByUsername: nil,
			serverEnableTCP:          true,
			serverEnableUDP:          false,
			checkServerErr: func(t *testing.T, err error) {
				if err != ErrNoAcceptableAuthMethod {
					t.Errorf("err = %v, want %v", err, ErrNoAcceptableAuthMethod)
				}
			},
		},
		{
			name: "UnsupportedUsernamePasswordAuthVersion",
			clientMsgs: [][]byte{
				{Version, 2, MethodNoAuthenticationRequired, MethodUsernamePassword},
				{5, 5, 'h', 'e'},
			},
			expectedResponses: [][]byte{
				{Version, MethodUsernamePassword},
			},
			serverUserInfoByUsername: map[string]UserInfo{
				"hello": {
					Username: "hello",
					Password: "world",
				},
			},
			serverEnableTCP: true,
			serverEnableUDP: false,
			checkServerErr: func(t *testing.T, err error) {
				var e UnsupportedUsernamePasswordAuthVersionError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != 5 {
					t.Errorf("e = %d, want 5", e)
				}
			},
		},
		{
			name: "ZeroULEN",
			clientMsgs: [][]byte{
				{Version, 1, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 0, 0, 0},
			},
			expectedResponses: [][]byte{
				{Version, MethodUsernamePassword},
			},
			serverUserInfoByUsername: map[string]UserInfo{
				"hello": {
					Username: "hello",
					Password: "world",
				},
			},
			serverEnableTCP: true,
			serverEnableUDP: false,
			checkServerErr: func(t *testing.T, err error) {
				if err != errZeroULEN {
					t.Errorf("err = %v, want %v", err, errZeroULEN)
				}
			},
		},
		{
			name: "ZeroPLEN",
			clientMsgs: [][]byte{
				{Version, 1, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 0},
			},
			expectedResponses: [][]byte{
				{Version, MethodUsernamePassword},
			},
			serverUserInfoByUsername: map[string]UserInfo{
				"hello": {
					Username: "hello",
					Password: "world",
				},
			},
			serverEnableTCP: true,
			serverEnableUDP: false,
			checkServerErr: func(t *testing.T, err error) {
				if err != errZeroPLEN {
					t.Errorf("err = %v, want %v", err, errZeroPLEN)
				}
			},
		},
		{
			name: "IncorrectUsername",
			clientMsgs: [][]byte{
				{Version, 1, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			},
			expectedResponses: [][]byte{
				{Version, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 1},
			},
			serverUserInfoByUsername: map[string]UserInfo{
				"he11o": {
					Username: "he11o",
					Password: "world",
				},
			},
			serverEnableTCP: true,
			serverEnableUDP: false,
			checkServerErr: func(t *testing.T, err error) {
				if err != ErrIncorrectUsernamePassword {
					t.Errorf("err = %v, want %v", err, ErrIncorrectUsernamePassword)
				}
			},
		},
		{
			name: "IncorrectPassword",
			clientMsgs: [][]byte{
				{Version, 1, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			},
			expectedResponses: [][]byte{
				{Version, MethodUsernamePassword},
				{UsernamePasswordAuthVersion, 1},
			},
			serverUserInfoByUsername: map[string]UserInfo{
				"hello": {
					Username: "hello",
					Password: "wor1d",
				},
			},
			serverEnableTCP: true,
			serverEnableUDP: false,
			checkServerErr: func(t *testing.T, err error) {
				if err != ErrIncorrectUsernamePassword {
					t.Errorf("err = %v, want %v", err, ErrIncorrectUsernamePassword)
				}
			},
		},
		{
			name: "UnsupportedCommand/Connect",
			clientMsgs: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
				{Version, CmdConnect, 0, AtypIPv4, 127, 0, 0, 1, 0, 80},
			},
			expectedResponses: [][]byte{
				{Version, MethodNoAuthenticationRequired},
				{Version, ReplyCommandNotSupported, 0, AtypIPv4, 0, 0, 0, 0, 0, 0},
			},
			serverUserInfoByUsername: nil,
			serverEnableTCP:          false,
			serverEnableUDP:          true,
			checkServerErr: func(t *testing.T, err error) {
				var e UnsupportedCommandError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != CmdConnect {
					t.Errorf("e = %d, want %d", e, CmdConnect)
				}
			},
		},
		{
			name: "UnsupportedCommand/Bind",
			clientMsgs: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
				{Version, CmdBind, 0, AtypIPv4, 0, 0, 0, 0, 0, 0},
			},
			expectedResponses: [][]byte{
				{Version, MethodNoAuthenticationRequired},
				{Version, ReplyCommandNotSupported, 0, AtypIPv4, 0, 0, 0, 0, 0, 0},
			},
			serverUserInfoByUsername: nil,
			serverEnableTCP:          true,
			serverEnableUDP:          true,
			checkServerErr: func(t *testing.T, err error) {
				var e UnsupportedCommandError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != CmdBind {
					t.Errorf("e = %d, want %d", e, CmdBind)
				}
			},
		},
		{
			name: "UnsupportedCommand/UDPAssociate",
			clientMsgs: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
				{Version, CmdUDPAssociate, 0, AtypIPv4, 0, 0, 0, 0, 0, 0},
			},
			expectedResponses: [][]byte{
				{Version, MethodNoAuthenticationRequired},
				{Version, ReplyCommandNotSupported, 0, AtypIPv4, 0, 0, 0, 0, 0, 0},
			},
			serverUserInfoByUsername: nil,
			serverEnableTCP:          true,
			serverEnableUDP:          false,
			checkServerErr: func(t *testing.T, err error) {
				var e UnsupportedCommandError
				if !errors.As(err, &e) {
					t.Fatalf("err = %v, want %T", err, e)
				}
				if e != CmdUDPAssociate {
					t.Errorf("e = %d, want %d", e, CmdUDPAssociate)
				}
			},
		},
		{
			name: "LocalAddrNotTCPAddr",
			clientMsgs: [][]byte{
				{Version, 1, MethodNoAuthenticationRequired},
				{Version, CmdUDPAssociate, 0, AtypIPv4, 0, 0, 0, 0, 0, 0},
			},
			expectedResponses: [][]byte{
				{Version, MethodNoAuthenticationRequired},
			},
			serverUserInfoByUsername: nil,
			serverEnableTCP:          false,
			serverEnableUDP:          true,
			checkServerErr: func(t *testing.T, err error) {
				if !errors.Is(err, errLocalAddrNotTCPAddr) {
					t.Errorf("err = %v, want %v", err, errLocalAddrNotTCPAddr)
				}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			testStreamServerError(t, logger, c.clientMsgs, c.expectedResponses, c.serverUserInfoByUsername, c.serverEnableTCP, c.serverEnableUDP, c.checkServerErr)
		})
	}
}

func testStreamServerError(
	t *testing.T,
	logger *zap.Logger,
	clientMsgs [][]byte,
	expectedResponses [][]byte,
	serverUserInfoByUsername map[string]UserInfo,
	serverEnableTCP, serverEnableUDP bool,
	checkServerErr func(*testing.T, error),
) {
	pl, pr := netio.NewPipe()

	var (
		wg         sync.WaitGroup
		cerr, serr error
	)

	wg.Add(3)

	go func() {
		defer func() {
			_ = pl.CloseWrite()
			wg.Done()
		}()

		for _, msg := range clientMsgs {
			if _, cerr = pl.Write(msg); cerr != nil {
				return
			}
		}
	}()

	go func() {
		defer func() {
			_ = pl.CloseRead()
			wg.Done()
		}()

		b := make([]byte, 1024)

		for _, expectedResp := range expectedResponses {
			n, err := pl.Read(b)
			if err != nil {
				t.Errorf("Failed to read response: %v", err)
				return
			}

			resp := b[:n]
			if !bytes.Equal(resp, expectedResp) {
				t.Errorf("resp = %v, want %v", resp, expectedResp)
			}
		}
	}()

	go func() {
		defer func() {
			_ = pr.Close()
			wg.Done()
		}()

		if serverUserInfoByUsername == nil {
			_, _, serr = ServerAccept(pr, logger, serverEnableTCP, serverEnableUDP)
		} else {
			_, _, _, serr = ServerAcceptUsernamePassword(pr, logger, serverUserInfoByUsername, serverEnableTCP, serverEnableUDP)
		}
	}()

	wg.Wait()

	if cerr != nil {
		t.Fatalf("cerr = %v", cerr)
	}
	checkServerErr(t, serr)
}

func TestStreamServerConfigValidation(t *testing.T) {
	b := make([]byte, 256)
	rand.Read(b)
	longString := string(b)

	for _, c := range []struct {
		name        string
		config      StreamServerConfig
		expectedErr error
	}{
		{
			name: "NoUsers",
			config: StreamServerConfig{
				EnableUserPassAuth: true,
				EnableTCP:          true,
				EnableUDP:          true,
			},
			expectedErr: nil,
		},
		{
			name: "ValidUsers",
			config: StreamServerConfig{
				Users: []UserInfo{
					{
						Username: "hello",
						Password: "world",
					},
				},
				EnableUserPassAuth: true,
				EnableTCP:          true,
				EnableUDP:          true,
			},
			expectedErr: nil,
		},
		{
			name: "EmptyUsername",
			config: StreamServerConfig{
				Users: []UserInfo{
					{
						Username: "",
						Password: "world",
					},
				},
				EnableUserPassAuth: true,
				EnableTCP:          true,
				EnableUDP:          true,
			},
			expectedErr: ErrUsernameLengthOutOfRange,
		},
		{
			name: "LongUsername",
			config: StreamServerConfig{
				Users: []UserInfo{
					{
						Username: longString,
						Password: "world",
					},
				},
				EnableUserPassAuth: true,
				EnableTCP:          true,
				EnableUDP:          true,
			},
			expectedErr: ErrUsernameLengthOutOfRange,
		},
		{
			name: "EmptyPassword",
			config: StreamServerConfig{
				Users: []UserInfo{
					{
						Username: "hello",
						Password: "",
					},
				},
				EnableUserPassAuth: true,
				EnableTCP:          true,
				EnableUDP:          true,
			},
			expectedErr: ErrPasswordLengthOutOfRange,
		},
		{
			name: "LongPassword",
			config: StreamServerConfig{
				Users: []UserInfo{
					{
						Username: "hello",
						Password: longString,
					},
				},
				EnableUserPassAuth: true,
				EnableTCP:          true,
				EnableUDP:          true,
			},
			expectedErr: ErrPasswordLengthOutOfRange,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.config.NewStreamServer(); !errors.Is(err, c.expectedErr) {
				t.Errorf("err = %v, want %v", err, c.expectedErr)
			}
		})
	}
}

func TestStreamClientServer(t *testing.T) {
	b := make([]byte, 255+255)
	rand.Read(b)
	userInfo255 := UserInfo{
		Username: string(b[:255]),
		Password: string(b[255:]),
	}

	for _, authCase := range []struct {
		name             string
		clientAuthMsg    []byte
		serverUsers      []UserInfo
		expectedUsername string
	}{
		{
			name:             "NoAuth",
			clientAuthMsg:    nil,
			serverUsers:      nil,
			expectedUsername: "",
		},
		{
			name:          "UserPassAuth/1",
			clientAuthMsg: []byte{UsernamePasswordAuthVersion, 1, 'h', 1, 'w'},
			serverUsers: []UserInfo{
				{
					Username: "h",
					Password: "w",
				},
			},
			expectedUsername: "h",
		},
		{
			name:          "UserPassAuth/5",
			clientAuthMsg: []byte{UsernamePasswordAuthVersion, 5, 'h', 'e', 'l', 'l', 'o', 5, 'w', 'o', 'r', 'l', 'd'},
			serverUsers: []UserInfo{
				{
					Username: "hello",
					Password: "world",
				},
			},
			expectedUsername: "hello",
		},
		{
			name:          "UserPassAuth/255",
			clientAuthMsg: userInfo255.AppendAuthMsg(nil),
			serverUsers: []UserInfo{
				userInfo255,
			},
			expectedUsername: userInfo255.Username,
		},
	} {
		t.Run(authCase.name, func(t *testing.T) {
			for _, udpCase := range []struct {
				name      string
				enableUDP bool
			}{
				{"EnableUDP", true},
				{"DisableUDP", false},
			} {
				t.Run(udpCase.name, func(t *testing.T) {
					addr := conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Loopback(), 1080))

					newClient := func(psc *netiotest.PipeStreamClient) netio.StreamClient {
						clientConfig := StreamClientConfig{
							InnerClient: psc,
							Addr:        addr,
							AuthMsg:     authCase.clientAuthMsg,
						}
						return clientConfig.NewStreamClient()
					}

					serverConfig := StreamServerConfig{
						Users:              authCase.serverUsers,
						EnableUserPassAuth: len(authCase.clientAuthMsg) > 0,
						EnableTCP:          true,
						EnableUDP:          udpCase.enableUDP,
					}
					server, err := serverConfig.NewStreamServer()
					if err != nil {
						t.Fatalf("Failed to create server: %v", err)
					}

					t.Run("Proceed", func(t *testing.T) {
						netiotest.TestPreambleStreamClientServerProceed(
							t,
							newClient,
							server,
							addr,
							authCase.expectedUsername,
						)
					})

					t.Run("Abort", func(t *testing.T) {
						netiotest.TestStreamClientServerAbort(
							t,
							newClient,
							server,
							func(t *testing.T, dialResult conn.DialResult, err error) {
								reply := ReplyFromDialResultCode(dialResult.Code)
								if reply == ReplySucceeded {
									if err != nil && err != io.ErrClosedPipe {
										t.Errorf("err = %v, want nil or io.ErrClosedPipe", err)
									}
									return
								}

								var e ReplyError
								if !errors.As(err, &e) {
									t.Errorf("err = %v, want %T", err, e)
									return
								}
								if byte(e) != reply {
									t.Errorf("e = %d, want %d", e, reply)
								}
							},
						)
					})
				})
			}
		})
	}
}
