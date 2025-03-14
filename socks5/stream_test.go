package socks5

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/zerocopy"
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
				{Version, ReplyConnectionRefused, 0, AtypIPv4, 0},
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
			name: "AcceptRequiresTCPConn",
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
				if err != zerocopy.ErrAcceptRequiresTCPConn {
					t.Errorf("err = %v, want %v", err, zerocopy.ErrAcceptRequiresTCPConn)
				}
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			testStreamServerError(t, c.clientMsgs, c.expectedResponses, c.serverUserInfoByUsername, c.serverEnableTCP, c.serverEnableUDP, c.checkServerErr)
		})
	}
}

func testStreamServerError(
	t *testing.T,
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
			_, serr = ServerAccept(pr, serverEnableTCP, serverEnableUDP)
		} else {
			_, _, serr = ServerAcceptUsernamePassword(pr, serverUserInfoByUsername, serverEnableTCP, serverEnableUDP)
		}
	}()

	wg.Wait()

	if cerr != nil {
		t.Fatalf("cerr = %v", cerr)
	}
	checkServerErr(t, serr)
}
