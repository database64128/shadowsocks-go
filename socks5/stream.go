package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/database64128/tfo-go"
)

// SOCKS version 5.
const Version = 5

// SOCKS5 authentication methods as defined in RFC 1928 section 3.
const (
	MethodNoAuthenticationRequired = 0
	MethodGSSAPI                   = 1
	MethodUsernamePassword         = 2
	MethodNoAcceptable             = 0xFF
)

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

// SOCKS errors as defined in RFC 1928 section 6.
const (
	Succeeded               = 0
	ErrGeneralFailure       = 1
	ErrConnectionNotAllowed = 2
	ErrNetworkUnreachable   = 3
	ErrHostUnreachable      = 4
	ErrConnectionRefused    = 5
	ErrTTLExpired           = 6
	ErrCommandNotSupported  = 7
	ErrAddressNotSupported  = 8
)

var (
	ErrUnsupportedSocksVersion         = errors.New("unsupported SOCKS version")
	ErrUnsupportedAuthenticationMethod = errors.New("unsupported authentication method")
	ErrUnsupportedCommand              = errors.New("unsupported command")
	ErrUDPAssociateDone                = errors.New("UDP ASSOCIATE done")
)

// replyWithStatus writes a reply to w with the REP field set to status.
func replyWithStatus(w io.Writer, status byte) error {
	_, err := w.Write([]byte{Version, status, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// ClientRequest writes a request to targetAddr and returns the bound address in reply.
func ClientRequest(rw io.ReadWriter, command byte, targetAddr Addr) (Addr, error) {
	b := make([]byte, 3+MaxAddrLen)

	// Write VER NMETHDOS METHODS.
	_, err := rw.Write([]byte{Version, 1, MethodNoAuthenticationRequired})
	if err != nil {
		return nil, err
	}

	// Read version selection message.
	_, err = io.ReadFull(rw, b[:2])
	if err != nil {
		return nil, err
	}

	// Check VER.
	if b[0] != Version {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
	}

	// Check METHOD.
	if b[1] != MethodNoAuthenticationRequired {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAuthenticationMethod, b[1])
	}

	// Write VER, CMD, RSV, SOCKS address.
	b[1] = command
	n := copy(b[3:], targetAddr)
	_, err = rw.Write(b[:3+n])
	if err != nil {
		return nil, err
	}

	// Read VER, REP, RSV.
	_, err = io.ReadFull(rw, b[:3])
	if err != nil {
		return nil, err
	}

	// Check VER.
	if b[0] != Version {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
	}

	// Check REP.
	if b[1] != Succeeded {
		return nil, fmt.Errorf("SOCKS error: %d", b[1])
	}

	// Read SOCKS address.
	return AppendFromReader(b[3:3], rw)
}

// ClientConnect writes a CONNECT request to targetAddr.
func ClientConnect(rw io.ReadWriter, targetAddr Addr) error {
	_, err := ClientRequest(rw, CmdConnect, targetAddr)
	return err
}

// ClientUDPAssociate writes a UDP ASSOCIATE request to targetAddr.
func ClientUDPAssociate(rw io.ReadWriter, targetAddr Addr) (Addr, error) {
	return ClientRequest(rw, CmdUDPAssociate, targetAddr)
}

// ServerAccept processes an incoming request from r.
// enableTCP enables the CONNECT command.
// enableUDP enables the UDP ASSOCIATE command.
// conn must be provided when UDP is enabled.
func ServerAccept(rw io.ReadWriter, enableTCP, enableUDP bool, conn tfo.Conn) (Addr, error) {
	b := make([]byte, 3+MaxAddrLen)

	// Read VER, NMETHODS.
	_, err := io.ReadFull(rw, b[:2])
	if err != nil {
		return nil, err
	}

	// Check VER.
	if b[0] != Version {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
	}

	// Check NMETHODS.
	if b[1] == 0 {
		return nil, fmt.Errorf("NMETHODS is %d", b[1])
	}

	// Read METHODS.
	_, err = io.ReadFull(rw, b[:b[1]])
	if err != nil {
		return nil, err
	}

	// Check METHODS.
	if bytes.IndexByte(b[:b[1]], MethodNoAuthenticationRequired) == -1 {
		_, err = rw.Write([]byte{Version, MethodNoAcceptable})
		if err == nil {
			err = ErrUnsupportedAuthenticationMethod
		}
		return nil, err
	}

	// Write method selection message.
	//
	// 	+-----+--------+
	// 	| VER | METHOD |
	// 	+-----+--------+
	// 	|  1  |   1    |
	// 	+-----+--------+
	_, err = rw.Write([]byte{Version, MethodNoAuthenticationRequired})
	if err != nil {
		return nil, err
	}

	// Read VER, CMD, RSV.
	_, err = io.ReadFull(rw, b[:3])
	if err != nil {
		return nil, err
	}

	// Check VER.
	if b[0] != Version {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
	}

	// Read SOCKS address.
	addr, err := AppendFromReader(b[3:3], rw)
	if err != nil {
		return nil, err
	}

	switch {
	case b[1] == CmdConnect && enableTCP:
		err = replyWithStatus(rw, Succeeded)
		return addr, err

	case b[1] == CmdUDPAssociate && enableUDP:
		// Use the connection's local address as the returned UDP bound address.
		localAddr := conn.LocalAddr()
		var localAddrPort netip.AddrPort

		// net.Addr -> netip.AddrPort
		if tcpAddr, ok := localAddr.(*net.TCPAddr); ok {
			localAddrPort = tcpAddr.AddrPort()
		} else {
			localAddrPort, err = netip.ParseAddrPort(localAddr.String())
			if err != nil {
				return nil, err
			}
		}

		// Construct reply.
		b[1] = Succeeded
		reply := AppendFromAddrPort(b[:3], localAddrPort)

		// Write reply.
		_, err = rw.Write(reply)
		if err != nil {
			return nil, err
		}

		// Hold the connection open.
		_, err = rw.Read(b[:1])
		if err == nil || err == io.EOF {
			err = ErrUDPAssociateDone
		}
		return nil, err

	default:
		err = replyWithStatus(rw, ErrCommandNotSupported)
		if err == nil {
			err = fmt.Errorf("%w: %d", ErrUnsupportedCommand, b[1])
		}
		return nil, err
	}
}
