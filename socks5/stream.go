package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/database64128/shadowsocks-go/conn"
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
func replyWithStatus(w io.Writer, b []byte, status byte) error {
	const replyLen = 3 + IPv4AddrLen
	reply := b[:replyLen]
	reply[0] = Version
	reply[1] = status
	reply[2] = 0
	*(*[IPv4AddrLen]byte)(reply[3:]) = IPv4UnspecifiedAddr
	_, err := w.Write(reply)
	return err
}

// ClientRequest writes a request to targetAddr and returns the bound address in reply.
func ClientRequest(rw io.ReadWriter, command byte, targetAddr conn.Addr) (addr conn.Addr, err error) {
	b := make([]byte, 3+MaxAddrLen)
	b[0] = Version
	b[1] = 1
	b[2] = MethodNoAuthenticationRequired

	// Write VER NMETHDOS METHODS.
	_, err = rw.Write(b[:3])
	if err != nil {
		return
	}

	// Read version selection message.
	_, err = io.ReadFull(rw, b[:2])
	if err != nil {
		return
	}

	// Check VER.
	if b[0] != Version {
		err = fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
		return
	}

	// Check METHOD.
	if b[1] != MethodNoAuthenticationRequired {
		err = fmt.Errorf("%w: %d", ErrUnsupportedAuthenticationMethod, b[1])
		return
	}

	// Write VER, CMD, RSV, SOCKS address.
	b[1] = command
	n := WriteAddrFromConnAddr(b[3:], targetAddr)
	_, err = rw.Write(b[:3+n])
	if err != nil {
		return
	}

	// Read VER, REP, RSV.
	_, err = io.ReadFull(rw, b[:3])
	if err != nil {
		return
	}

	// Check VER.
	if b[0] != Version {
		err = fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
		return
	}

	// Check REP.
	if b[1] != Succeeded {
		err = fmt.Errorf("SOCKS error: %d", b[1])
		return
	}

	// Read SOCKS address.
	sa, err := AppendFromReader(b[3:3], rw)
	if err != nil {
		return
	}
	addr, _, err = ConnAddrFromSlice(sa)
	return
}

// ClientConnect writes a CONNECT request to targetAddr.
func ClientConnect(rw io.ReadWriter, targetAddr conn.Addr) error {
	_, err := ClientRequest(rw, CmdConnect, targetAddr)
	return err
}

// ClientUDPAssociate writes a UDP ASSOCIATE request to targetAddr.
func ClientUDPAssociate(rw io.ReadWriter, targetAddr conn.Addr) (conn.Addr, error) {
	return ClientRequest(rw, CmdUDPAssociate, targetAddr)
}

// ServerAccept processes an incoming request from rw.
//
// enableTCP enables the CONNECT command.
// enableUDP enables the UDP ASSOCIATE command.
//
// When UDP is enabled, rw must be a [*net.TCPConn].
func ServerAccept(rw io.ReadWriter, enableTCP, enableUDP bool) (addr conn.Addr, err error) {
	b := make([]byte, 3+MaxAddrLen)

	// Read VER, NMETHODS.
	_, err = io.ReadFull(rw, b[:2])
	if err != nil {
		return
	}

	// Check VER.
	if b[0] != Version {
		err = fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
		return
	}

	// Check NMETHODS.
	if b[1] == 0 {
		err = fmt.Errorf("NMETHODS is %d", b[1])
		return
	}

	// Read METHODS.
	_, err = io.ReadFull(rw, b[:b[1]])
	if err != nil {
		return
	}

	// Check METHODS.
	if bytes.IndexByte(b[:b[1]], MethodNoAuthenticationRequired) == -1 {
		b[0] = Version
		b[1] = MethodNoAcceptable
		_, err = rw.Write(b[:2])
		if err == nil {
			err = ErrUnsupportedAuthenticationMethod
		}
		return
	}

	// Write method selection message.
	//
	// 	+-----+--------+
	// 	| VER | METHOD |
	// 	+-----+--------+
	// 	|  1  |   1    |
	// 	+-----+--------+
	b[0] = Version
	b[1] = MethodNoAuthenticationRequired
	_, err = rw.Write(b[:2])
	if err != nil {
		return
	}

	// Read VER, CMD, RSV.
	_, err = io.ReadFull(rw, b[:3])
	if err != nil {
		return
	}

	// Check VER.
	if b[0] != Version {
		err = fmt.Errorf("%w: %d", ErrUnsupportedSocksVersion, b[0])
		return
	}

	// Read SOCKS address.
	sa, err := AppendFromReader(b[3:3], rw)
	if err != nil {
		return
	}
	addr, _, err = ConnAddrFromSlice(sa)
	if err != nil {
		return
	}

	switch {
	case b[1] == CmdConnect && enableTCP:
		err = replyWithStatus(rw, b, Succeeded)

	case b[1] == CmdUDPAssociate && enableUDP:
		// Use the connection's local address as the returned UDP bound address.
		localAddrPort := rw.(*net.TCPConn).LocalAddr().(*net.TCPAddr).AddrPort()

		// Construct reply.
		b[1] = Succeeded
		reply := AppendAddrFromAddrPort(b[:3], localAddrPort)

		// Write reply.
		_, err = rw.Write(reply)
		if err != nil {
			return
		}

		// Hold the connection open.
		_, err = rw.Read(b[:1])
		if err == nil || err == io.EOF {
			err = ErrUDPAssociateDone
		}

	default:
		err = replyWithStatus(rw, b, ErrCommandNotSupported)
		if err == nil {
			err = fmt.Errorf("%w: %d", ErrUnsupportedCommand, b[1])
		}
	}

	return
}
