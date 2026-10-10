package service

import (
	"errors"

	"github.com/database64128/shadowsocks-go/conn"
)

// SocketBufferSizeConfig configures the socket send and receive buffer sizes.
type SocketBufferSizeConfig struct {
	// SendBufferSize optionally specifies the socket send buffer size.
	//
	// For UDP sockets,
	// if zero, [conn.DefaultUDPSocketBufferSize] is used;
	// if negative, the send buffer size is never modified.
	//
	// For other types of sockets,
	// if zero, the send buffer size is never modified;
	// negative values are not allowed.
	//
	// Available on POSIX systems.
	SendBufferSize int `json:"sendBufferSize,omitzero"`

	// ReceiveBufferSize optionally specifies the socket receive buffer size.
	//
	// For UDP sockets,
	// if zero, [conn.DefaultUDPSocketBufferSize] is used;
	// if negative, the receive buffer size is never modified.
	//
	// For other types of sockets,
	// if zero, the receive buffer size is never modified;
	// negative values are not allowed.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int `json:"receiveBufferSize,omitzero"`
}

func (cfg SocketBufferSizeConfig) genericSocketBufferSizes() (snd, rcv int, err error) {
	if cfg.SendBufferSize < 0 {
		return 0, 0, errors.New("negative send buffer size")
	}
	if cfg.ReceiveBufferSize < 0 {
		return 0, 0, errors.New("negative receive buffer size")
	}
	return cfg.SendBufferSize, cfg.ReceiveBufferSize, nil
}

func (cfg SocketBufferSizeConfig) udpSocketSendBufferSize() int {
	return udpSocketBufferSize(cfg.SendBufferSize)
}

func (cfg SocketBufferSizeConfig) udpSocketReceiveBufferSize() int {
	return udpSocketBufferSize(cfg.ReceiveBufferSize)
}

func udpSocketBufferSize(opt int) int {
	switch {
	case opt == 0:
		return conn.DefaultUDPSocketBufferSize
	case opt < 0:
		return 0
	default:
		return opt
	}
}
