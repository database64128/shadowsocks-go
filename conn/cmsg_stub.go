//go:build !darwin && !freebsd && !linux && !openbsd && !windows

package conn

const socketControlMessageBufferSize = 0

func parseSocketControlMessage(_ []byte) (SocketControlMessage, error) {
	return SocketControlMessage{}, nil
}

func (SocketControlMessage) appendTo(b []byte) []byte {
	return b
}
