package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/socks5"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go"
	"go.uber.org/zap"
)

// TCPRelay is a relay service for TCP traffic.
//
// When started, the relay service accepts incoming TCP connections on the server,
// and dispatches them to a client selected by the router.
//
// TCPRelay implements the Service interface.
type TCPRelay struct {
	serverName     string
	listenAddress  string
	listenerFwmark int
	listenerTFO    bool
	server         zerocopy.TCPServer
	connCloser     zerocopy.TCPConnCloser
	router         *router.Router
	listener       *net.TCPListener
	logger         *zap.Logger
}

// String implements the Service String method.
func (s *TCPRelay) String() string {
	return fmt.Sprintf("TCP relay service for %s", s.serverName)
}

// Start implements the Service Start method.
func (s *TCPRelay) Start() error {
	lc := tfo.ListenConfig{
		DisableTFO: !s.listenerTFO,
	}
	l, err := lc.Listen(context.Background(), "tcp", s.listenAddress)
	if err != nil {
		return err
	}
	s.listener = l.(*net.TCPListener)

	go func() {
		defer s.listener.Close()

		for {
			clientConn, err := s.listener.AcceptTCP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Warn("Failed to accept TCP connection",
					zap.String("server", s.serverName),
					zap.String("listenAddress", s.listenAddress),
					zap.Error(err),
				)
				continue
			}

			go s.handleConn(clientConn)
		}
	}()

	s.logger.Info("Started TCP relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.Int("listenerFwmark", s.listenerFwmark),
		zap.Bool("listenerTFO", s.listenerTFO),
	)

	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(clientConn *net.TCPConn) {
	defer clientConn.Close()

	// Get client address.
	clientAddress := clientConn.RemoteAddr().String()
	clientAddr, err := socks5.ParseAddr(clientAddress)
	if err != nil {
		s.logger.Error("Failed to parse client address",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Error(err),
		)
		return
	}
	clientAddrPort, err := clientAddr.AddrPort(true)
	if err != nil {
		s.logger.Error("Failed to convert socks5.Addr to netip.AddrPort",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Error(err),
		)
		return
	}

	// Handshake.
	rw, targetAddr, payload, err := s.server.Accept(clientConn)
	if err != nil {
		if err == socks5.ErrUDPAssociateHold {
			s.logger.Debug("Keeping TCP connection open for SOCKS5 UDP association",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.String("clientAddress", clientAddress),
			)

			b := make([]byte, 1)
			_, err = clientConn.Read(b)
			if err == nil || err == io.EOF {
				return
			}
		}

		s.logger.Warn("Failed to complete handshake with client",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Error(err),
		)

		s.connCloser.Do(clientConn, s.serverName, s.listenAddress, "", s.logger)
		return
	}

	// Route.
	c, err := s.router.GetTCPClient(s.serverName, clientAddrPort, targetAddr)
	if err != nil {
		s.logger.Warn("Failed to get TCP client for client connection",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Stringer("targetAddress", targetAddr),
			zap.Error(err),
		)
		return
	}

	// Create remote connection.
	remoteConn, err := c.Dial(targetAddr, payload)
	if err != nil {
		s.logger.Warn("Failed to create remote connection",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Stringer("targetAddress", targetAddr),
			zap.Int("payloadLength", len(payload)),
			zap.Error(err),
		)
		return
	}
	defer remoteConn.Close()

	// Two-way relay.
	nl2r, nr2l, err := zerocopy.TwoWayRelay(rw, remoteConn)
	if err != nil {
		s.logger.Warn("Two-way relay failed",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Stringer("targetAddress", targetAddr),
			zap.Int64("nl2r", nl2r),
			zap.Int64("nr2l", nr2l),
			zap.Error(err),
		)
		return
	}

	s.logger.Info("Two-way relay completed",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
		zap.String("clientAddress", clientAddress),
		zap.Stringer("targetAddress", targetAddr),
		zap.Int64("nl2r", nl2r),
		zap.Int64("nr2l", nr2l),
	)
}

// Stop implements the Service Stop method.
func (s *TCPRelay) Stop() error {
	if s.listener != nil {
		s.listener.Close()
	}
	return nil
}
