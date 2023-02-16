package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/database64128/tfo-go/v2"
	"go.uber.org/zap"
)

const (
	initialPayloadWaitBufferSize = 1280
	initialPayloadWaitTimeout    = 250 * time.Millisecond
)

// TCPRelay is a relay service for TCP traffic.
//
// When started, the relay service accepts incoming TCP connections on the server,
// and dispatches them to a client selected by the router.
//
// TCPRelay implements the Service interface.
type TCPRelay struct {
	serverName            string
	listenAddress         string
	wg                    sync.WaitGroup
	listenConfig          tfo.ListenConfig
	waitForInitialPayload bool
	server                zerocopy.TCPServer
	connCloser            zerocopy.TCPConnCloser
	fallbackAddress       *conn.Addr
	collector             stats.Collector
	router                *router.Router
	logger                *zap.Logger
	listener              *net.TCPListener
}

func NewTCPRelay(
	serverName, listenAddress string, listenerFwmark int, listenerTFO, listenerTransparent, waitForInitialPayload bool,
	server zerocopy.TCPServer,
	connCloser zerocopy.TCPConnCloser,
	fallbackAddress *conn.Addr,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) *TCPRelay {
	return &TCPRelay{
		serverName:            serverName,
		listenAddress:         listenAddress,
		listenConfig:          conn.NewListenConfig(listenerTFO, listenerTransparent, listenerFwmark),
		waitForInitialPayload: waitForInitialPayload,
		server:                server,
		connCloser:            connCloser,
		fallbackAddress:       fallbackAddress,
		collector:             collector,
		router:                router,
		logger:                logger,
	}
}

// String implements the Service String method.
func (s *TCPRelay) String() string {
	return fmt.Sprintf("TCP relay service for %s", s.serverName)
}

// Start implements the Service Start method.
func (s *TCPRelay) Start() error {
	l, err := s.listenConfig.Listen(context.Background(), "tcp", s.listenAddress)
	if err != nil {
		return err
	}
	s.listener = l.(*net.TCPListener)

	s.wg.Add(1)

	go func() {
		for {
			clientConn, err := s.listener.AcceptTCP()
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break
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

		s.wg.Done()
	}()

	s.logger.Info("Started TCP relay service",
		zap.String("server", s.serverName),
		zap.String("listenAddress", s.listenAddress),
	)

	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(clientConn *net.TCPConn) {
	defer clientConn.Close()

	// Get client address.
	clientAddrPort := clientConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	clientAddress := clientAddrPort.String()

	// Handshake.
	clientRW, targetAddr, payload, username, err := s.server.Accept(clientConn)
	if err != nil {
		if err == zerocopy.ErrAcceptDoneNoRelay {
			s.logger.Debug("The accepted connection has been handled without relaying",
				zap.String("server", s.serverName),
				zap.String("listenAddress", s.listenAddress),
				zap.String("clientAddress", clientAddress),
			)
			return
		}

		s.logger.Warn("Failed to complete handshake with client",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.Error(err),
		)

		if s.fallbackAddress == nil || len(payload) == 0 {
			s.connCloser(clientConn, s.serverName, s.listenAddress, clientAddress, s.logger)
			return
		}

		clientRW = direct.NewDirectStreamReadWriter(clientConn)
		targetAddr = *s.fallbackAddress
	}

	// Convert target address to string once for log messages.
	targetAddress := targetAddr.String()

	// Route.
	c, err := s.router.GetTCPClient(router.RequestInfo{
		Server:         s.serverName,
		Username:       username,
		SourceAddrPort: clientAddrPort,
		TargetAddr:     targetAddr,
	})
	if err != nil {
		s.logger.Warn("Failed to get TCP client for client connection",
			zap.String("server", s.serverName),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.String("targetAddress", targetAddress),
			zap.String("username", username),
			zap.Error(err),
		)
		return
	}

	// Get client info.
	clientInfo := c.Info()

	// Wait for initial payload if all of the following are true:
	// 1. not disabled
	// 2. server does not have native support
	// 3. client has native support
	if s.waitForInitialPayload && clientInfo.NativeInitialPayload {
		clientReaderInfo := clientRW.ReaderInfo()
		payloadBufSize := clientReaderInfo.MinPayloadBufferSizePerRead
		if payloadBufSize == 0 {
			payloadBufSize = initialPayloadWaitBufferSize
		}

		payload = make([]byte, clientReaderInfo.Headroom.Front+payloadBufSize+clientReaderInfo.Headroom.Rear)

		err = clientConn.SetReadDeadline(time.Now().Add(initialPayloadWaitTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline to initial payload wait timeout",
				zap.String("server", s.serverName),
				zap.String("client", clientInfo.Name),
				zap.String("listenAddress", s.listenAddress),
				zap.String("clientAddress", clientAddress),
				zap.String("targetAddress", targetAddress),
				zap.String("username", username),
				zap.Error(err),
			)
			return
		}

		payloadLength, err := clientRW.ReadZeroCopy(payload, clientReaderInfo.Headroom.Front, payloadBufSize)
		switch {
		case err == nil:
			payload = payload[clientReaderInfo.Headroom.Front : clientReaderInfo.Headroom.Front+payloadLength]
			s.logger.Debug("Got initial payload",
				zap.String("server", s.serverName),
				zap.String("client", clientInfo.Name),
				zap.String("listenAddress", s.listenAddress),
				zap.String("clientAddress", clientAddress),
				zap.String("targetAddress", targetAddress),
				zap.String("username", username),
				zap.Int("payloadLength", payloadLength),
			)

		case errors.Is(err, os.ErrDeadlineExceeded):
			s.logger.Debug("Initial payload wait timed out",
				zap.String("server", s.serverName),
				zap.String("client", clientInfo.Name),
				zap.String("listenAddress", s.listenAddress),
				zap.String("clientAddress", clientAddress),
				zap.String("targetAddress", targetAddress),
				zap.String("username", username),
			)

		default:
			s.logger.Warn("Failed to read initial payload",
				zap.String("server", s.serverName),
				zap.String("client", clientInfo.Name),
				zap.String("listenAddress", s.listenAddress),
				zap.String("clientAddress", clientAddress),
				zap.String("targetAddress", targetAddress),
				zap.String("username", username),
				zap.Error(err),
			)
			return
		}

		err = clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			s.logger.Warn("Failed to reset read deadline",
				zap.String("server", s.serverName),
				zap.String("client", clientInfo.Name),
				zap.String("listenAddress", s.listenAddress),
				zap.String("clientAddress", clientAddress),
				zap.String("targetAddress", targetAddress),
				zap.String("username", username),
				zap.Error(err),
			)
			return
		}
	}

	// Create remote connection.
	remoteConn, remoteRW, err := c.Dial(targetAddr, payload)
	if err != nil {
		s.logger.Warn("Failed to create remote connection",
			zap.String("server", s.serverName),
			zap.String("client", clientInfo.Name),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.String("targetAddress", targetAddress),
			zap.String("username", username),
			zap.Int("initialPayloadLength", len(payload)),
			zap.Error(err),
		)
		return
	}
	defer remoteConn.Close()

	s.logger.Info("Two-way relay started",
		zap.String("server", s.serverName),
		zap.String("client", clientInfo.Name),
		zap.String("listenAddress", s.listenAddress),
		zap.String("clientAddress", clientAddress),
		zap.String("targetAddress", targetAddress),
		zap.String("username", username),
		zap.Int("initialPayloadLength", len(payload)),
	)

	// Two-way relay.
	nl2r, nr2l, err := zerocopy.TwoWayRelay(clientRW, remoteRW)
	nl2r += int64(len(payload))
	s.collector.CollectTCPSession(username, uint64(nr2l), uint64(nl2r))
	if err != nil {
		s.logger.Warn("Two-way relay failed",
			zap.String("server", s.serverName),
			zap.String("client", clientInfo.Name),
			zap.String("listenAddress", s.listenAddress),
			zap.String("clientAddress", clientAddress),
			zap.String("targetAddress", targetAddress),
			zap.String("username", username),
			zap.Int64("nl2r", nl2r),
			zap.Int64("nr2l", nr2l),
			zap.Error(err),
		)
		return
	}

	s.logger.Info("Two-way relay completed",
		zap.String("server", s.serverName),
		zap.String("client", clientInfo.Name),
		zap.String("listenAddress", s.listenAddress),
		zap.String("clientAddress", clientAddress),
		zap.String("targetAddress", targetAddress),
		zap.String("username", username),
		zap.Int64("nl2r", nl2r),
		zap.Int64("nr2l", nr2l),
	)
}

// Stop implements the Service Stop method.
func (s *TCPRelay) Stop() error {
	if s.listener == nil {
		return nil
	}
	if err := s.listener.SetDeadline(time.Now()); err != nil {
		return err
	}
	s.wg.Wait()
	return s.listener.Close()
}
