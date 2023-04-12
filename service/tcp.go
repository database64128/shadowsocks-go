package service

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"go.uber.org/zap"
)

const (
	initialPayloadWaitBufferSize = 1280
	initialPayloadWaitTimeout    = 250 * time.Millisecond
)

// tcpRelayListener configures the TCP listener for a relay service.
type tcpRelayListener struct {
	listener              *net.TCPListener
	listenConfig          conn.ListenConfig
	waitForInitialPayload bool
	network               string
	address               string
}

// TCPRelay is a relay service for TCP traffic.
//
// When started, the relay service accepts incoming TCP connections on the server,
// and dispatches them to a client selected by the router.
//
// TCPRelay implements the Service interface.
type TCPRelay struct {
	serverIndex     int
	serverName      string
	listeners       []tcpRelayListener
	wg              sync.WaitGroup
	server          zerocopy.TCPServer
	connCloser      zerocopy.TCPConnCloser
	fallbackAddress conn.Addr
	collector       stats.Collector
	router          *router.Router
	logger          *zap.Logger
}

func NewTCPRelay(
	serverIndex int,
	serverName string,
	listeners []tcpRelayListener,
	server zerocopy.TCPServer,
	connCloser zerocopy.TCPConnCloser,
	fallbackAddress conn.Addr,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) *TCPRelay {
	return &TCPRelay{
		serverIndex:     serverIndex,
		serverName:      serverName,
		listeners:       listeners,
		server:          server,
		connCloser:      connCloser,
		fallbackAddress: fallbackAddress,
		collector:       collector,
		router:          router,
		logger:          logger,
	}
}

// String implements the Service String method.
func (s *TCPRelay) String() string {
	return "TCP relay service for " + s.serverName
}

// Start implements the Service Start method.
func (s *TCPRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		index := i
		lnc := &s.listeners[index]

		l, err := lnc.listenConfig.ListenTCP(ctx, lnc.network, lnc.address)
		if err != nil {
			return err
		}
		lnc.listener = l

		s.wg.Add(1)

		go func() {
			for {
				clientConn, err := lnc.listener.AcceptTCP()
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					s.logger.Warn("Failed to accept TCP connection",
						zap.String("server", s.serverName),
						zap.Int("listener", index),
						zap.String("listenAddress", lnc.address),
						zap.Error(err),
					)
					continue
				}

				go s.handleConn(ctx, index, lnc, clientConn)
			}

			s.wg.Done()
		}()

		s.logger.Info("Started TCP relay service listener",
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
		)
	}
	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(ctx context.Context, index int, lnc *tcpRelayListener, clientConn *net.TCPConn) {
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
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
				zap.String("clientAddress", clientAddress),
			)
			return
		}

		s.logger.Warn("Failed to complete handshake with client",
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
			zap.String("clientAddress", clientAddress),
			zap.Error(err),
		)

		if !s.fallbackAddress.IsValid() || len(payload) == 0 {
			s.connCloser(clientConn, s.serverName, lnc.address, clientAddress, s.logger)
			return
		}

		clientRW = direct.NewDirectStreamReadWriter(clientConn)
		targetAddr = s.fallbackAddress
	}

	// Convert target address to string once for log messages.
	targetAddress := targetAddr.String()

	// Route.
	c, err := s.router.GetTCPClient(ctx, router.RequestInfo{
		ServerIndex:    s.serverIndex,
		Username:       username,
		SourceAddrPort: clientAddrPort,
		TargetAddr:     targetAddr,
	})
	if err != nil {
		s.logger.Warn("Failed to get TCP client for client connection",
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
			zap.String("clientAddress", clientAddress),
			zap.String("username", username),
			zap.String("targetAddress", targetAddress),
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
	if lnc.waitForInitialPayload && clientInfo.NativeInitialPayload {
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
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
				zap.String("clientAddress", clientAddress),
				zap.String("username", username),
				zap.String("targetAddress", targetAddress),
				zap.String("client", clientInfo.Name),
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
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
				zap.String("clientAddress", clientAddress),
				zap.String("username", username),
				zap.String("targetAddress", targetAddress),
				zap.String("client", clientInfo.Name),
				zap.Int("payloadLength", payloadLength),
			)

		case errors.Is(err, os.ErrDeadlineExceeded):
			s.logger.Debug("Initial payload wait timed out",
				zap.String("server", s.serverName),
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
				zap.String("clientAddress", clientAddress),
				zap.String("username", username),
				zap.String("targetAddress", targetAddress),
				zap.String("client", clientInfo.Name),
			)

		default:
			s.logger.Warn("Failed to read initial payload",
				zap.String("server", s.serverName),
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
				zap.String("clientAddress", clientAddress),
				zap.String("username", username),
				zap.String("targetAddress", targetAddress),
				zap.String("client", clientInfo.Name),
				zap.Error(err),
			)
			return
		}

		err = clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			s.logger.Warn("Failed to reset read deadline",
				zap.String("server", s.serverName),
				zap.Int("listener", index),
				zap.String("listenAddress", lnc.address),
				zap.String("clientAddress", clientAddress),
				zap.String("username", username),
				zap.String("targetAddress", targetAddress),
				zap.String("client", clientInfo.Name),
				zap.Error(err),
			)
			return
		}
	}

	// Create remote connection.
	remoteConn, remoteRW, err := c.Dial(ctx, targetAddr, payload)
	if err != nil {
		s.logger.Warn("Failed to create remote connection",
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
			zap.String("clientAddress", clientAddress),
			zap.String("username", username),
			zap.String("targetAddress", targetAddress),
			zap.String("client", clientInfo.Name),
			zap.Int("initialPayloadLength", len(payload)),
			zap.Error(err),
		)
		return
	}
	defer remoteConn.Close()

	s.logger.Info("Two-way relay started",
		zap.String("server", s.serverName),
		zap.Int("listener", index),
		zap.String("listenAddress", lnc.address),
		zap.String("clientAddress", clientAddress),
		zap.String("username", username),
		zap.String("targetAddress", targetAddress),
		zap.String("client", clientInfo.Name),
		zap.Int("initialPayloadLength", len(payload)),
	)

	// Two-way relay.
	nl2r, nr2l, err := zerocopy.TwoWayRelay(clientRW, remoteRW)
	nl2r += int64(len(payload))
	s.collector.CollectTCPSession(username, uint64(nr2l), uint64(nl2r))
	if err != nil {
		s.logger.Warn("Two-way relay failed",
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
			zap.String("clientAddress", clientAddress),
			zap.String("username", username),
			zap.String("targetAddress", targetAddress),
			zap.String("client", clientInfo.Name),
			zap.Int64("nl2r", nl2r),
			zap.Int64("nr2l", nr2l),
			zap.Error(err),
		)
		return
	}

	s.logger.Info("Two-way relay completed",
		zap.String("server", s.serverName),
		zap.Int("listener", index),
		zap.String("listenAddress", lnc.address),
		zap.String("clientAddress", clientAddress),
		zap.String("username", username),
		zap.String("targetAddress", targetAddress),
		zap.String("client", clientInfo.Name),
		zap.Int64("nl2r", nl2r),
		zap.Int64("nr2l", nr2l),
	)
}

// Stop implements the Service Stop method.
func (s *TCPRelay) Stop() error {
	now := time.Now()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.SetDeadline(now); err != nil {
			s.logger.Warn("Failed to set deadline on listener",
				zap.String("server", s.serverName),
				zap.Int("listener", i),
				zap.String("listenAddress", lnc.address),
				zap.Error(err),
			)
		}
	}

	s.wg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.Close(); err != nil {
			s.logger.Warn("Failed to close listener",
				zap.String("server", s.serverName),
				zap.Int("listener", i),
				zap.String("listenAddress", lnc.address),
				zap.Error(err),
			)
		}
	}

	return nil
}
