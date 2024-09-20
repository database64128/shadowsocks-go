package service

import (
	"context"
	"errors"
	"io"
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
	defaultInitialPayloadWaitBufferSize = 1440
	defaultInitialPayloadWaitTimeout    = 250 * time.Millisecond
)

// tcpRelayListener configures the TCP listener for a relay service.
type tcpRelayListener struct {
	logger                       *zap.Logger
	listener                     *net.TCPListener
	listenConfig                 conn.ListenConfig
	waitForInitialPayload        bool
	initialPayloadWaitTimeout    time.Duration
	initialPayloadWaitBufferSize int
	network                      string
	address                      string
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
	acceptWg        sync.WaitGroup
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
		lnc.address = l.Addr().String()
		lnc.logger = s.logger.With(
			zap.String("server", s.serverName),
			zap.Int("listener", index),
			zap.String("listenAddress", lnc.address),
		)

		s.acceptWg.Add(1)

		go func() {
			for {
				clientConn, err := lnc.listener.AcceptTCP()
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					lnc.logger.Warn("Failed to accept TCP connection", zap.Error(err))
					continue
				}

				go s.handleConn(ctx, lnc, clientConn)
			}

			s.acceptWg.Done()
		}()

		lnc.logger.Info("Started TCP relay service listener")
	}
	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(ctx context.Context, lnc *tcpRelayListener, clientConn *net.TCPConn) {
	// Get client address.
	clientAddrPort := clientConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	clientAddress := clientAddrPort.String()

	// Handshake.
	clientRW, targetAddr, payload, username, err := s.server.Accept(clientConn)
	if err != nil {
		if err == zerocopy.ErrAcceptDoneNoRelay {
			if ce := lnc.logger.Check(zap.DebugLevel, "The accepted connection has been handled without relaying"); ce != nil {
				ce.Write(
					zap.String("clientAddress", clientAddress),
				)
			}
			clientConn.Close()
			return
		}

		logger := lnc.logger.With(
			zap.String("clientAddress", clientAddress),
		)

		logger.Warn("Failed to complete handshake with client", zap.Error(err))

		if !s.fallbackAddress.IsValid() || len(payload) == 0 {
			s.connCloser(clientConn, logger)
			clientConn.Close()
			return
		}

		clientRW = direct.NewDirectStreamReadWriter(clientConn)
		targetAddr = s.fallbackAddress
	}
	defer clientRW.Close()

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
		lnc.logger.Warn("Failed to get TCP client for client connection",
			zap.String("clientAddress", clientAddress),
			zap.String("username", username),
			zap.String("targetAddress", targetAddress),
			zap.Error(err),
		)
		return
	}

	// Get client info.
	clientInfo := c.Info()

	// Create logger with new fields.
	logger := lnc.logger.With(
		zap.String("clientAddress", clientAddress),
		zap.String("username", username),
		zap.String("targetAddress", targetAddress),
		zap.String("client", clientInfo.Name),
	)

	// Wait for initial payload if all of the following are true:
	// 1. not disabled
	// 2. server does not have native support
	// 3. client has native support
	if lnc.waitForInitialPayload && clientInfo.NativeInitialPayload {
		clientReaderInfo := clientRW.ReaderInfo()
		payloadBufSize := max(clientReaderInfo.MinPayloadBufferSizePerRead, lnc.initialPayloadWaitBufferSize)
		payload = make([]byte, clientReaderInfo.Headroom.Front+payloadBufSize+clientReaderInfo.Headroom.Rear)

		err = clientConn.SetReadDeadline(time.Now().Add(lnc.initialPayloadWaitTimeout))
		if err != nil {
			logger.Warn("Failed to set read deadline to initial payload wait timeout", zap.Error(err))
			return
		}

		payloadLength, err := clientRW.ReadZeroCopy(payload, clientReaderInfo.Headroom.Front, payloadBufSize)
		switch {
		case err == nil:
			if ce := logger.Check(zap.DebugLevel, "Got initial payload"); ce != nil {
				ce.Write(
					zap.Int("payloadLength", payloadLength),
				)
			}

		case err == io.EOF:
			if ce := logger.Check(zap.DebugLevel, "Got initial payload and EOF"); ce != nil {
				ce.Write(
					zap.Int("payloadLength", payloadLength),
				)
			}

		case errors.Is(err, os.ErrDeadlineExceeded):
			if ce := logger.Check(zap.DebugLevel, "Initial payload wait timed out"); ce != nil {
				ce.Write()
			}

		default:
			logger.Warn("Failed to read initial payload", zap.Error(err))
			return
		}

		payload = payload[clientReaderInfo.Headroom.Front : clientReaderInfo.Headroom.Front+payloadLength]

		err = clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			logger.Warn("Failed to reset read deadline", zap.Error(err))
			return
		}
	}

	// Create remote connection.
	remoteRawRW, remoteRW, err := c.Dial(ctx, targetAddr, payload)
	if err != nil {
		logger.Warn("Failed to create remote connection",
			zap.Int("initialPayloadLength", len(payload)),
			zap.Error(err),
		)
		return
	}
	defer remoteRawRW.Close()

	logger.Info("Two-way relay started",
		zap.Int("initialPayloadLength", len(payload)),
	)

	// Two-way relay.
	nl2r, nr2l, err := zerocopy.TwoWayRelay(clientRW, remoteRW)
	nl2r += int64(len(payload))
	s.collector.CollectTCPSession(username, uint64(nr2l), uint64(nl2r))
	if err != nil {
		logger.Warn("Two-way relay failed",
			zap.Int64("nl2r", nl2r),
			zap.Int64("nr2l", nr2l),
			zap.Error(err),
		)
		return
	}

	logger.Info("Two-way relay completed",
		zap.Int64("nl2r", nl2r),
		zap.Int64("nr2l", nr2l),
	)
}

// Stop implements the Service Stop method.
func (s *TCPRelay) Stop() error {
	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.SetDeadline(conn.ALongTimeAgo); err != nil {
			lnc.logger.Warn("Failed to set deadline on listener", zap.Error(err))
		}
	}

	s.acceptWg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.Close(); err != nil {
			lnc.logger.Warn("Failed to close listener", zap.Error(err))
		}
	}

	return nil
}
