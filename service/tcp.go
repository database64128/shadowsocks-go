package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
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
	serverIndex int
	serverName  string
	listeners   []tcpRelayListener
	acceptWg    sync.WaitGroup
	server      netio.StreamServer
	collector   stats.Collector
	router      *router.Router
	logger      *zap.Logger
}

func NewTCPRelay(
	serverIndex int,
	serverName string,
	listeners []tcpRelayListener,
	server netio.StreamServer,
	collector stats.Collector,
	router *router.Router,
	logger *zap.Logger,
) *TCPRelay {
	return &TCPRelay{
		serverIndex: serverIndex,
		serverName:  serverName,
		listeners:   listeners,
		server:      server,
		collector:   collector,
		router:      router,
		logger:      logger,
	}
}

var _ shadowsocks.Service = (*TCPRelay)(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (s *TCPRelay) ZapField() zap.Field {
	return zap.String("serverTCPRelay", s.serverName)
}

// Start implements [shadowsocks.Service.Start].
func (s *TCPRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		index := i
		lnc := &s.listeners[index]

		l, _, err := lnc.listenConfig.ListenTCP(ctx, lnc.network, lnc.address)
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

		s.acceptWg.Go(func() {
			for {
				clientConn, err := lnc.listener.AcceptTCP()
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					lnc.logger.Error("Failed to accept TCP connection", zap.Error(err))
					continue
				}

				go s.handleConn(ctx, lnc, clientConn)
			}
		})

		lnc.logger.Info("Started TCP relay service listener")
	}
	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(ctx context.Context, lnc *tcpRelayListener, clientTCPConn *net.TCPConn) {
	var clientConn netio.Conn
	defer func() {
		if clientConn != nil {
			_ = clientConn.Close()
		} else {
			_ = clientTCPConn.Close()
		}
	}()

	// Get client address.
	clientAddrPort := clientTCPConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	clientAddress := clientAddrPort.String()
	logger := lnc.logger.With(
		zap.String("clientAddress", clientAddress),
	)

	// Handshake.
	req, err := s.server.HandleStream(clientTCPConn, logger)
	if err != nil {
		if err == netio.ErrHandleStreamDone {
			logger.Debug("Handled TCP connection without bidirectional copy")
			return
		}
		logger.Warn("Failed to complete handshake with client", zap.Error(err))
		return
	}

	// Convert target address to string once for log messages.
	targetAddress := req.Addr.String()

	// Route.
	c, err := s.router.GetTCPClient(ctx, router.RequestInfo{
		ServerIndex:    s.serverIndex,
		Username:       req.Username,
		SourceAddrPort: clientAddrPort,
		TargetAddr:     req.Addr,
	})
	if err != nil {
		logger.Warn("Failed to get TCP client for client connection",
			zap.String("username", req.Username),
			zap.String("targetAddress", targetAddress),
			zap.Error(err),
		)

		dialResult := router.DialResultFromError(err)
		if err = req.Abort(dialResult); err != nil {
			logger.Warn("Failed to abort pending connection",
				zap.String("username", req.Username),
				zap.String("targetAddress", targetAddress),
				zap.Error(err),
			)
		}
		return
	}

	// Create dialer.
	dialer, clientInfo := c.NewStreamDialer()

	// Create logger with new fields.
	logger = logger.With(
		zap.String("username", req.Username),
		zap.String("targetAddress", targetAddress),
		zap.String("client", clientInfo.Name),
	)

	// Wait for initial payload if all of the following are true:
	// 1. not disabled
	// 2. server does not have native support
	// 3. server did not return initial payload
	// 4. client has native support
	if len(req.Payload) == 0 && clientInfo.NativeInitialPayload && lnc.waitForInitialPayload {
		clientConn, err = req.PendingConn.Proceed()
		if err != nil {
			logger.Warn("Failed to proceed with pending connection", zap.Error(err))
			return
		}

		req.Payload = make([]byte, lnc.initialPayloadWaitBufferSize)

		if err = clientConn.SetReadDeadline(time.Now().Add(lnc.initialPayloadWaitTimeout)); err != nil {
			logger.Error("Failed to set read deadline to initial payload wait timeout", zap.Error(err))
			return
		}

		payloadLength, err := clientConn.Read(req.Payload)
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

		req.Payload = req.Payload[:payloadLength]

		if err = clientConn.SetReadDeadline(time.Time{}); err != nil {
			logger.Error("Failed to reset read deadline", zap.Error(err))
			return
		}
	}

	// Create remote connection.
	remoteConn, err := dialer.DialStream(ctx, req.Addr, req.Payload)
	if err != nil {
		logger.Warn("Failed to create remote connection",
			zap.Int("initialPayloadLength", len(req.Payload)),
			zap.Error(err),
		)
		if clientConn == nil {
			dialResult := conn.DialResultFromError(err)
			if err = req.Abort(dialResult); err != nil {
				logger.Warn("Failed to abort pending connection", zap.Error(err))
			}
		}
		return
	}
	defer remoteConn.Close()

	if clientConn == nil {
		clientConn, err = req.PendingConn.Proceed()
		if err != nil {
			logger.Warn("Failed to proceed with pending connection", zap.Error(err))
			return
		}
	}

	logger.Info("Bidirectional copy started",
		zap.Int("initialPayloadLength", len(req.Payload)),
	)

	// Bidirectional copy.
	nl2r, nr2l, err := netio.BidirectionalCopy(clientConn, remoteConn)
	nl2r += int64(len(req.Payload))
	s.collector.CollectTCPSession(req.Username, uint64(nr2l), uint64(nl2r))
	if err != nil {
		logger.Warn("Bidirectional copy failed",
			zap.Int64("nl2r", nl2r),
			zap.Int64("nr2l", nr2l),
			zap.Error(err),
		)
		return
	}

	logger.Info("Bidirectional copy completed",
		zap.Int64("nl2r", nl2r),
		zap.Int64("nr2l", nr2l),
	)
}

// Stop implements [shadowsocks.Service.Stop].
func (s *TCPRelay) Stop() error {
	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.SetDeadline(conn.ALongTimeAgo); err != nil {
			lnc.logger.Error("Failed to set deadline on listener", zap.Error(err))
		}
	}

	s.acceptWg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.Close(); err != nil {
			lnc.logger.Error("Failed to close listener", zap.Error(err))
		}
	}

	s.logger.Info("Stopped TCP relay service", zap.String("server", s.serverName))
	return nil
}
