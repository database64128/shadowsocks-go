package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/netio"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/tslog"
)

const (
	defaultInitialPayloadWaitBufferSize = 1440
	defaultInitialPayloadWaitTimeout    = 250 * time.Millisecond
)

type streamRelayInitialPayloadWaitConfig struct {
	waitForInitialPayload        bool
	initialPayloadWaitTimeout    time.Duration
	initialPayloadWaitBufferSize int
}

// streamRelayTCPListener is the configuration for a stream relay TCP listener.
type streamRelayTCPListener struct {
	logger                   *tslog.Logger
	listener                 *net.TCPListener
	listenConfig             conn.TCPListenConfig
	network                  string
	address                  string
	initialPayloadWaitConfig streamRelayInitialPayloadWaitConfig
}

// streamRelayUnixListener is the configuration for a stream relay Unix domain socket listener.
type streamRelayUnixListener struct {
	logger                   *tslog.Logger
	listener                 *net.UnixListener
	listenConfig             conn.UnixDomainSocketConfig
	network                  string
	address                  string
	permissions              conn.UnixDomainSocketPermissions
	initialPayloadWaitConfig streamRelayInitialPayloadWaitConfig
}

// TCPRelay is a relay service for TCP traffic.
//
// When started, the relay service accepts incoming TCP connections on the server,
// and dispatches them to a client selected by the router.
//
// TCPRelay implements the Service interface.
type TCPRelay struct {
	serverIndex   int
	serverName    string
	tcpListeners  []streamRelayTCPListener
	unixListeners []streamRelayUnixListener
	acceptWg      sync.WaitGroup
	server        netio.StreamServer
	collector     stats.Collector
	router        *router.Router
	logger        *tslog.Logger
}

func NewTCPRelay(
	serverIndex int,
	serverName string,
	tcpListeners []streamRelayTCPListener,
	unixListeners []streamRelayUnixListener,
	server netio.StreamServer,
	collector stats.Collector,
	router *router.Router,
	logger *tslog.Logger,
) *TCPRelay {
	return &TCPRelay{
		serverIndex:   serverIndex,
		serverName:    serverName,
		tcpListeners:  tcpListeners,
		unixListeners: unixListeners,
		server:        server,
		collector:     collector,
		router:        router,
		logger:        logger,
	}
}

var _ shadowsocks.Service = (*TCPRelay)(nil)

// SlogAttr implements [shadowsocks.Service.SlogAttr].
func (s *TCPRelay) SlogAttr() slog.Attr {
	return slog.String("serverTCPRelay", s.serverName)
}

// Start implements [shadowsocks.Service.Start].
func (s *TCPRelay) Start(ctx context.Context) error {
	tcpListeners := s.tcpListeners
	for i := range tcpListeners {
		lnc := &tcpListeners[i]

		l, err := lnc.listenConfig.Listen(ctx, lnc.network, lnc.address)
		if err != nil {
			return err
		}
		lnc.listener = l
		lnc.address = l.Addr().String()
		lnc.logger = s.logger.WithAttrs(
			slog.String("server", s.serverName),
			slog.Int("tcpListener", i),
			slog.String("listenAddress", lnc.address),
		)

		s.acceptWg.Go(func() {
			for {
				clientConn, err := lnc.listener.AcceptTCP()
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					lnc.logger.Error("Failed to accept TCP connection", tslog.Err(err))
					continue
				}

				go s.handleConn(ctx, lnc.logger, lnc.initialPayloadWaitConfig, clientConn)
			}
		})

		lnc.logger.Info("Started stream relay service TCP listener")
	}

	unixListeners := s.unixListeners
	for i := range unixListeners {
		lnc := &unixListeners[i]

		l, err := lnc.listenConfig.Listen(ctx, lnc.network, lnc.address, lnc.permissions)
		if err != nil {
			return err
		}
		lnc.listener = l
		lnc.address = l.Addr().String()
		lnc.logger = s.logger.WithAttrs(
			slog.String("server", s.serverName),
			slog.Int("unixListener", i),
			slog.String("listenAddress", lnc.address),
		)

		s.acceptWg.Go(func() {
			for {
				clientConn, err := lnc.listener.AcceptUnix()
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					lnc.logger.Error("Failed to accept Unix connection", tslog.Err(err))
					continue
				}

				go s.handleConn(ctx, lnc.logger, lnc.initialPayloadWaitConfig, clientConn)
			}
		})

		lnc.logger.Info("Started stream relay service Unix listener")
	}

	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(
	ctx context.Context,
	logger *tslog.Logger,
	ipwCfg streamRelayInitialPayloadWaitConfig,
	acceptedConn netio.Conn,
) {
	var inConn netio.Conn
	defer func() {
		if inConn != nil {
			_ = inConn.Close()
		} else {
			_ = acceptedConn.Close()
		}
	}()

	var (
		clientAddrPort netip.AddrPort
		clientAddress  string
	)
	clientAddr := acceptedConn.RemoteAddr()
	if clientTCPAddr, ok := clientAddr.(*net.TCPAddr); ok {
		clientAddrPort = clientTCPAddr.AddrPort()
		// Unlike net.TCPAddr.String, netip.AddrPort.String preserves IPv4-mapped IPv6 addresses.
		clientAddress = clientAddrPort.String()
	} else {
		clientAddress = clientAddr.String()
	}

	logger = logger.WithAttrs(
		slog.String("clientAddress", clientAddress),
	)

	// Handshake.
	req, err := s.server.HandleStream(acceptedConn, logger)
	if err != nil {
		if err == netio.ErrHandleStreamDone {
			logger.Debug("Handled stream connection without bidirectional copy")
			return
		}
		logger.Warn("Failed to complete handshake with client", tslog.Err(err))
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
			slog.String("username", req.Username),
			slog.String("targetAddress", targetAddress),
			tslog.Err(err),
		)

		dialResult := conn.DialResultFromError(err)
		if err = req.Abort(dialResult); err != nil {
			logger.Warn("Failed to abort pending connection",
				slog.String("username", req.Username),
				slog.String("targetAddress", targetAddress),
				tslog.Err(err),
			)
		}
		return
	}

	// Create dialer.
	dialer, clientInfo := c.NewStreamDialer()

	// Create logger with new fields.
	logger = logger.WithAttrs(
		slog.String("username", req.Username),
		slog.String("targetAddress", targetAddress),
		slog.String("client", clientInfo.Name),
	)

	// Wait for initial payload if all of the following are true:
	// 1. not disabled
	// 2. server does not have native support
	// 3. server did not return initial payload
	// 4. client has native support
	if len(req.Payload) == 0 && clientInfo.NativeInitialPayload && ipwCfg.waitForInitialPayload {
		inConn, err = req.PendingConn.Proceed()
		if err != nil {
			logger.Warn("Failed to proceed with pending connection", tslog.Err(err))
			return
		}

		req.Payload = make([]byte, ipwCfg.initialPayloadWaitBufferSize)

		if err = inConn.SetReadDeadline(time.Now().Add(ipwCfg.initialPayloadWaitTimeout)); err != nil {
			logger.Error("Failed to set read deadline to initial payload wait timeout", tslog.Err(err))
			return
		}

		payloadLength, err := inConn.Read(req.Payload)
		switch {
		case err == nil:
			if logger.Enabled(slog.LevelDebug) {
				logger.Debug("Got initial payload",
					slog.Int("payloadLength", payloadLength),
				)
			}

		case err == io.EOF:
			if logger.Enabled(slog.LevelDebug) {
				logger.Debug("Got initial payload and EOF",
					slog.Int("payloadLength", payloadLength),
				)
			}

		case errors.Is(err, os.ErrDeadlineExceeded):
			logger.Debug("Initial payload wait timed out")

		default:
			logger.Warn("Failed to read initial payload", tslog.Err(err))
			return
		}

		req.Payload = req.Payload[:payloadLength]

		if err = inConn.SetReadDeadline(time.Time{}); err != nil {
			logger.Error("Failed to reset read deadline", tslog.Err(err))
			return
		}
	}

	// Open outgoing connection to destination address.
	outConn, err := dialer.DialStream(ctx, req.Addr, req.Payload)
	if err != nil {
		logger.Warn("Failed to open outgoing connection",
			slog.Int("initialPayloadLength", len(req.Payload)),
			tslog.Err(err),
		)
		if inConn == nil {
			dialResult := conn.DialResultFromError(err)
			if err = req.Abort(dialResult); err != nil {
				logger.Warn("Failed to abort pending connection", tslog.Err(err))
			}
		}
		return
	}
	defer outConn.Close()

	if inConn == nil {
		inConn, err = req.PendingConn.Proceed()
		if err != nil {
			logger.Warn("Failed to proceed with pending connection", tslog.Err(err))
			return
		}
	}

	logger.Info("Bidirectional copy started",
		slog.Int("initialPayloadLength", len(req.Payload)),
	)

	// Bidirectional copy.
	nl2r, nr2l, err := netio.BidirectionalCopy(inConn, outConn)
	nl2r += int64(len(req.Payload))
	s.collector.CollectTCPSession(req.Username, uint64(nr2l), uint64(nl2r))
	if err != nil {
		logger.Warn("Bidirectional copy failed",
			slog.Int64("nl2r", nl2r),
			slog.Int64("nr2l", nr2l),
			tslog.Err(err),
		)
		return
	}

	logger.Info("Bidirectional copy completed",
		slog.Int64("nl2r", nl2r),
		slog.Int64("nr2l", nr2l),
	)
}

// Stop implements [shadowsocks.Service.Stop].
func (s *TCPRelay) Stop() error {
	tcpListeners := s.tcpListeners
	unixListeners := s.unixListeners

	for i := range tcpListeners {
		lnc := &tcpListeners[i]
		if err := lnc.listener.SetDeadline(conn.ALongTimeAgo); err != nil {
			lnc.logger.Error("Failed to set deadline on TCP listener", tslog.Err(err))
		}
	}
	for i := range unixListeners {
		lnc := &unixListeners[i]
		if err := lnc.listener.SetDeadline(conn.ALongTimeAgo); err != nil {
			lnc.logger.Error("Failed to set deadline on Unix listener", tslog.Err(err))
		}
	}

	s.acceptWg.Wait()

	for i := range tcpListeners {
		lnc := &tcpListeners[i]
		if err := lnc.listener.Close(); err != nil {
			lnc.logger.Error("Failed to close TCP listener", tslog.Err(err))
		}
	}
	for i := range unixListeners {
		lnc := &unixListeners[i]
		if err := lnc.listener.Close(); err != nil {
			lnc.logger.Error("Failed to close Unix listener", tslog.Err(err))
		}
	}

	s.logger.Info("Stopped stream relay service", slog.String("server", s.serverName))
	return nil
}
