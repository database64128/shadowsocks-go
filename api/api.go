package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"path"
	"strings"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/api/internal/restapi"
	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"go.uber.org/zap"
	"go4.org/netipx"
)

// Config stores the configuration for the RESTful API.
type Config struct {
	// Enabled controls whether the API server is enabled.
	Enabled bool `json:"enabled"`

	// DebugPprof enables pprof endpoints for debugging and profiling.
	DebugPprof bool `json:"debugPprof"`

	// TrustedProxies specifies the IP address prefixes of trusted proxies.
	TrustedProxies []netip.Prefix `json:"trustedProxies"`

	// RealIPHeaderKey specifies the header field to use for determining
	// the client's real IP address when the request is from a trusted proxy.
	// If empty, the real IP address is not appended to [http.Request.RemoteAddr].
	RealIPHeaderKey string `json:"realIPHeaderKey"`

	// StaticPath is the path where static files are served from.
	// If empty, static file serving is disabled.
	StaticPath string `json:"staticPath"`

	// SecretPath adds a secret path prefix to API and pprof endpoints.
	// Static files are not affected. If empty, no secret path is added.
	SecretPath string `json:"secretPath"`

	// Listeners is the list of server listeners.
	Listeners []ListenerConfig `json:"listeners"`
}

// ListenerConfig is the configuration for a server listener.
type ListenerConfig struct {
	// Network is the network type.
	Network string `json:"network"`

	// Address is the address to listen on.
	Address string `json:"address"`

	// Fwmark sets the listener's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int `json:"fwmark"`

	// TrafficClass sets the traffic class of the listener.
	//
	// Available on most platforms except Windows.
	TrafficClass int `json:"trafficClass"`

	// FastOpenBacklog specifies the maximum number of pending TFO connections on Linux.
	// If the value is 0, Go std's listen(2) backlog is used.
	//
	// On other platforms, a non-negative value is ignored, as they do not have the option to set the TFO backlog.
	//
	// On all platforms, a negative value disables TFO.
	FastOpenBacklog int `json:"fastOpenBacklog"`

	// DeferAcceptSecs sets TCP_DEFER_ACCEPT to the given number of seconds on the listener.
	//
	// Available on Linux.
	DeferAcceptSecs int `json:"deferAcceptSecs"`

	// UserTimeoutMsecs sets TCP_USER_TIMEOUT to the given number of milliseconds on the listener.
	//
	// Available on Linux.
	UserTimeoutMsecs int `json:"userTimeoutMsecs"`

	// CertList is the name of the certificate list in the certificate store,
	// used as the server certificate for HTTPS.
	CertList string `json:"certList"`

	// ClientCAs is the name of the X.509 certificate pool in the certificate store,
	// used as the root CA set for verifying client certificates.
	ClientCAs string `json:"clientCAs"`

	// EncryptedClientHelloKeys are the ECH keys to use when a client attempts ECH.
	EncryptedClientHelloKeys []EncryptedClientHelloKey `json:"encryptedClientHelloKeys"`

	// EnableTLS controls whether to enable TLS.
	EnableTLS bool `json:"enableTLS"`

	// RequireAndVerifyClientCert controls whether to require and verify client certificates.
	RequireAndVerifyClientCert bool `json:"requireAndVerifyClientCert"`

	// ReusePort enables SO_REUSEPORT on the listener.
	//
	// Available on Linux and the BSDs.
	ReusePort bool `json:"reusePort"`

	// FastOpen enables TCP Fast Open on the listener.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	FastOpen bool `json:"fastOpen"`

	// FastOpenFallback enables runtime detection of TCP Fast Open support on the listener.
	//
	// When enabled, the listener will start without TFO if TFO is not available on the system.
	// When disabled, the listener will abort if TFO cannot be enabled on the socket.
	//
	// Available on all platforms.
	FastOpenFallback bool `json:"fastOpenFallback"`

	// Multipath enables multipath TCP on the listener.
	//
	// Unlike Go std, we make MPTCP strictly opt-in.
	// That is, if this field is false, MPTCP will be explicitly disabled.
	// This ensures that if Go std suddenly decides to enable MPTCP by default,
	// existing configurations won't encounter issues due to missing features in the kernel MPTCP stack,
	// such as TCP keepalive (as of Linux 6.5), and failed connect attempts won't always be retried once.
	//
	// Available on platforms supported by Go std's MPTCP implementation.
	Multipath bool `json:"multipath"`
}

// EncryptedClientHelloKey holds a private key that is associated
// with a specific ECH config known to a client.
type EncryptedClientHelloKey struct {
	// Config should be a marshalled ECHConfig associated with PrivateKey. This
	// must match the config provided to clients byte-for-byte. The config
	// should only specify the DHKEM(X25519, HKDF-SHA256) KEM ID (0x0020), the
	// HKDF-SHA256 KDF ID (0x0001), and a subset of the following AEAD IDs:
	// AES-128-GCM (0x0000), AES-256-GCM (0x0001), ChaCha20Poly1305 (0x0002).
	Config []byte `json:"config"`

	// PrivateKey should be a marshalled private key. Currently, we expect
	// this to be the output of [ecdh.PrivateKey.Bytes].
	PrivateKey []byte `json:"privateKey"`

	// SendAsRetry indicates if Config should be sent as part of the list of
	// retry configs when ECH is requested by the client but rejected by the
	// server.
	SendAsRetry bool `json:"sendAsRetry"`
}

// NewServer returns a new API server from the config.
func (c *Config) NewServer(logger *zap.Logger, listenConfigCache conn.ListenConfigCache, tlsCertStore *tlscerts.Store) (*Server, *ssm.ServerManager, error) {
	if len(c.Listeners) == 0 {
		return nil, nil, errors.New("no listeners specified")
	}

	lcs := make([]listenConfig, len(c.Listeners))
	for i := range c.Listeners {
		lnc := &c.Listeners[i]
		lcs[i] = listenConfig{
			listenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
				Fwmark:              lnc.Fwmark,
				TrafficClass:        lnc.TrafficClass,
				TCPFastOpenBacklog:  lnc.FastOpenBacklog,
				TCPDeferAcceptSecs:  lnc.DeferAcceptSecs,
				TCPUserTimeoutMsecs: lnc.UserTimeoutMsecs,
				ReusePort:           lnc.ReusePort,
				TCPFastOpen:         lnc.FastOpen,
				TCPFastOpenFallback: lnc.FastOpenFallback,
				MultipathTCP:        lnc.Multipath,
			}),
			network: lnc.Network,
			address: lnc.Address,
		}

		if lnc.EnableTLS {
			var tlsConfig tls.Config

			if lnc.CertList != "" {
				certs, getCert, ok := tlsCertStore.GetCertList(lnc.CertList)
				if !ok {
					return nil, nil, fmt.Errorf("certificate list %q not found", lnc.CertList)
				}
				tlsConfig.Certificates = certs
				tlsConfig.GetCertificate = getCert
			}

			if lnc.ClientCAs != "" {
				pool, ok := tlsCertStore.GetX509CertPool(lnc.ClientCAs)
				if !ok {
					return nil, nil, fmt.Errorf("client CA X.509 certificate pool %q not found", lnc.ClientCAs)
				}
				tlsConfig.ClientCAs = pool
			}

			tlsConfig.EncryptedClientHelloKeys = make([]tls.EncryptedClientHelloKey, len(lnc.EncryptedClientHelloKeys))
			for j, key := range lnc.EncryptedClientHelloKeys {
				tlsConfig.EncryptedClientHelloKeys[j] = tls.EncryptedClientHelloKey{
					Config:      key.Config,
					PrivateKey:  key.PrivateKey,
					SendAsRetry: key.SendAsRetry,
				}
			}

			if lnc.RequireAndVerifyClientCert {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}

			lcs[i].tlsConfig = &tlsConfig
		}
	}

	mux := http.NewServeMux()

	basePath := "/"
	if c.SecretPath != "" {
		basePath = joinPatternPath(basePath, c.SecretPath)
	}

	realIP, err := newRealIPMiddleware(logger, c.TrustedProxies, c.RealIPHeaderKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create real IP middleware: %w", err)
	}

	if c.DebugPprof {
		register := func(path string, handler http.HandlerFunc) {
			pattern := "GET " + joinPatternPath(basePath, path)
			mux.Handle(pattern, realIP(logPprofRequests(logger, handler)))
		}

		// [pprof.Index] requires the URL path to start with "/debug/pprof/".
		indexPath := joinPatternPath(basePath, "/debug/pprof/")
		prefix := strings.TrimSuffix(indexPath, "/debug/pprof/")
		mux.Handle(indexPath, realIP(logPprofRequests(logger, http.StripPrefix(prefix, http.HandlerFunc(pprof.Index)))))

		register("/debug/pprof/cmdline", pprof.Cmdline)
		register("/debug/pprof/profile", pprof.Profile)
		register("/debug/pprof/symbol", pprof.Symbol)
		register("/debug/pprof/trace", pprof.Trace)
	}

	// /api/ssm/v1
	apiSSMv1Path := joinPatternPath(basePath, "/api/ssm/v1")
	sm := ssm.NewServerManager()
	sm.RegisterHandlers(func(method, path string, handler restapi.HandlerFunc) {
		pattern := method + " " + joinPatternPath(apiSSMv1Path, path)
		mux.Handle(pattern, realIP(logAPIRequests(logger, handler)))
	})

	if c.StaticPath != "" {
		mux.Handle("GET /", realIP(logFileServerRequests(logger, http.FileServer(http.Dir(c.StaticPath)))))
	}

	errorLog, err := zap.NewStdLogAt(logger, zap.ErrorLevel)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create error logger: %w", err)
	}

	return &Server{
		logger: logger,
		lcs:    lcs,
		server: http.Server{
			Handler:  mux,
			ErrorLog: errorLog,
		},
	}, sm, nil
}

// joinPatternPath joins path elements into a pattern path.
func joinPatternPath(elem ...string) string {
	if len(elem) == 0 {
		return ""
	}
	p := path.Join(elem...)
	if p == "" {
		return ""
	}
	// Add back the trailing slash removed by [path.Join].
	if last := elem[len(elem)-1]; last != "" && last[len(last)-1] == '/' {
		if p[len(p)-1] != '/' {
			return p + "/"
		}
	}
	return p
}

// newRealIPMiddleware returns a middleware that appends the content of realIPHeaderKey
// to [http.Request.RemoteAddr] if the request is from a trusted proxy.
//
// If realIPHeaderKey is empty, the middleware is a no-op.
func newRealIPMiddleware(logger *zap.Logger, trustedProxies []netip.Prefix, realIPHeaderKey string) (func(http.Handler) http.Handler, error) {
	if realIPHeaderKey == "" {
		return func(h http.Handler) http.Handler {
			return h
		}, nil
	}

	var sb netipx.IPSetBuilder
	for _, p := range trustedProxies {
		sb.AddPrefix(p)
	}

	proxySet, err := sb.IPSet()
	if err != nil {
		return nil, fmt.Errorf("failed to build trusted proxy prefix set: %w", err)
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.Header[realIPHeaderKey]; len(v) > 0 {
				proxyAddrPort, err := netip.ParseAddrPort(r.RemoteAddr)
				if err != nil {
					logger.Warn("Failed to parse HTTP request remote address",
						zap.String("remoteAddr", r.RemoteAddr),
						zap.Error(err),
					)
					return
				}

				if proxySet.Contains(proxyAddrPort.Addr()) {
					r.RemoteAddr = fmt.Sprintf("%s (%s: %v)", r.RemoteAddr, realIPHeaderKey, v)
				}
			}

			h.ServeHTTP(w, r)
		})
	}, nil
}

// logPprofRequests is a middleware that logs pprof requests.
func logPprofRequests(logger *zap.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		logger.Info("Handled pprof request",
			zap.String("proto", r.Proto),
			zap.String("method", r.Method),
			zap.String("requestURI", r.RequestURI),
			zap.String("host", r.Host),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	})
}

// logAPIRequests is a middleware that logs API requests.
func logAPIRequests(logger *zap.Logger, h restapi.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, err := h(w, r)
		logger.Info("Handled API request",
			zap.String("proto", r.Proto),
			zap.String("method", r.Method),
			zap.String("requestURI", r.RequestURI),
			zap.String("host", r.Host),
			zap.String("remoteAddr", r.RemoteAddr),
			zap.Int("status", status),
			zap.Error(err),
		)
	})
}

// logFileServerRequests is a middleware that logs file server requests.
func logFileServerRequests(logger *zap.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		logger.Info("Served file",
			zap.String("proto", r.Proto),
			zap.String("method", r.Method),
			zap.String("requestURI", r.RequestURI),
			zap.String("host", r.Host),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	})
}

type listenConfig struct {
	listenConfig conn.ListenConfig
	network      string
	address      string
	tlsConfig    *tls.Config
}

// Server is the RESTful API server.
type Server struct {
	logger *zap.Logger
	lcs    []listenConfig
	server http.Server
}

var _ shadowsocks.Service = (*Server)(nil)

// ZapField implements [shadowsocks.Service.ZapField].
func (*Server) ZapField() zap.Field {
	return zap.String("service", "api")
}

// Start starts the API server.
//
// Start implements [shadowsocks.Service.Start].
func (s *Server) Start(ctx context.Context) error {
	for i := range s.lcs {
		lc := &s.lcs[i]
		ln, _, err := lc.listenConfig.Listen(ctx, lc.network, lc.address)
		if err != nil {
			return err
		}

		if lc.tlsConfig != nil {
			ln = tls.NewListener(ln, lc.tlsConfig)
		}

		go func() {
			if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.logger.Error("Failed to serve API", zap.Error(err))
			}
		}()

		s.logger.Info("Started API server listener", zap.Stringer("listenAddress", ln.Addr()))
	}
	return nil
}

// Stop stops the API server.
//
// Stop implements [shadowsocks.Service.Stop].
func (s *Server) Stop() error {
	return s.server.Close()
}
