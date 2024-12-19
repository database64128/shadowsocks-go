package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"path"

	"github.com/database64128/shadowsocks-go/api/internal/restapi"
	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"go.uber.org/zap"
)

// Config stores the configuration for the RESTful API.
type Config struct {
	// Enabled controls whether the API server is enabled.
	Enabled bool `json:"enabled"`

	// DebugPprof enables pprof endpoints for debugging and profiling.
	DebugPprof bool `json:"debugPprof"`

	// EnableTrustedProxyCheck enables trusted proxy checks.
	EnableTrustedProxyCheck bool `json:"enableTrustedProxyCheck"`

	// TrustedProxies is the list of trusted proxies.
	// This only takes effect if EnableTrustedProxyCheck is true.
	TrustedProxies []string `json:"trustedProxies"`

	// ProxyHeader is the header used to determine the client's IP address.
	// If empty, the remote peer's address is used.
	ProxyHeader string `json:"proxyHeader"`

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

	if c.DebugPprof {
		register := func(path string, handler http.HandlerFunc) {
			pattern := "GET " + joinPatternPath(basePath, path)
			mux.Handle(pattern, logPprofRequests(logger, handler))
		}

		register("/debug/pprof/", pprof.Index)
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
		mux.Handle(pattern, logAPIRequests(logger, handler))
	})

	if c.StaticPath != "" {
		mux.Handle("GET /", logFileServerRequests(logger, http.FileServer(http.Dir(c.StaticPath))))
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

// logPprofRequests is a middleware that logs pprof requests.
func logPprofRequests(logger *zap.Logger, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(w, r)
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

// String implements [service.Service.String].
func (s *Server) String() string {
	return "API server"
}

// Start starts the API server.
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
func (s *Server) Stop() error {
	return s.server.Close()
}
