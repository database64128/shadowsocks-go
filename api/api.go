package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"path"
	"strings"

	"github.com/database64128/shadowsocks-go"
	"github.com/database64128/shadowsocks-go/api/certmgr"
	"github.com/database64128/shadowsocks-go/api/internal/restapi"
	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/prefixset"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/tslog"
)

// Config is the configuration for the HTTP API server.
type Config struct {
	// DebugPprof enables pprof endpoints for debugging and profiling.
	DebugPprof bool

	// StaticAllowEscapingSymlinks controls whether to allow serving static files
	// that escape the static path via symlinks.
	StaticAllowEscapingSymlinks bool

	// TrustedProxies specifies the IP address prefixes of trusted proxies.
	// Requests from these proxies will be trusted to contain the real IP address
	// in the specified header field.
	// If empty, all proxies are trusted.
	TrustedProxies []netip.Prefix

	// RealIPHeaderKey specifies the header field to use for determining
	// the client's real IP address when the request is from a trusted proxy.
	// If empty, the real IP address is not appended to [http.Request.RemoteAddr].
	RealIPHeaderKey string

	// StaticPath is the path where static files are served from.
	// If empty, static file serving is disabled.
	StaticPath string

	// SecretPath adds a secret path prefix to API and pprof endpoints.
	// Static files are not affected. If empty, no secret path is added.
	SecretPath string

	// TCPListeners is the list of TCP listeners.
	TCPListeners []TCPListenerConfig
}

// TCPListenerConfig is the configuration for a TCP listener.
type TCPListenerConfig struct {
	// TCPListenConfig is the configuration for the TCP listener socket.
	TCPListenConfig conn.TCPListenConfig

	// Network specifies the address family of the listener.
	//
	//  - "tcp": TCP listener. Dual-stack on supported platforms. IPv4 on platforms without IPV6_V6ONLY.
	//  - "tcp4": IPv4 TCP listener.
	//  - "tcp6": IPv6-only TCP listener.
	Network string

	// Address specifies the address to listen on.
	Address string

	// TLSConfig specifies the TLS configuration for the listener.
	//
	// If nil, TLS is not enabled.
	TLSConfig *tls.Config
}

// NewServer returns a new API server from the config.
func (c *Config) NewServer(
	logger *tslog.Logger,
	tlsCertStore *tlscerts.Store,
	serverByName map[string]ssm.Server,
	serverNames []string,
) (*Server, error) {
	if len(c.TCPListeners) == 0 {
		return nil, errors.New("no listeners specified")
	}

	mux := http.NewServeMux()
	realIP := newRealIPMiddleware(logger, c.TrustedProxies, c.RealIPHeaderKey)
	basePath := "/"
	if c.SecretPath != "" {
		basePath = joinPatternPath(basePath, c.SecretPath)
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
	sm := ssm.NewServerManager(serverByName, serverNames)
	sm.RegisterHandlers(func(method, path string, handler restapi.HandlerFunc) {
		pattern := method + " " + joinPatternPath(apiSSMv1Path, path)
		mux.Handle(pattern, realIP(logAPIRequests(logger, handler)))
	})

	// /api/tlscerts/v1
	apiTLSCertsV1Path := joinPatternPath(basePath, "/api/tlscerts/v1")
	cm := certmgr.NewCertificateManager(tlsCertStore)
	cm.RegisterHandlers(func(method, path string, handler restapi.HandlerFunc) {
		pattern := method + " " + joinPatternPath(apiTLSCertsV1Path, path)
		mux.Handle(pattern, realIP(logAPIRequests(logger, handler)))
	})

	var staticFileRoot *os.Root
	if c.StaticPath != "" {
		var fsys fs.FS
		if !c.StaticAllowEscapingSymlinks {
			var err error
			staticFileRoot, err = os.OpenRoot(c.StaticPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open static path: %w", err)
			}
			fsys = staticFileRoot.FS()
		} else {
			fsys = os.DirFS(c.StaticPath)
		}
		mux.Handle("GET /", realIP(logFileServerRequests(logger, http.FileServerFS(fsys))))
	}

	return &Server{
		logger:         logger,
		tcpLnCfgs:      c.TCPListeners,
		staticFileRoot: staticFileRoot,
		server: http.Server{
			Handler:  mux,
			ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
		},
	}, nil
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
func newRealIPMiddleware(logger *tslog.Logger, trustedProxies []netip.Prefix, realIPHeaderKey string) func(http.Handler) http.Handler {
	if realIPHeaderKey == "" {
		return func(h http.Handler) http.Handler {
			return h
		}
	}

	realIPHeaderKey = http.CanonicalHeaderKey(realIPHeaderKey)

	// Trust all proxies if no trusted proxies are specified.
	// This used to be disallowed, but we later realized that the server
	// may use client certificates to authenticate clients, in which case
	// there's no point in checking the remote address.
	if len(trustedProxies) == 0 {
		return func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if v := r.Header[realIPHeaderKey]; len(v) > 0 {
					r.RemoteAddr = fmt.Sprintf("%s (%s: %v)", r.RemoteAddr, realIPHeaderKey, v)
				}
				h.ServeHTTP(w, r)
			})
		}
	}

	var proxySet prefixset.PrefixSet
	for _, p := range trustedProxies {
		proxySet.Insert(p)
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.Header[realIPHeaderKey]; len(v) > 0 {
				proxyAddrPort, err := netip.ParseAddrPort(r.RemoteAddr)
				if err != nil {
					logger.Error("Failed to parse HTTP request remote address",
						slog.String("remoteAddr", r.RemoteAddr),
						tslog.Err(err),
					)
					return
				}

				if proxySet.Contains(proxyAddrPort.Addr()) {
					r.RemoteAddr = fmt.Sprintf("%s (%s: %v)", r.RemoteAddr, realIPHeaderKey, v)
				}
			}

			h.ServeHTTP(w, r)
		})
	}
}

// logPprofRequests is a middleware that logs pprof requests.
func logPprofRequests(logger *tslog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		logger.Info("Handled pprof request",
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("requestURI", r.RequestURI),
			slog.String("host", r.Host),
			slog.String("remoteAddr", r.RemoteAddr),
		)
	})
}

// logAPIRequests is a middleware that logs API requests.
func logAPIRequests(logger *tslog.Logger, h restapi.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, err := h(w, r)
		logger.Info("Handled API request",
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("requestURI", r.RequestURI),
			slog.String("host", r.Host),
			slog.String("remoteAddr", r.RemoteAddr),
			slog.Int("status", status),
			tslog.Err(err),
		)
	})
}

// logFileServerRequests is a middleware that logs file server requests.
func logFileServerRequests(logger *tslog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		logger.Info("Served file",
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("requestURI", r.RequestURI),
			slog.String("host", r.Host),
			slog.String("remoteAddr", r.RemoteAddr),
		)
	})
}

// Server is the RESTful API server.
type Server struct {
	logger         *tslog.Logger
	tcpLnCfgs      []TCPListenerConfig
	server         http.Server
	staticFileRoot *os.Root
}

var _ shadowsocks.Service = (*Server)(nil)

// SlogAttr implements [shadowsocks.Service.SlogAttr].
func (*Server) SlogAttr() slog.Attr {
	return slog.String("service", "api")
}

// Start starts the API server.
//
// Start implements [shadowsocks.Service.Start].
func (s *Server) Start(ctx context.Context) error {
	tcpLnCfgs := s.tcpLnCfgs
	for i := range tcpLnCfgs {
		lc := &tcpLnCfgs[i]

		ln, err := lc.TCPListenConfig.Listen(ctx, lc.Network, lc.Address)
		if err != nil {
			return err
		}
		go s.serve(ln, lc.TLSConfig)

		s.logger.Info("Started API server TCP listener", slog.Any("listenAddress", ln.Addr()))
	}
	return nil
}

func (s *Server) serve(ln net.Listener, tlsConfig *tls.Config) {
	if tlsConfig != nil {
		ln = tls.NewListener(ln, tlsConfig)
	}
	if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.logger.Error("Failed to serve API", tslog.Err(err))
	}
}

// Stop stops the API server.
//
// Stop implements [shadowsocks.Service.Stop].
func (s *Server) Stop() error {
	if err := s.server.Close(); err != nil {
		return err
	}
	if s.staticFileRoot != nil {
		if err := s.staticFileRoot.Close(); err != nil {
			return err
		}
	}
	s.logger.Info("Stopped API server")
	return nil
}
