package api

import (
	"context"
	"errors"

	v1 "github.com/database64128/shadowsocks-go/api/v1"
	"github.com/database64128/shadowsocks-go/jsonhelper"
	"github.com/gofiber/contrib/fiberzap/v2"
	"github.com/gofiber/fiber/v2"
	fiberlog "github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/pprof"
	"go.uber.org/zap"
)

// Config stores the configuration for the RESTful API.
type Config struct {
	Enabled bool `json:"enabled"`

	// Debug
	DebugPprof bool `json:"debugPprof"`

	// Reverse proxy
	EnableTrustedProxyCheck bool     `json:"enableTrustedProxyCheck"`
	TrustedProxies          []string `json:"trustedProxies"`
	ProxyHeader             string   `json:"proxyHeader"`

	// Listen
	Listen         string `json:"listen"`
	CertFile       string `json:"certFile"`
	KeyFile        string `json:"keyFile"`
	ClientCertFile string `json:"clientCertFile"`

	// Misc
	SecretPath      string `json:"secretPath"`
	FiberConfigPath string `json:"fiberConfigPath"`
}

// Server returns a new API server from the config.
func (c *Config) Server(logger *zap.Logger) (*Server, *v1.ServerManager, error) {
	if !c.Enabled {
		return nil, nil, nil
	}

	fiberlog.SetLogger(fiberzap.NewLogger(fiberzap.LoggerConfig{
		SetLogger: logger,
	}))

	fc := fiber.Config{
		ProxyHeader:             c.ProxyHeader,
		DisableStartupMessage:   true,
		Network:                 "tcp",
		EnableTrustedProxyCheck: c.EnableTrustedProxyCheck,
		TrustedProxies:          c.TrustedProxies,
	}

	if c.FiberConfigPath != "" {
		if err := jsonhelper.LoadAndDecodeDisallowUnknownFields(c.FiberConfigPath, &fc); err != nil {
			return nil, nil, err
		}
	}

	app := fiber.New(fc)

	app.Use(etag.New())

	app.Use(fiberzap.New(fiberzap.Config{
		Logger: logger,
		Fields: []string{"latency", "status", "method", "url", "ip"},
	}))

	if c.DebugPprof {
		app.Use(pprof.New())
	}

	var router fiber.Router = app
	if c.SecretPath != "" {
		router = app.Group(c.SecretPath)
	}

	sm := v1.Routes(router)

	return &Server{
		logger:         logger,
		app:            app,
		listen:         c.Listen,
		certFile:       c.CertFile,
		keyFile:        c.KeyFile,
		clientCertFile: c.ClientCertFile,
	}, sm, nil
}

// Server is the RESTful API server.
type Server struct {
	logger         *zap.Logger
	app            *fiber.App
	listen         string
	certFile       string
	keyFile        string
	clientCertFile string
	ctx            context.Context
}

// String implements the service.Service String method.
func (s *Server) String() string {
	return "API server"
}

// Start starts the API server.
func (s *Server) Start(ctx context.Context) error {
	s.ctx = ctx
	go func() {
		var err error
		switch {
		case s.clientCertFile != "":
			err = s.app.ListenMutualTLS(s.listen, s.certFile, s.keyFile, s.clientCertFile)
		case s.certFile != "":
			err = s.app.ListenTLS(s.listen, s.certFile, s.keyFile)
		default:
			err = s.app.Listen(s.listen)
		}
		if err != nil {
			s.logger.Fatal("Failed to start API server", zap.Error(err))
		}
	}()
	return nil
}

// Stop stops the API server.
func (s *Server) Stop() error {
	if err := s.app.ShutdownWithContext(s.ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
	return nil
}
