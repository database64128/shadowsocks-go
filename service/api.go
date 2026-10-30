package service

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"

	"github.com/database64128/shadowsocks-go/api"
	"github.com/database64128/shadowsocks-go/api/ssm"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/tlscerts"
	"github.com/database64128/shadowsocks-go/tslog"
)

// APIConfig is the configuration for the HTTP API server.
type APIConfig struct {
	// Enabled controls whether the API server is enabled.
	Enabled bool `json:"enabled"`

	// DebugPprof enables pprof endpoints for debugging and profiling.
	DebugPprof bool `json:"debugPprof,omitzero"`

	// StaticAllowEscapingSymlinks controls whether to allow serving static files
	// that escape the static path via symlinks.
	StaticAllowEscapingSymlinks bool `json:"staticAllowEscapingSymlinks,omitzero"`

	// TrustedProxies specifies the IP address prefixes of trusted proxies.
	// Requests from these proxies will be trusted to contain the real IP address
	// in the specified header field.
	// If empty, all proxies are trusted.
	TrustedProxies []netip.Prefix `json:"trustedProxies,omitzero"`

	// RealIPHeaderKey specifies the header field to use for determining
	// the client's real IP address when the request is from a trusted proxy.
	// If empty, the real IP address is not appended to [http.Request.RemoteAddr].
	RealIPHeaderKey string `json:"realIPHeaderKey,omitzero"`

	// StaticPath is the path where static files are served from.
	// If empty, static file serving is disabled.
	StaticPath string `json:"staticPath,omitzero"`

	// SecretPath adds a secret path prefix to API and pprof endpoints.
	// Static files are not affected. If empty, no secret path is added.
	SecretPath string `json:"secretPath,omitzero"`

	// Listeners is the list of TCP listeners.
	Listeners []APIListenerConfig `json:"listeners"`
}

// APIListenerConfig is the configuration for an API server TCP listener.
type APIListenerConfig struct {
	ListenerConfig
	IPListenerConfig
	TCPListenerConfig
	TLSServerConfig
}

// NewServer returns a new API server.
func (cfg *APIConfig) NewServer(
	logger *tslog.Logger,
	tcpListenConfigCache conn.TCPListenConfigCache,
	tlsCertStore *tlscerts.Store,
	serverByName map[string]ssm.Server,
	serverNames []string,
) (*api.Server, error) {
	cfgListeners := cfg.Listeners
	if len(cfgListeners) == 0 {
		return nil, errors.New("no listeners specified")
	}

	tcpLnCfgs := make([]api.TCPListenerConfig, len(cfgListeners))
	for i := range cfgListeners {
		lnc := &cfgListeners[i]

		var tlsConfig *tls.Config
		if lnc.EnableTLS {
			tlsConfig = &tls.Config{}

			if lnc.CertList != "" {
				certList, ok := tlsCertStore.GetCertList(lnc.CertList)
				if !ok {
					return nil, fmt.Errorf("certificate list %q not found", lnc.CertList)
				}
				tlsConfig.Certificates, tlsConfig.GetCertificate = certList.GetCertificateFunc()
			}

			if lnc.ClientCAs != "" {
				pool, ok := tlsCertStore.GetX509CertPool(lnc.ClientCAs)
				if !ok {
					return nil, fmt.Errorf("client CA X.509 certificate pool %q not found", lnc.ClientCAs)
				}
				tlsConfig.ClientCAs = pool
			}

			if lncECHKeys := lnc.EncryptedClientHelloKeys; len(lncECHKeys) > 0 {
				tlsECHKeys := make([]tls.EncryptedClientHelloKey, len(lncECHKeys))
				for j, key := range lncECHKeys {
					tlsECHKeys[j] = tls.EncryptedClientHelloKey{
						Config:      key.Config,
						PrivateKey:  key.PrivateKey,
						SendAsRetry: key.SendAsRetry,
					}
				}
				tlsConfig.EncryptedClientHelloKeys = tlsECHKeys
			}

			if lnc.RequireAndVerifyClientCert {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}

		sndBufSize, rcvBufSize, err := lnc.SocketBufferSizeConfig.genericSocketBufferSizes()
		if err != nil {
			return nil, err
		}

		tcpLnCfgs[i] = api.TCPListenerConfig{
			TCPListenConfig: tcpListenConfigCache.Get(conn.TCPListenSocketOptions{
				SendBufferSize:      sndBufSize,
				ReceiveBufferSize:   rcvBufSize,
				Fwmark:              lnc.Fwmark,
				TrafficClass:        lnc.TrafficClass,
				TCPFastOpenBacklog:  lnc.FastOpenBacklog,
				TCPDeferAcceptSecs:  lnc.DeferAcceptSecs,
				TCPUserTimeoutMsecs: lnc.UserTimeoutMsecs,
				ReusePort:           lnc.ReusePort,
				PathMTUDiscovery:    lnc.PathMTUDiscovery.TCP(),
				TCPFastOpen:         lnc.FastOpen,
				TCPFastOpenFallback: lnc.FastOpenFallback,
				MultipathTCP:        lnc.Multipath,
			}),
			Network:   lnc.Network,
			Address:   lnc.Address,
			TLSConfig: tlsConfig,
		}
	}

	apiCfg := api.Config{
		DebugPprof:                  cfg.DebugPprof,
		StaticAllowEscapingSymlinks: cfg.StaticAllowEscapingSymlinks,
		TrustedProxies:              cfg.TrustedProxies,
		RealIPHeaderKey:             cfg.RealIPHeaderKey,
		StaticPath:                  cfg.StaticPath,
		SecretPath:                  cfg.SecretPath,
		TCPListeners:                tcpLnCfgs,
	}
	return apiCfg.NewServer(logger, tlsCertStore, serverByName, serverNames)
}
