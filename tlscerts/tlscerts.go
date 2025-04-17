// Package tlscerts provides a store for TLS certificates.
package tlscerts

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
)

// Config is the configuration for the TLS certificate store.
type Config struct {
	// CertLists is a list of TLS certificate lists.
	CertLists []TLSCertListConfig `json:"certLists,omitzero"`

	// X509CertPools is a list of X.509 certificate pools.
	X509CertPools []X509CertPoolConfig `json:"x509CertPools,omitzero"`
}

// Store is a store for TLS certificates.
type Store struct {
	config              Config
	certListByName      map[string]TLSCertList
	x509CertPoolByName  map[string]*x509.CertPool
	reloadableCertLists []TLSCertList
}

// NewStore creates a new store for TLS certificates.
func (c *Config) NewStore() (*Store, error) {
	if len(c.CertLists) == 0 && len(c.X509CertPools) == 0 {
		return &Store{}, nil
	}

	certListByName := make(map[string]TLSCertList, len(c.CertLists))

	var reloadableCertListCount int
	for _, certListCfg := range c.CertLists {
		if certListCfg.Reloadable {
			reloadableCertListCount++
		}
	}
	reloadableCertLists := make([]TLSCertList, 0, reloadableCertListCount)

	for _, certListCfg := range c.CertLists {
		if _, ok := certListByName[certListCfg.Name]; ok {
			return nil, fmt.Errorf("duplicate TLS certificate list name: %q", certListCfg.Name)
		}

		certList, err := certListCfg.NewTLSCertList()
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate list %q: %w", certListCfg.Name, err)
		}
		certListByName[certListCfg.Name] = certList

		if certListCfg.Reloadable {
			reloadableCertLists = append(reloadableCertLists, certList)
		}
	}

	x509CertPoolByName := make(map[string]*x509.CertPool, len(c.X509CertPools))

	for _, x509CertPool := range c.X509CertPools {
		if _, ok := x509CertPoolByName[x509CertPool.Name]; ok {
			return nil, fmt.Errorf("duplicate X.509 certificate pool name: %q", x509CertPool.Name)
		}

		pool, err := x509CertPool.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load X.509 certificate pool %q: %w", x509CertPool.Name, err)
		}
		x509CertPoolByName[x509CertPool.Name] = pool
	}

	return &Store{
		config:              *c,
		certListByName:      certListByName,
		x509CertPoolByName:  x509CertPoolByName,
		reloadableCertLists: reloadableCertLists,
	}, nil
}

// Config returns the configuration of the TLS certificate store.
func (s *Store) Config() *Config {
	return &s.config
}

// GetCertList gets a TLS certificate list by name.
func (s *Store) GetCertList(name string) (TLSCertList, bool) {
	certList, ok := s.certListByName[name]
	return certList, ok
}

// GetX509CertPool gets an X.509 certificate pool by name.
func (s *Store) GetX509CertPool(name string) (pool *x509.CertPool, ok bool) {
	pool, ok = s.x509CertPoolByName[name]
	return
}

// ReloadableCertLists returns the list of reloadable TLS certificate lists.
func (s *Store) ReloadableCertLists() []TLSCertList {
	return s.reloadableCertLists
}

// TLSCertListConfig is the configuration for a list of TLS certificates.
type TLSCertListConfig struct {
	// Name is the name of the certificate list.
	Name string `json:"name"`

	// Certs is a list of TLS certificates.
	Certs []TLSCertConfig `json:"certs"`

	// Reloadable controls whether the certificates can be reloaded on demand.
	Reloadable bool `json:"reloadable,omitzero"`
}

// Load loads the TLS certificate list.
func (c *TLSCertListConfig) Load() (certs []tls.Certificate, err error) {
	certs = make([]tls.Certificate, len(c.Certs))
	for i, cert := range c.Certs {
		certs[i], err = cert.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate at index %d: %w", i, err)
		}
	}
	return certs, nil
}

var errNoCertificates = errors.New("no certificates configured")

// NewTLSCertList creates a new TLS certificate list.
func (c *TLSCertListConfig) NewTLSCertList() (TLSCertList, error) {
	if len(c.Certs) == 0 {
		return nil, errNoCertificates
	}

	certs, err := c.Load()
	if err != nil {
		return nil, err
	}

	if !c.Reloadable {
		return newStaticTLSCertList(c, certs), nil
	}
	return newReloadableTLSCertList(c, certs), nil
}

// TLSCertList is a list of TLS certificates.
type TLSCertList interface {
	// Config returns the configuration of the TLS certificate list.
	Config() *TLSCertListConfig

	// GetCertificateFunc returns the TLS certificates or a function to get the server certificate.
	GetCertificateFunc() (certs []tls.Certificate, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error))

	// GetClientCertificateFunc returns the TLS client certificates or a function to get the client certificate.
	GetClientCertificateFunc() (certs []tls.Certificate, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error))

	// Reload reloads the TLS certificate list.
	// It returns [ReloadDisabledError] if reloading is not enabled.
	Reload() error
}

// StaticTLSCertList is a static list of TLS certificates.
// It does not support reloading.
//
// StaticTLSCertList implements [TLSCertList].
type StaticTLSCertList struct {
	config *TLSCertListConfig
	certs  []tls.Certificate
}

// newStaticTLSCertList returns a new static TLS certificate list.
func newStaticTLSCertList(config *TLSCertListConfig, certs []tls.Certificate) *StaticTLSCertList {
	return &StaticTLSCertList{
		config: config,
		certs:  certs,
	}
}

// Config implements [TLSCertList.Config].
func (cl *StaticTLSCertList) Config() *TLSCertListConfig {
	return cl.config
}

// GetCertificateFunc implements [TLSCertList.GetCertificateFunc].
func (cl *StaticTLSCertList) GetCertificateFunc() (certs []tls.Certificate, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) {
	return cl.certs, nil
}

// GetClientCertificateFunc implements [TLSCertList.GetClientCertificateFunc].
func (cl *StaticTLSCertList) GetClientCertificateFunc() (certs []tls.Certificate, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) {
	return cl.certs, nil
}

// ReloadDisabledError is an error indicating that reloading is not enabled for this certificate list.
type ReloadDisabledError struct{}

func (ReloadDisabledError) Error() string {
	return "reloading is not enabled for this certificate list"
}

func (ReloadDisabledError) Is(target error) bool {
	return target == errors.ErrUnsupported
}

// Reload implements [TLSCertList.Reload].
func (cl *StaticTLSCertList) Reload() error {
	return ReloadDisabledError{}
}

// ReloadableTLSCertList is a reloadable list of TLS certificates.
//
// ReloadableTLSCertList implements [TLSCertList].
type ReloadableTLSCertList struct {
	config        *TLSCertListConfig
	atomicCerts   atomic.Pointer[[]tls.Certificate]
	getCert       func(*tls.ClientHelloInfo) (*tls.Certificate, error)        // lazily initialized
	getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error) // lazily initialized
}

// newReloadableTLSCertList returns a new reloadable TLS certificate list.
func newReloadableTLSCertList(config *TLSCertListConfig, certs []tls.Certificate) *ReloadableTLSCertList {
	cl := ReloadableTLSCertList{
		config: config,
	}
	cl.atomicCerts.Store(&certs)
	return &cl
}

// Config implements [TLSCertList.Config].
func (cl *ReloadableTLSCertList) Config() *TLSCertListConfig {
	return cl.config
}

// GetCertificateFunc implements [TLSCertList.GetCertificateFunc].
func (cl *ReloadableTLSCertList) GetCertificateFunc() (certs []tls.Certificate, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) {
	if cl.getCert == nil {
		cl.getCert = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certs := *cl.atomicCerts.Load()

			switch len(certs) {
			case 0:
				return nil, errNoCertificates
			case 1:
				return &certs[0], nil
			}

			for i := range certs {
				cert := &certs[i]
				if err := chi.SupportsCertificate(cert); err != nil {
					continue
				}
				return cert, nil
			}

			// If nothing matches, return the first certificate.
			return &certs[0], nil
		}
	}
	return nil, cl.getCert
}

// GetClientCertificateFunc implements [TLSCertList.GetClientCertificateFunc].
func (cl *ReloadableTLSCertList) GetClientCertificateFunc() (certs []tls.Certificate, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) {
	if cl.getClientCert == nil {
		cl.getClientCert = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			certs := *cl.atomicCerts.Load()

			for i := range certs {
				cert := &certs[i]
				if err := cri.SupportsCertificate(cert); err != nil {
					continue
				}
				return cert, nil
			}

			// No acceptable certificate found. Don't send a certificate.
			return &tls.Certificate{}, nil
		}
	}
	return nil, cl.getClientCert
}

// Reload implements [TLSCertList.Reload].
func (cl *ReloadableTLSCertList) Reload() error {
	certs, err := cl.config.Load()
	if err != nil {
		return err
	}
	cl.atomicCerts.Store(&certs)
	return nil
}

// TLSCertConfig is the configuration for a TLS certificate.
type TLSCertConfig struct {
	// CertPath is the path to the PEM-encoded certificate.
	CertPath string `json:"certPath"`

	// KeyPath is the path to the PEM-encoded private key.
	KeyPath string `json:"keyPath"`
}

// Load loads the TLS certificate.
func (c *TLSCertConfig) Load() (cert tls.Certificate, err error) {
	return tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
}

// X509CertPoolConfig is the configuration for an X.509 certificate pool.
type X509CertPoolConfig struct {
	// Name is the name of the certificate pool.
	Name string `json:"name"`

	// CertPaths is a list of paths to PEM-encoded certificates.
	CertPaths []string `json:"certPaths"`
}

// Load loads the X.509 certificate pool.
func (c *X509CertPoolConfig) Load() (pool *x509.CertPool, err error) {
	pool = x509.NewCertPool()
	for _, path := range c.CertPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file %q: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("invalid certificate file %q", path)
		}
	}
	return pool, nil
}
