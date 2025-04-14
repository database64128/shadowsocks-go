// Package tlscerts provides a store for TLS certificates.
package tlscerts

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
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
	certListByName     map[string][]tls.Certificate
	x509CertPoolByName map[string]*x509.CertPool
}

// NewStore creates a new store for TLS certificates.
func (c *Config) NewStore() (*Store, error) {
	if len(c.CertLists) == 0 && len(c.X509CertPools) == 0 {
		return &Store{}, nil
	}

	certListByName := make(map[string][]tls.Certificate, len(c.CertLists))

	for _, certList := range c.CertLists {
		if _, ok := certListByName[certList.Name]; ok {
			return nil, fmt.Errorf("duplicate TLS certificate list name: %q", certList.Name)
		}

		certs, err := certList.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate list %q: %w", certList.Name, err)
		}
		certListByName[certList.Name] = certs
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
		certListByName:     certListByName,
		x509CertPoolByName: x509CertPoolByName,
	}, nil
}

// GetCertList gets a TLS server certificate list by name.
func (s *Store) GetCertList(name string) (certs []tls.Certificate, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), ok bool) {
	certs, ok = s.certListByName[name]
	return
}

// GetClientCertList gets a TLS client certificate list by name.
func (s *Store) GetClientCertList(name string) (certs []tls.Certificate, getClientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error), ok bool) {
	certs, ok = s.certListByName[name]
	return
}

// GetX509CertPool gets an X.509 certificate pool by name.
func (s *Store) GetX509CertPool(name string) (pool *x509.CertPool, ok bool) {
	pool, ok = s.x509CertPoolByName[name]
	return
}

// TLSCertListConfig is the configuration for a list of TLS certificates.
type TLSCertListConfig struct {
	// Name is the name of the certificate list.
	Name string `json:"name"`

	// Certs is a list of TLS certificates.
	Certs []TLSCertConfig `json:"certs"`
}

// Load loads the TLS certificate list.
func (c *TLSCertListConfig) Load() (certs []tls.Certificate, err error) {
	certs = make([]tls.Certificate, len(c.Certs))
	for i, cert := range c.Certs {
		certs[i], err = cert.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate %q: %w", c.Name, err)
		}
	}
	return certs, nil
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
